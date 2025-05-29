import requests
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any
import os
import argparse
import logging
from dotenv import load_dotenv
from pycti import OpenCTIConnectorHelper, get_config_variable
import time
import stix2
from stix2 import Identity, Indicator, Note, Relationship
import urllib3
import re
import yaml
from pathlib import Path
import uuid
import pytz

# Set timezone to Amsterdam
amsterdam_tz = pytz.timezone('Europe/Amsterdam')
os.environ['TZ'] = 'Europe/Amsterdam'
if hasattr(time, 'tzset'):
    time.tzset()

# Configure logging with timezone
logging.Formatter.converter = lambda *args: datetime.now(amsterdam_tz).timetuple()

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables
load_dotenv()

__version__ = "0.0.1"
BANNER = f"""
URLScan.io importer, version {__version__}
"""

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

def defang_url(url: str) -> str:
    """
    Defang a URL by replacing dots and other special characters.
    This makes the URL non-clickable and safer to handle.
    """
    if not url:
        return url
        
    # Replace http:// and https://
    url = re.sub(r'https?://', 'hxxp://', url)
    
    # Replace dots in domain with [.]
    parts = url.split('/')
    if len(parts) > 2:  # If we have a domain
        domain = parts[2]
        defanged_domain = domain.replace('.', '[.]')
        parts[2] = defanged_domain
        url = '/'.join(parts)
    
    return url

# Print banner
print(BANNER)

class URLScanBuilder:
    """URLScan builder."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: stix2.Identity,
        stix_objects: [],
        stix_entity: dict,
        opencti_entity: dict,
        data: dict,
    ) -> None:
        """Initialize URLScan builder."""
        self.helper = helper
        self.author = author
        self.bundle = stix_objects + [self.author]
        self.opencti_entity = opencti_entity
        self.stix_entity = stix_entity
        self.attributes = data["attributes"] if "attributes" in data else data
        self.score = self._compute_score()

        # Add the external reference
        if "result" in data:
            link = f"https://urlscan.io/result/{data['_id']}/"
            self.helper.log_debug(f"[URLScan] adding external reference {link}")
            self.external_reference = self._create_external_reference(
                link,
                "URLScan.io Report",
            )
        else:
            self.external_reference = None

    def _compute_score(self) -> int:
        """Compute the score for the observable based on verdicts."""
        score = 0
        if "verdicts" in self.attributes:
            verdicts = self.attributes["verdicts"]
            if verdicts.get("overall", {}).get("malicious"):
                score = 100
            elif verdicts.get("urlscan", {}).get("malicious"):
                score = 80
            elif verdicts.get("community", {}).get("malicious"):
                score = 60
            elif self.attributes.get("engines", {}):
                malicious_count = sum(1 for v in self.attributes["engines"].values() if v.get("malicious"))
                if malicious_count > 0:
                    score = 40
        return score

    def _create_external_reference(self, url: str, description: str) -> dict:
        """Create an external reference with the given url."""
        external_reference = {
            "source_name": self.author["name"],
            "url": url,
            "description": description,
        }
        return external_reference

    def create_indicator_based_on(self, pattern: str):
        """Enrich the observable with URLScan.io data."""
        if self.score >= 60:  # Only enrich if score is high enough
            self.helper.log_debug(f"[URLScan] enriching observable with score {self.score}")
            
            # Create labels list
            label_values = ["urlscan"]
            if self.score >= 80:
                label_values.extend(["malicious", "urlscan-malicious"])
            
            # Extract targeting information
            targeting_info = {
                'brands': [],
                'categories': [],
                'sectors': set()
            }
            
            if "verdicts" in self.attributes and "urlscan" in self.attributes["verdicts"]:
                urlscan = self.attributes["verdicts"]["urlscan"]
                if isinstance(urlscan, dict):
                    # Extract brands and sectors
                    if "brands" in urlscan:
                        for brand in urlscan["brands"]:
                            if isinstance(brand, dict):
                                brand_name = brand.get("name", "")
                                if brand_name:
                                    targeting_info['brands'].append(brand_name)
                                    # Add brand as label
                                    brand_label = brand_name.lower().replace(' ', '-')
                                    label_values.append(brand_label)
                                
                                # Extract sectors from vertical
                                if "vertical" in brand:
                                    for sector in brand["vertical"]:
                                        targeting_info['sectors'].add(sector)
                                        # Add sector as label
                                        sector_label = sector.lower().replace(' ', '-')
                                        label_values.append(sector_label)
                            elif isinstance(brand, str):
                                targeting_info['brands'].append(brand)
                                # Add brand as label
                                brand_label = brand.lower().replace(' ', '-')
                                label_values.append(brand_label)
                    
                    # Extract categories
                    if "categories" in urlscan:
                        for category in urlscan["categories"]:
                            targeting_info['categories'].append(category)
                            # Add category as label
                            category_label = category.lower().replace(' ', '-')
                            label_values.append(category_label)
            
            # Update existing entity with labels
            try:
                # Get existing labels
                observable = self.helper.api.stix_cyber_observable.read(id=self.stix_entity["id"])
                if observable:
                    # Get existing label IDs
                    existing_label_ids = [label["id"] for label in observable.get("objectLabel", [])]
                    
                    # Get or create new label IDs
                    new_label_ids = []
                    for label_value in label_values:
                        try:
                            # Check if label exists
                            labels = self.helper.api.label.list(search=label_value)
                            label_id = None
                            
                            # Find exact match
                            for label in labels:
                                if label["value"].lower() == label_value.lower():
                                    label_id = label["id"]
                                    break
                            
                            # Create label if it doesn't exist
                            if not label_id:
                                # Set color based on label type
                                color = None
                                if label_value in ["urlscan-malicious", "malicious"]:
                                    color = "#ff0000"  # Red for malicious
                                elif label_value in targeting_info['brands']:
                                    color = "#00ff00"  # Green for brands
                                elif label_value in targeting_info['sectors']:
                                    color = "#ffff00"  # Yellow for sectors
                                elif label_value in targeting_info['categories']:
                                    color = "#ff0000"  # Red for categories
                                
                                new_label = self.helper.api.label.create(
                                    value=label_value,
                                    color=color
                                )
                                label_id = new_label["id"]
                            
                            new_label_ids.append(label_id)
                        except Exception as e:
                            self.helper.log_error(f"[URLScan] Error getting/creating label {label_value}: {str(e)}")
                    
                    # Combine existing and new label IDs
                    all_label_ids = list(set(existing_label_ids + new_label_ids))
                    
                    # Update observable with new labels one by one
                    for label_id in all_label_ids:
                        try:
                            self.helper.api.stix_cyber_observable.add_label(
                                id=self.stix_entity["id"],
                                label_id=label_id
                            )
                            self.helper.log_debug(f"[URLScan] Added label {label_id} to entity {self.stix_entity['id']}")
                        except Exception as e:
                            self.helper.log_error(f"[URLScan] Error adding label {label_id}: {str(e)}")
                    
                    self.helper.log_debug(f"[URLScan] Updated entity {self.stix_entity['id']} with labels: {label_values}")
                else:
                    self.helper.log_error(f"[URLScan] Could not find observable with ID {self.stix_entity['id']}")
                    return "Could not find observable to enrich"
            except Exception as e:
                self.helper.log_error(f"[URLScan] Error updating entity labels: {str(e)}")
                return f"Error updating labels: {str(e)}"
            
            # Create note with analysis results
            if "verdicts" in self.attributes:
                content = "# URLScan.io Analysis Results\n\n"
                
                # Add scan information
                if "task" in self.attributes:
                    task = self.attributes["task"]
                    content += f"**Scan Time:** {task.get('time', 'N/A')}\n"
                    content += f"**Scan Method:** {task.get('method', 'N/A')}\n"
                    content += f"**Scan Visibility:** {task.get('visibility', 'N/A')}\n\n"
                
                # Add targeting information if available
                if targeting_info['brands'] or targeting_info['categories'] or targeting_info['sectors']:
                    content += "## Targeting Information\n\n"
                    if targeting_info['brands']:
                        content += f"**Targeted Brands:** {', '.join(targeting_info['brands'])}\n\n"
                    if targeting_info['categories']:
                        content += f"**Categories:** {', '.join(targeting_info['categories'])}\n\n"
                    if targeting_info['sectors']:
                        content += f"**Targeted Sectors:** {', '.join(targeting_info['sectors'])}\n\n"
                
                # Add page information if available
                if "page" in self.attributes:
                    page = self.attributes["page"]
                    content += "## Page Information\n\n"
                    content += f"**Title:** {page.get('title', 'N/A')}\n"
                    content += f"**MIME Type:** {page.get('mimeType', 'N/A')}\n"
                    content += f"**Country:** {page.get('country', 'N/A')}\n"
                    content += f"**IP:** {page.get('ip', 'N/A')}\n"
                    content += f"**ASN:** {page.get('asn', 'N/A')} ({page.get('asnname', 'N/A')})\n"
                    content += f"**TLS Valid Days:** {page.get('tlsValidDays', 'N/A')}\n"
                    content += f"**TLS Issuer:** {page.get('tlsIssuer', 'N/A')}\n"
                    content += f"**Domain:** {page.get('domain', 'N/A')}\n"
                    content += f"**Apex Domain:** {page.get('apexDomain', 'N/A')}\n"
                    content += f"**Status Code:** {page.get('status', 'N/A')}\n"
                    content += f"**Redirected:** {page.get('redirected', 'N/A')}\n\n"
                
                content += "## Verdict Results\n\n"
                content += "| Category | Result |\n"
                content += "|----------|--------|\n"
                
                verdicts = self.attributes["verdicts"]
                if "overall" in verdicts:
                    overall = verdicts["overall"]
                    if isinstance(overall, dict):
                        content += f"| Overall | {'Malicious' if overall.get('malicious') else 'Clean'} |\n"
                    else:
                        content += f"| Overall | {overall} |\n"
                        
                if "urlscan" in verdicts:
                    urlscan = verdicts["urlscan"]
                    if isinstance(urlscan, dict):
                        content += f"| URLScan | {'Malicious' if urlscan.get('malicious') else 'Clean'} |\n"
                    else:
                        content += f"| URLScan | {urlscan} |\n"
                        
                if "community" in verdicts:
                    community = verdicts["community"]
                    if isinstance(community, dict):
                        content += f"| Community | {'Malicious' if community.get('malicious') else 'Clean'} |\n"
                    else:
                        content += f"| Community | {community} |\n"
                
                if "engines" in verdicts:
                    content += "\n## Engine Results\n\n"
                    content += "| Engine | Result |\n"
                    content += "|--------|--------|\n"
                    for engine, result in verdicts["engines"].items():
                        if isinstance(result, dict):
                            content += f"| {engine} | {'Malicious' if result.get('malicious') else 'Clean'} |\n"
                        else:
                            content += f"| {engine} | {result} |\n"
                
                # Add note to existing entity
                try:
                    # Create external reference first if available
                    ext_ref_id = None
                    if self.external_reference:
                        try:
                            ext_ref = self.helper.api.external_reference.create(
                                source_name=self.external_reference["source_name"],
                                url=self.external_reference["url"],
                                description=self.external_reference.get("description", "")
                            )
                            ext_ref_id = ext_ref["id"]
                            self.helper.log_debug(f"[URLScan] Created external reference {ext_ref_id}")
                        except Exception as e:
                            self.helper.log_error(f"[URLScan] Error creating external reference: {str(e)}")
                    
                    # Create note with external reference if available
                    self.helper.log_debug(f"[URLScan] Creating note for entity {self.stix_entity['id']}")
                    self.helper.log_debug(f"[URLScan] Note content: {content}")
                    
                    note = self.helper.api.note.create(
                        content=content,
                        createdBy=self.author["id"],
                        objectId=self.stix_entity["id"],
                        attribute_abstract="URLScan.io Analysis Results",
                        externalReferences=[ext_ref_id] if ext_ref_id else [],
                        objectMarking=[stix2.TLP_WHITE["id"]]
                    )
                    
                    if note:
                        self.helper.log_debug(f"[URLScan] Successfully created note with ID: {note['id']}")
                        # Verify note was created
                        try:
                            created_note = self.helper.api.note.read(id=note["id"])
                            if created_note:
                                self.helper.log_debug(f"[URLScan] Verified note exists: {created_note['id']}")
                            else:
                                self.helper.log_error("[URLScan] Note was not found after creation")
                        except Exception as e:
                            self.helper.log_error(f"[URLScan] Error verifying note: {str(e)}")
                    else:
                        self.helper.log_error("[URLScan] Note creation returned no result")
                except Exception as e:
                    self.helper.log_error(f"[URLScan] Error adding note to entity: {str(e)}")
                    self.helper.log_error(f"[URLScan] Full error details: {traceback.format_exc()}")
                
                # Add external reference to observable if available
                if self.external_reference:
                    try:
                        # Create external reference first
                        ext_ref = self.helper.api.external_reference.create(
                            source_name=self.external_reference["source_name"],
                            url=self.external_reference["url"],
                            description=self.external_reference.get("description", "")
                        )
                        # Then add it to the observable
                        self.helper.api.stix_cyber_observable.add_external_reference(
                            id=self.stix_entity["id"],
                            external_reference_id=ext_ref["id"]
                        )
                        self.helper.log_debug(f"[URLScan] Added external reference to entity {self.stix_entity['id']}")
                    except Exception as e:
                        self.helper.log_error(f"[URLScan] Error adding external reference: {str(e)}")
                
                # Add relationships for domain and IP if available
                if "page" in self.attributes:
                    page = self.attributes["page"]
                    
                    # Add domain relationship
                    if "domain" in page:
                        domain = page["domain"]
                        try:
                            # Create or get domain observable
                            domain_obs = self.helper.api.stix_cyber_observable.create(
                                simple_observable_key="Domain-Name.value",
                                simple_observable_value=domain,
                                objectLabel=label_values
                            )
                            
                            # Wait a moment for the observable to be fully created
                            time.sleep(1)
                            
                            # Verify both observables exist before creating relationship
                            source_obs = self.helper.api.stix_cyber_observable.read(id=self.stix_entity["id"])
                            target_obs = self.helper.api.stix_cyber_observable.read(id=domain_obs["id"])
                            
                            if source_obs and target_obs and source_obs["id"] != target_obs["id"]:
                                # Create relationship between URL and domain
                                self.helper.api.stix_core_relationship.create(
                                    fromId=source_obs["id"],
                                    toId=target_obs["id"],
                                    relationship_type="related-to",
                                    description=f"URL {self.opencti_entity['observable_value']} is related to domain {domain}"
                                )
                                self.helper.log_debug(f"[URLScan] Added relationship between URL and domain {domain}")
                            else:
                                self.helper.log_error("[URLScan] Could not verify both observables exist for relationship or they are the same")
                        except Exception as e:
                            self.helper.log_error(f"[URLScan] Error creating domain relationship: {str(e)}")
                    
                    # Add IP relationship
                    if "ip" in page:
                        ip = page["ip"]
                        try:
                            # Create or get IP observable
                            ip_obs = self.helper.api.stix_cyber_observable.create(
                                simple_observable_key="IPv4-Addr.value",
                                simple_observable_value=ip,
                                objectLabel=label_values
                            )
                            
                            # Wait a moment for the observable to be fully created
                            time.sleep(1)
                            
                            # Verify both observables exist before creating relationship
                            source_obs = self.helper.api.stix_cyber_observable.read(id=self.stix_entity["id"])
                            target_obs = self.helper.api.stix_cyber_observable.read(id=ip_obs["id"])
                            
                            if source_obs and target_obs and source_obs["id"] != target_obs["id"]:
                                # Create relationship between URL and IP
                                self.helper.api.stix_core_relationship.create(
                                    fromId=source_obs["id"],
                                    toId=target_obs["id"],
                                    relationship_type="related-to",
                                    description=f"URL {self.opencti_entity['observable_value']} is related to IP {ip}"
                                )
                                self.helper.log_debug(f"[URLScan] Added relationship between URL and IP {ip}")
                            else:
                                self.helper.log_error("[URLScan] Could not verify both observables exist for relationship or they are the same")
                        except Exception as e:
                            self.helper.log_error(f"[URLScan] Error creating IP relationship: {str(e)}")
                
                # Create relationships with sectors
                for sector in targeting_info['sectors']:
                    try:
                        # Get or create sector
                        sector_obj = self.helper.api.identity.list(
                            filters={
                                "mode": "and",
                                "filters": [{"key": "name", "values": [sector]}],
                                "filterGroups": []
                            }
                        )
                        
                        if not sector_obj:
                            sector_obj = self.helper.api.identity.create(
                                type="Sector",
                                name=sector,
                                description=f"Sector targeted in phishing campaigns"
                            )
                        else:
                            sector_obj = sector_obj[0]
                        
                        # Create relationship between URL and sector
                        self.helper.api.stix_core_relationship.create(
                            fromId=self.stix_entity["id"],
                            toId=sector_obj["id"],
                            relationship_type="related-to",  # Changed from 'targets' to 'related-to'
                            description=f"URL {self.opencti_entity['observable_value']} is related to sector {sector}"
                        )
                        self.helper.log_debug(f"[URLScan] Added relationship between URL and sector {sector}")
                    except Exception as e:
                        self.helper.log_error(f"[URLScan] Error creating sector relationship: {str(e)}")
                
                return "Successfully enriched observable"
            else:
                return "No verdicts found to enrich observable"
        return "Score too low to enrich observable"

    def create_note(self, abstract: str, content: str):
        """Create a Note with the given abstract and content."""
        self.helper.log_debug(f"[URLScan] creating note with abstract {abstract}")
        self.bundle.append(
            stix2.Note(
                id=f"note--{uuid.uuid4()}",
                abstract=abstract,
                content=content,
                created_by_ref=self.author,
                object_refs=[self.stix_entity["id"]],
            )
        )

    def create_notes(self):
        """Create Notes with the analysis results."""
        if "verdicts" in self.attributes:
            content = "## URLScan.io Analysis Results\n\n"
            content += "| Category | Result |\n"
            content += "|----------|--------|\n"
            
            verdicts = self.attributes["verdicts"]
            if "overall" in verdicts:
                overall = verdicts["overall"]
                if isinstance(overall, dict):
                    content += f"| Overall | {'Malicious' if overall.get('malicious') else 'Clean'} |\n"
                else:
                    content += f"| Overall | {overall} |\n"
                    
            if "urlscan" in verdicts:
                urlscan = verdicts["urlscan"]
                if isinstance(urlscan, dict):
                    content += f"| URLScan | {'Malicious' if urlscan.get('malicious') else 'Clean'} |\n"
                else:
                    content += f"| URLScan | {urlscan} |\n"
                    
            if "community" in verdicts:
                community = verdicts["community"]
                if isinstance(community, dict):
                    content += f"| Community | {'Malicious' if community.get('malicious') else 'Clean'} |\n"
                else:
                    content += f"| Community | {community} |\n"
            
            if "engines" in verdicts:
                content += "\n## Engine Results\n\n"
                content += "| Engine | Result |\n"
                content += "|--------|--------|\n"
                for engine, result in verdicts["engines"].items():
                    if isinstance(result, dict):
                        content += f"| {engine} | {'Malicious' if result.get('malicious') else 'Clean'} |\n"
                    else:
                        content += f"| {engine} | {result} |\n"
            
            self.create_note("URLScan.io Results", content)

    def send_bundle(self) -> str:
        """Serialize and send the bundle to be inserted."""
        self.helper.metric.state("idle")
        if self.bundle is not None:
            self.helper.log_debug(f"[URLScan] sending bundle: {self.bundle}")
            self.helper.metric.inc("record_send", len(self.bundle))
            
            # Create a STIX bundle with custom content allowed
            bundle = stix2.Bundle(objects=self.bundle, allow_custom=True)
            
            # Serialize the bundle
            serialized_bundle = bundle.serialize()
            
            # In test mode, use direct API call instead of RabbitMQ
            if hasattr(self.helper, 'test_mode') and self.helper.test_mode:
                print("\nSending bundle directly to OpenCTI API...")
                try:
                    # Parse the serialized bundle back into a dictionary
                    bundle_dict = json.loads(serialized_bundle)
                    # Use the OpenCTI API to import the bundle
                    self.helper.api.stix2.import_bundle(bundle_dict)
                    print("Bundle successfully imported")
                    return f"Sent {len(self.bundle)} stix bundle(s) for worker import"
                except Exception as e:
                    print(f"Error importing bundle: {str(e)}")
                    raise
            else:
                # Normal mode - use RabbitMQ
                self.helper.send_stix2_bundle(serialized_bundle)
                return f"Sent {len(self.bundle)} stix bundle(s) for worker import"
        return "Nothing to attach"

class URLScanConnector:
    def __init__(self):
        print("Initializing URLScan connector...")
        # Create config dictionary from environment variables
        config = {
            "opencti": {
                "url": os.getenv("OPENCTI_API_URL", "http://opencti:8080"),
                "token": os.getenv("OPENCTI_API_KEY", "your-api-key"),
                "verify_ssl": os.getenv("OPENCTI_VERIFY_SSL", "false").lower() == "true",
                "timezone": "Europe/Amsterdam"
            },
            "connector": {
                "id": "urlscan-connector",
                "type": "INTERNAL_ENRICHMENT",
                "name": "URLScan.io",
                "scope": os.getenv("CONNECTOR_SCOPE", "Domain-Name,Url"),
                "confidence_level": int(os.getenv("CONFIDENCE_LEVEL", "60")),
                "log_level": "info",
                "auto": False,
                "update_existing_data": os.getenv("UPDATE_EXISTING_DATA", "true").lower() == "true"
            }
        }
        
        self.helper = OpenCTIConnectorHelper(config, playbook_compatible=True)
        print("Connector initialized successfully")
        
        # Get configuration values
        self.only_active_urls = os.getenv("ONLY_ACTIVE_URLS", "true").lower() == "true"
        self.update_existing_data = os.getenv("UPDATE_EXISTING_DATA", "true").lower() == "true"
        self.confidence_level = int(os.getenv("CONFIDENCE_LEVEL", "60"))
        
        # Create organization
        self.author = stix2.Identity(
            name="URLScan.io",
            identity_class="organization",
            description="URLScan.io search results importer",
            confidence=self.helper.connect_confidence_level,
        )

    def _process_message(self, data: Dict):
        """Process a message from OpenCTI."""
        try:
            self.helper.metric.inc("run_count")
            self.helper.metric.state("running")
            
            logger.info("Received message from OpenCTI")
            logger.info(f"Message data: {json.dumps(data, indent=2)}")
            
            stix_objects = data.get("stix_objects", [])
            stix_entity = data.get("stix_entity", {})
            opencti_entity = data.get("enrichment_entity", {})

            if not stix_entity or not opencti_entity:
                error_msg = "Missing required data in message"
                logger.error(error_msg)
                return {
                    "status": "error",
                    "message": error_msg
                }

            # Extract TLP
            tlp = "TLP:CLEAR"
            for marking_definition in opencti_entity.get("objectMarking", []):
                if marking_definition["definition_type"] == "TLP":
                    tlp = marking_definition["definition"]

            if not OpenCTIConnectorHelper.check_max_tlp(tlp, "TLP:AMBER"):
                error_msg = "Do not send any data, TLP of the observable is greater than MAX TLP"
                logger.error(error_msg)
                return {
                    "status": "error",
                    "message": error_msg
                }

            logger.info(
                f"[URLScan] Starting enrichment of observable: {opencti_entity.get('observable_value', 'unknown')}"
            )
            
            # Fetch data from URLScan.io
            if opencti_entity["entity_type"] == "Domain-Name":
                query = f"domain:{opencti_entity['observable_value']}"
            else:  # Url
                query = f"url:{opencti_entity['observable_value']}"
            
            logger.info(f"Fetching data from URLScan.io with query: {query}")
            data = self.fetch_urlscan_data(query)
            if not data:
                error_msg = f"No data found for {opencti_entity['entity_type']} {opencti_entity['observable_value']}"
                logger.info(error_msg)
                return {
                    "status": "error",
                    "message": error_msg
                }

            logger.info(f"Found {len(data)} results from URLScan.io")

            # Process each result
            for result in data:
                # Skip non-active URLs if only_active_urls is True
                if self.only_active_urls and result.get('page', {}).get('status') != 200:
                    logger.info(f"Skipping URL with status {result.get('page', {}).get('status')} as only_active_urls is enabled")
                    continue

                logger.info(f"Processing result: {json.dumps(result, indent=2)}")

                try:
                    builder = URLScanBuilder(
                        self.helper,
                        self.author,
                        stix_objects,
                        stix_entity,
                        opencti_entity,
                        result,
                    )

                    # Enrich the observable
                    if opencti_entity["entity_type"] == "Domain-Name":
                        result = builder.create_indicator_based_on(
                            f"""[domain-name:value = '{opencti_entity["observable_value"]}']"""
                        )
                    else:  # Url
                        result = builder.create_indicator_based_on(
                            f"""[url:value = '{opencti_entity["observable_value"]}']"""
                        )

                    logger.info(f"Successfully processed result: {result}")
                    return {
                        "status": "success",
                        "message": f"Successfully enriched {opencti_entity['entity_type']} {opencti_entity['observable_value']}",
                        "data": result
                    }

                except Exception as e:
                    error_msg = f"Error processing result: {str(e)}"
                    logger.error(error_msg)
                    logger.error(traceback.format_exc())
                    return {
                        "status": "error",
                        "message": error_msg
                    }
            
        except Exception as e:
            error_msg = f"Error processing message: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            return {
                "status": "error",
                "message": error_msg
            }

    def get_label(self, label_value, color=None):
        """Check if a label exists, if not create it."""
        logger.info(f"Checking for label: {label_value} with color: {color}")
        labels = self.helper.api.label.list(search=label_value)
        for label in labels:
            if label["value"].lower() == label_value.lower():
                logger.info(f"Found existing label: {label_value}")
                return label["id"]
        
        # Set color for malicious labels
        if label_value in ["urlscan-malicious", "malicious"]:
            color = "#ff0000"  # Red for malicious labels
        
        logger.info(f"Creating new label: {label_value} with color: {color}")
        new_label = self.helper.api.label.create(
            value=label_value, color=color)
        return new_label["id"]

    def create_observable(
        self,
        observable_key,
        observable_value,
        description,
        observable_type,
        external_reference_id,
        labels
    ):
        # Create observable
        observable = self.helper.api.stix_cyber_observable.create(
            simple_observable_key=observable_key,
            simple_observable_value=observable_value,
            objectMarking=[stix2.TLP_GREEN["id"]],
            externalReferences=[external_reference_id],
            createdBy=self.author["id"],
            x_opencti_score=self.confidence_level,
            x_opencti_create_indicator=True,
            x_opencti_main_observable_type=observable_type,
        )

        # Add labels to the observable with delay between operations
        if observable and labels:
            logger.info(f"Adding labels to observable {observable_value}: {labels}")
            for label in labels:
                try:
                    # Only urlscan-malicious gets a specific color (red)
                    color = "#ff0000" if label in ["urlscan-malicious", "malicious"] else None
                    
                    label_id = self.get_label(label, color=color)
                    if label_id:
                        time.sleep(0.5)  # Add delay between operations
                        # Update the observable with the new label
                        self.helper.api.stix_cyber_observable.update(
                            id=observable["id"],
                            objectLabel=[label_id]
                        )
                        logger.info(f"Added label {label} to {observable_value}")
                except Exception as e:
                    self.helper.log_error(
                        f"Failed to add label {label} to {observable_value}: {str(e)}")
                    time.sleep(0.5)  # Add longer delay after error
                    continue

        return observable

    def get_or_create_sector(self, name: str) -> Dict[str, Any]:
        """Get or create a sector in OpenCTI."""
        try:
            # Search for existing sector
            sectors = self.helper.api.identity.list(
                filters={
                    "mode": "and",
                    "filters": [{"key": "name", "values": [name]}],
                    "filterGroups": []
                }
            )
            
            if sectors:
                return sectors[0]
            
            # Create new sector if not found
            return self.helper.api.identity.create(
                type="Sector",
                name=name,
                description=f"Sector targeted in phishing campaigns"
            )
        except Exception as e:
            logger.error(f"Error getting/creating sector {name}: {str(e)}")
            return None

    def fetch_urlscan_data(self, query: str = None) -> List[Dict[str, Any]]:
        """Fetch data from URLScan.io search API."""
        try:
            # If no query provided, get domains from OpenCTI
            if not query:
                logger.info("No query provided, fetching domains from OpenCTI")
                domains = self.helper.api.stix_cyber_observable.list(
                    filters={
                        "mode": "and",
                        "filters": [{"key": "entity_type", "values": ["Domain-Name"]}],
                        "filterGroups": []
                    }
                )
                if not domains:
                    logger.info("No domains found in OpenCTI")
                    return []
                
                # Use the first domain for testing
                domain = domains[0]["value"]
                logger.info(f"Using domain from OpenCTI: {domain}")
                query = f"domain:{domain}"
            else:
                # If query is provided, ensure it's properly formatted
                if not query.startswith("domain:"):
                    query = f"domain:{query}"
            
            # URLScan.io search API endpoint
            url = f"https://urlscan.io/api/v1/search/?q={query}"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1"
            }
            print(f"\nMaking request to URLScan.io API: {url}")
            
            try:
                response = requests.get(url, headers=headers, timeout=30)
                print(f"Response status code: {response.status_code}")
                print(f"Response headers: {dict(response.headers)}")
                
                if response.status_code != 200:
                    print(f"Error response from URLScan.io: {response.text}")
                    return []
                    
                response.raise_for_status()
                data = response.json()
                
                # Print total results found
                total = data.get('total', 0)
                print(f"\nTotal results found: {total}")
                
                results = data.get("results", [])
                if results:
                    print("\nFirst result preview:")
                    print(f"URL: {results[0].get('page', {}).get('url', 'N/A')}")
                    print(f"Result URL: {results[0].get('result', 'N/A')}")
                    
                    # Fetch full result for each entry
                    for result in results:
                        result_url = result.get('result')
                        if result_url:
                            print(f"\nFetching full result from: {result_url}")
                            try:
                                result_response = requests.get(result_url, headers=headers, timeout=30)
                                if result_response.status_code == 200:
                                    full_result = result_response.json()
                                    result.update(full_result)
                                    print(f"Verdicts: {json.dumps(full_result.get('verdicts', {}), indent=2)}")
                            except Exception as e:
                                print(f"Error fetching full result: {str(e)}")
                else:
                    print("\nNo results found")
                
                return results
            except requests.exceptions.Timeout:
                print("Request timed out after 30 seconds")
                return []
            except requests.exceptions.RequestException as e:
                print(f"Request error: {str(e)}")
                return []
                
        except Exception as e:
            print(f"Unexpected error in fetch_urlscan_data: {str(e)}")
            import traceback
            print(traceback.format_exc())
            return []

    def extract_labels(self, data: List[Dict[str, Any]]) -> List[str]:
        """Extract unique labels from URLScan.io data."""
        labels = set()
        for entry in data:
            if 'verdicts' in entry:
                logger.info(f"Processing verdicts for entry: {entry.get('page', {}).get('url', 'unknown')}")
                if entry['verdicts'].get('overall', {}).get('malicious'):
                    labels.add('malicious')
                    logger.info("Found malicious verdict")
                if entry['verdicts'].get('overall', {}).get('malware'):
                    labels.add('malware')
                    logger.info("Found malware verdict")
                if entry['verdicts'].get('overall', {}).get('phishing'):
                    labels.add('phishing')
                    logger.info("Found phishing verdict")
        logger.info(f"Extracted unique labels: {list(labels)}")
        return list(labels)

    def create_opencti_objects(self, data: List[Dict[str, Any]], only_active: bool = False) -> Dict[str, Any]:
        """Create OpenCTI compatible objects from URLScan.io data.
        
        Args:
            data: List of URLScan.io data entries
            only_active: If True, only use the last active URL (status 200) as external reference
        """
        output = {
            "labels": [],
            "objects": [],
            "relationships": [],
            "knowledge": []
        }

        # Extract and create labels
        labels = self.extract_labels(data)
        output["labels"] = labels
        logger.info(f"Total unique labels found: {len(labels)}")

        # Find the last active URL for external reference
        last_active_url = None
        if only_active:
            for entry in reversed(data):
                if 'page' in entry and entry['page'].get('status') == 200:
                    last_active_url = entry
                    break

        # Process each entry
        for entry in data:
            if 'page' not in entry or 'url' not in entry['page']:
                continue

            url = entry['page']['url']
            logger.info(f"Processing URL {url}")
            scan_id = entry.get('_id', '')
            urlscan_result_url = f"https://urlscan.io/result/{scan_id}/"

            # Create external reference only for the last active URL
            if only_active and entry != last_active_url:
                external_reference = None
            else:
                external_reference = self.helper.api.external_reference.create(
                    source_name="urlscan.io",
                    url=urlscan_result_url
                )
            
            # Create base labels
            entry_labels = ["urlscan"]  # Base label
            
            # Check verdicts and add labels
            is_malicious = False
            verdict_details = {}
            targeting_info = {
                'brands': [],
                'categories': [],
                'sectors': set()
            }
            
            if 'verdicts' in entry:
                verdicts = entry['verdicts']
                logger.info(f"Processing verdicts for URL {url}: {json.dumps(verdicts, indent=2)}")
                
                # Check overall verdict
                overall = verdicts.get('overall', {})
                if isinstance(overall, dict) and overall.get('malicious'):
                    entry_labels.append('urlscan-malicious')
                    entry_labels.append('malicious')  # Add normal malicious label
                    is_malicious = True
                    logger.info(f"URL {url} is marked as malicious by URLScan.io")
                
                # Check urlscan verdict
                urlscan = verdicts.get('urlscan', {})
                if isinstance(urlscan, dict) and urlscan.get('malicious'):
                    entry_labels.append('urlscan-malicious')
                    entry_labels.append('malicious')  # Add normal malicious label
                    is_malicious = True
                    logger.info(f"URL {url} is marked as malicious by URLScan.io")
                    
                    # Extract targeting information
                    if 'brands' in urlscan:
                        for brand in urlscan['brands']:
                            if isinstance(brand, dict):
                                # Extract brand name and sectors
                                brand_name = brand.get('name', '')
                                if brand_name:
                                    targeting_info['brands'].append(brand_name)
                                    # Add brand as label with green color
                                    brand_label = brand_name.lower().replace(' ', '-')
                                    entry_labels.append(brand_label)
                                
                                # Extract sectors from vertical
                                if 'vertical' in brand:
                                    for sector in brand['vertical']:
                                        targeting_info['sectors'].add(sector)
                                        # Add sector as label with yellow color
                                        sector_label = sector.lower().replace(' ', '-')
                                        entry_labels.append(sector_label)
                            elif isinstance(brand, str):
                                targeting_info['brands'].append(brand)
                                # Add brand as label with green color
                                brand_label = brand.lower().replace(' ', '-')
                                entry_labels.append(brand_label)
                    
                    if 'categories' in urlscan:
                        for category in urlscan['categories']:
                            targeting_info['categories'].append(category)
                            # Add category as label with red color
                            category_label = category.lower().replace(' ', '-')
                            entry_labels.append(category_label)
                
                # Check community verdict
                community = verdicts.get('community', {})
                if isinstance(community, dict) and community.get('malicious'):
                    entry_labels.append('urlscan-malicious')
                    entry_labels.append('malicious')  # Add normal malicious label
                    is_malicious = True
                    logger.info(f"URL {url} is marked as malicious by URLScan.io community")
                
                # Check engine verdicts
                engines = verdicts.get('engines', {})
                if isinstance(engines, dict):
                    for engine, verdict in engines.items():
                        if isinstance(verdict, dict) and verdict.get('malicious'):
                            entry_labels.append('urlscan-malicious')
                            entry_labels.append('malicious')  # Add normal malicious label
                            is_malicious = True
                            logger.info(f"URL {url} is marked as malicious by engine {engine}")
                
                # Store detailed verdict information
                verdict_details = {
                    "overall": overall,
                    "urlscan": urlscan,
                    "community": community,
                    "engines": engines
                }

            # Remove duplicate labels
            entry_labels = list(dict.fromkeys(entry_labels))
            logger.info(f"Creating observable for URL {url} with labels: {entry_labels}")

            # Create URL observable
            url_obs = self.create_observable(
                "Url.value",
                url,
                f"URLScan.io search result for {url}",
                "Url",
                external_reference["id"] if external_reference else None,
                entry_labels
            )

            if url_obs:
                obj = {
                    "type": "url",
                    "value": url,
                    "labels": entry_labels,
                    "urlscan_result": urlscan_result_url,
                    "urlscan_screenshot": entry.get('screenshot', ''),
                    "scan_time": entry.get('task', {}).get('time', ''),
                    "scan_method": entry.get('task', {}).get('method', ''),
                    "scan_visibility": entry.get('task', {}).get('visibility', ''),
                    "verdict_details": verdict_details,
                    "targeting_info": {
                        'brands': targeting_info['brands'],
                        'categories': targeting_info['categories'],
                        'sectors': list(targeting_info['sectors'])
                    }
                }
                
                # Add additional information from URLScan.io
                if 'page' in entry:
                    page_info = entry['page']
                    obj.update({
                        "title": page_info.get('title', ''),
                        "mime_type": page_info.get('mimeType', ''),
                        "country": page_info.get('country', ''),
                        "ip": page_info.get('ip', ''),
                        "asn": page_info.get('asn', ''),
                        "asnname": page_info.get('asnname', ''),
                        "tls_valid_days": page_info.get('tlsValidDays', 0),
                        "tls_issuer": page_info.get('tlsIssuer', ''),
                        "domain": page_info.get('domain', ''),
                        "apex_domain": page_info.get('apexDomain', ''),
                        "status_code": page_info.get('status', ''),
                        "redirected": page_info.get('redirected', '')
                    })

                    # Create domain observable if available
                    if 'domain' in page_info:
                        domain = page_info['domain']
                        logger.info(f"Creating domain observable for: {domain}")
                        domain_obs = self.create_observable(
                            "Domain-Name.value",
                            domain,
                            f"Domain associated with {url}",
                            "Domain-Name",
                            external_reference["id"] if external_reference else None,
                            entry_labels
                        )
                        if domain_obs:
                            logger.info(f"Successfully created domain observable: {domain}")
                            
                            # Add relationship between URL and domain
                            relationship = {
                                "source": url_obs["id"],
                                "target": domain_obs["id"],
                                "type": "related-to",
                                "description": f"URL {url} is related to domain {domain}"
                            }
                            output["relationships"].append(relationship)

                # Create relationships with sectors
                for sector in targeting_info['sectors']:
                    sector_obj = self.get_or_create_sector(sector)
                    
                    if sector_obj:
                        # Add relationship between URL and sector
                        relationship = {
                            "source": url_obs["id"],
                            "target": sector_obj["id"],
                            "type": "related-to",
                            "description": f"URL {url} is related to sector {sector}"
                        }
                        output["relationships"].append(relationship)

                # Create IP observable if available
                if 'page' in entry and 'ip' in entry['page']:
                    ip = entry['page']['ip']
                    ip_obs = self.create_observable(
                        "IPv4-Addr.value",
                        ip,
                        f"IP address associated with {url}",
                        "IPv4-Addr",
                        external_reference["id"] if external_reference else None,
                        entry_labels
                    )
                    if ip_obs:
                        # Add relationship between URL and IP
                        relationship = {
                            "source": url_obs["id"],
                            "target": ip_obs["id"],
                            "type": "related-to",
                            "description": f"URL {url} is related to IP {ip}"
                        }
                        output["relationships"].append(relationship)

                # Add malicious status as comment if applicable
                if is_malicious:
                    logger.info(f"Processing malicious status for URL {url}")
                    # Check if there's an existing malicious comment
                    try:
                        existing_comments = self.helper.api.stix_cyber_observable.notes(id=url_obs["id"])
                        # Get labels from the observable itself
                        existing_labels = url_obs.get("labels", [])
                    except Exception as e:
                        logger.error(f"Failed to get existing comments/labels: {str(e)}")
                        existing_comments = []
                        existing_labels = []
                    
                    # Check if the status has changed (was not malicious before)
                    status_changed = not any(
                        "malicious" in label.lower() 
                        for label in existing_labels
                    )
                    
                    logger.info(f"Status changed: {status_changed}")
                    
                    if status_changed:
                        # Create new comment about malicious status
                        comment_content = f"URLScan.io detected malicious activity on {url}.\n"
                        comment_content += f"Scan time: {entry.get('task', {}).get('time', '')}\n"
                        comment_content += f"URLScan.io result: {urlscan_result_url}\n"
                        
                        if targeting_info['brands'] or targeting_info['categories'] or targeting_info['sectors']:
                            comment_content += "\nTargeting Information:\n"
                            if targeting_info['brands']:
                                comment_content += f"Targeted Brands: {', '.join(targeting_info['brands'])}\n"
                            if targeting_info['categories']:
                                comment_content += f"Categories: {', '.join(targeting_info['categories'])}\n"
                            if targeting_info['sectors']:
                                comment_content += f"Sectors: {', '.join(targeting_info['sectors'])}\n"
                        
                        comment_content += f"\nDetails: {json.dumps(verdict_details, indent=2)}"
                        
                        try:
                            self.helper.api.note.create(
                                content=comment_content,
                                createdBy=self.author["id"],
                                objectId=url_obs["id"]
                            )
                            logger.info(f"Added malicious comment for URL {url}")
                        except Exception as e:
                            logger.error(f"Failed to add malicious comment: {str(e)}")

                output["objects"].append(obj)
                logger.info(f"Successfully created observable for URL {url}")

        logger.info(f"Total objects created: {len(output['objects'])}")
        logger.info(f"Total relationships created: {len(output['relationships'])}")
        logger.info(f"Total knowledge entries created: {len(output['knowledge'])}")
        return output

    def save_to_json(self, data: Dict[str, Any], filename: str = "urlscan_export.json"):
        """Save data to a JSON file."""
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"Data saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving data to {filename}: {str(e)}")

    def run(self, query: str = None, only_active: bool = False):
        """Run the connector.
        
        Args:
            query: Search query for URLScan.io (if None, will use domains from OpenCTI)
            only_active: If True, only process URLs with status code 200
        """
        try:
            print(f"\nStarting URLScan.io enrichment")
            print(f"Only active URLs: {'enabled' if only_active else 'disabled'}")
            
            # Start the connector
            self.helper.listen(self._process_message)
            
        except KeyboardInterrupt:
            print("\nStopping connector...")
        except Exception as e:
            print(f"Error in connector run: {str(e)}")
            import traceback
            print(traceback.format_exc())

def generate_stix_id(type: str, value: str) -> str:
    """Generate a valid STIX ID with UUID."""
    return f"{type}--{uuid.uuid4()}"

def main():
    parser = argparse.ArgumentParser(description='URLScan.io OpenCTI Connector')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('-a', '--active-only', action='store_true', help='Only process URLs with status code 200')
    parser.add_argument('-t', '--test', action='store_true', help='Test mode - simulate OpenCTI enrichment task')
    parser.add_argument('domain', nargs='?', default=None, help='Domain to search for in URLScan.io')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.test:
        if not args.domain:
            print("Error: Domain is required in test mode")
            parser.print_help()
            return

        print(f"\n=== Testing URLScan.io connector with domain: {args.domain} ===")
        try:
            print("Initializing connector...")
            connector = URLScanConnector()
            # Set test mode flag
            connector.helper.test_mode = True
            print("Connector initialized successfully")
            
            # Create domain observable first
            print(f"Creating domain observable for {args.domain}...")
            domain_obs = connector.helper.api.stix_cyber_observable.create(
                simple_observable_key="Domain-Name.value",
                simple_observable_value=args.domain,
                objectLabel=["urlscan"]
            )
            print(f"Created domain observable with ID: {domain_obs['id']}")
            
            # Create a simulated OpenCTI message
            print("Creating test message...")
            test_message = {
                "stix_objects": [],
                "stix_entity": {
                    "id": domain_obs["id"],  # Use the actual ID from the created observable
                    "type": "domain-name",
                    "value": args.domain
                },
                "enrichment_entity": {
                    "id": domain_obs["id"],  # Use the actual ID from the created observable
                    "type": "Domain-Name",
                    "entity_type": "Domain-Name",
                    "observable_value": args.domain,
                    "objectMarking": [
                        {
                            "definition_type": "TLP",
                            "definition": "TLP:WHITE"
                        }
                    ]
                }
            }
            
            print("\nSimulating OpenCTI enrichment task...")
            print(f"Message structure: {json.dumps(test_message, indent=2)}")
            
            print("\nFetching data from URLScan.io...")
            results = connector.fetch_urlscan_data(f"domain:{args.domain}")
            if not results:
                print(f"No results found for domain: {args.domain}")
                return
                
            print(f"Found {len(results)} results from URLScan.io")
            
            print("\nProcessing results...")
            for result in results:
                print(f"\nProcessing result: {result.get('page', {}).get('url', 'N/A')}")
                if args.active_only and result.get('page', {}).get('status') != 200:
                    print("Skipping - not active URL")
                    continue
                    
                print("Creating builder...")
                builder = URLScanBuilder(
                    connector.helper,
                    connector.author,
                    test_message["stix_objects"],
                    test_message["stix_entity"],
                    test_message["enrichment_entity"],
                    result,
                )
                
                print("Enriching observable...")
                result = builder.create_indicator_based_on(
                    f"""[domain-name:value = '{args.domain}']"""
                )
                print(f"Enrichment result: {result}")
                
            print("\n=== Test completed successfully ===")
            
        except Exception as e:
            print(f"\nError during test: {str(e)}")
            import traceback
            print(traceback.format_exc())
        return

    # Normal mode - start the connector
    connector = URLScanConnector()
    connector.run(query=args.domain, only_active=args.active_only)

if __name__ == "__main__":
    main() 