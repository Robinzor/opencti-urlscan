import requests
import json
from datetime import datetime
from typing import Dict, List, Any
import os
import argparse
import logging
from dotenv import load_dotenv
from pycti import OpenCTIConnectorHelper, get_config_variable
import time
import stix2
import urllib3
import re

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

class URLScanConnector:
    def __init__(self):
        print("Initializing URLScan connector...")
        # Create config dictionary from environment variables
        config = {
            "opencti": {
                "url": os.getenv("OPENCTI_API_URL", "http://opencti:8080"),
                "token": os.getenv("OPENCTI_API_KEY", "your-api-key"),
                "verify_ssl": os.getenv("OPENCTI_VERIFY_SSL", "false").lower() == "true"
            },
            "connector": {
                "id": "urlscan-connector",
                "type": "INTERNAL_ENRICHMENT",
                "name": "URLScan.io",
                "scope": os.getenv("CONNECTOR_SCOPE", "Domain-Name,Url"),
                "confidence_level": int(os.getenv("CONFIDENCE_LEVEL", "60")),
                "log_level": "info",
                "auto": True,
                "update_existing_data": os.getenv("UPDATE_EXISTING_DATA", "true").lower() == "true"
            }
        }
        
        self.helper = OpenCTIConnectorHelper(config)
        print("Connector initialized successfully")
        
        # Get configuration values
        self.interval = int(os.getenv("INTERVAL", "300"))
        self.update_existing_data = os.getenv("UPDATE_EXISTING_DATA", "true").lower() == "true"
        self.score = int(os.getenv("CONFIDENCE_LEVEL", "60"))
        self.update_frequency = int(os.getenv("UPDATE_FREQUENCY", "30"))
        
        # Create organization
        external_reference_org = self.helper.api.external_reference.create(
            source_name="urlscan.io",
            url="https://urlscan.io/",
        )
        self.organization = self.helper.api.identity.create(
            type="Organization",
            name="URLScan.io",
            description="URLScan.io search results importer",
            externalReferences=[external_reference_org["id"]],
        )

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
            createdBy=self.organization["id"],
            x_opencti_score=self.score,
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
                                    self.get_label(brand_label, color="#00ff00")  # Green
                                
                                # Extract sectors from vertical
                                if 'vertical' in brand:
                                    for sector in brand['vertical']:
                                        targeting_info['sectors'].add(sector)
                                        # Add sector as label with yellow color
                                        sector_label = sector.lower().replace(' ', '-')
                                        entry_labels.append(sector_label)
                                        self.get_label(sector_label, color="#ffff00")  # Yellow
                            elif isinstance(brand, str):
                                targeting_info['brands'].append(brand)
                                # Add brand as label with green color
                                brand_label = brand.lower().replace(' ', '-')
                                entry_labels.append(brand_label)
                                self.get_label(brand_label, color="#00ff00")  # Green
                    
                    if 'categories' in urlscan:
                        for category in urlscan['categories']:
                            targeting_info['categories'].append(category)
                            # Add category as label with red color
                            category_label = category.lower().replace(' ', '-')
                            entry_labels.append(category_label)
                            self.get_label(category_label, color="#ff0000")  # Red
                
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
                                createdBy=self.organization["id"],
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
            print(f"Update frequency: {self.update_frequency} seconds")
            
            # Start the connector
            self.helper.listen(self._process_message)
            
        except KeyboardInterrupt:
            print("\nStopping connector...")
        except Exception as e:
            print(f"Error in connector run: {str(e)}")
            import traceback
            print(traceback.format_exc())

    def _process_message(self, data):
        """Process a message from OpenCTI."""
        try:
            logger.info("Received message from OpenCTI")
            logger.info(f"Message data: {json.dumps(data, indent=2)}")
            
            # Get the observable ID from the message
            observable_id = data.get("entity_id")
            if not observable_id:
                logger.error("No entity_id in message")
                return
            
            logger.info(f"Processing observable with ID: {observable_id}")
            
            # Get the observable
            observable = self.helper.api.stix_cyber_observable.read(id=observable_id)
            if not observable:
                logger.error(f"Could not find observable with id {observable_id}")
                return
            
            logger.info(f"Found observable: {json.dumps(observable, indent=2)}")
            
            # Check if it's a domain or URL
            entity_type = observable.get("entity_type")
            if entity_type not in ["Domain-Name", "Url"]:
                logger.error(f"Unsupported entity type: {entity_type}")
                return
            
            value = observable.get("value")
            logger.info(f"Processing {entity_type}: {value}")
            
            # Fetch data from URLScan.io
            if entity_type == "Domain-Name":
                query = f"domain:{value}"
            else:  # Url
                query = f"url:{value}"
            
            logger.info(f"Fetching data from URLScan.io with query: {query}")
            data = self.fetch_urlscan_data(query)
            if not data:
                logger.info(f"No data found for {entity_type} {value}")
                return

            logger.info(f"Found {len(data)} results from URLScan.io")
            
            # Create OpenCTI objects
            logger.info("Processing results...")
            output = self.create_opencti_objects(data, only_active=True)  # Only process URLs with status code 200
            logger.info(f"Results pushed to OpenCTI for {entity_type} {value}")
            logger.info(f"Created {len(output['objects'])} objects")
            logger.info(f"Created {len(output['relationships'])} relationships")
            logger.info(f"Created {len(output['knowledge'])} knowledge entries")

            # Return success response for internal enrichment
            return {
                "status": "success",
                "message": f"Successfully enriched {entity_type} {value}",
                "data": {
                    "objects": output["objects"],
                    "relationships": output["relationships"],
                    "knowledge": output["knowledge"]
                }
            }
            
        except Exception as e:
            logger.error(f"Error processing message: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return {
                "status": "error",
                "message": str(e)
            }

def main():
    parser = argparse.ArgumentParser(description='URLScan.io OpenCTI Connector')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('-a', '--active-only', action='store_true', help='Only process URLs with status code 200')
    parser.add_argument('domain', nargs='?', default=None, help='Domain to search for in URLScan.io (if not provided, will use all domains from OpenCTI)')
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    connector = URLScanConnector()
    connector.run(query=args.domain, only_active=args.active_only)

if __name__ == "__main__":
    main() 