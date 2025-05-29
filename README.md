# URLScan.io OpenCTI Connector

This connector enriches Domain-Name and URL observables in OpenCTI with data from URLScan.io. It provides additional context, relationships, and threat intelligence for your observables.

## Features

- Enriches both Domain-Name and URL observables
- Fetches detailed information from URLScan.io including:
  - Screenshots
  - Verdicts (malicious, phishing, malware)
  - Related domains and IPs
  - TLS information
  - ASN and country data
- Creates relationships between observables
- Adds labels based on URLScan.io verdicts
- Adds detailed comments with threat intelligence
- Supports both automatic and manual enrichment

## Configuration

The connector can be configured using environment variables:

```env
OPENCTI_API_URL=http://localhost:4000
OPENCTI_API_KEY=your-api-key
OPENCTI_VERIFY_SSL=false
URLSCAN_CONFIDENCE_LEVEL=60
URLSCAN_UPDATE_EXISTING_DATA=false
URLSCAN_UPDATE_FREQUENCY=30
```

### Environment Variables

- `OPENCTI_API_URL`: URL of your OpenCTI instance
- `OPENCTI_API_KEY`: Your OpenCTI API key
- `OPENCTI_VERIFY_SSL`: Whether to verify SSL certificates
- `URLSCAN_CONFIDENCE_LEVEL`: Confidence level for created observables (default: 60)
- `URLSCAN_UPDATE_EXISTING_DATA`: Whether to update existing data (default: false)
- `URLSCAN_UPDATE_FREQUENCY`: How often to check for updates in seconds (default: 30)

## Usage

### Running the Connector

```bash
python main.py
```

### Command Line Options

- `-t, --test`: Run in test mode (no OpenCTI integration)
- `-d, --debug`: Enable debug logging
- `-a, --active-only`: Only process URLs with status code 200
- `domain`: Optional domain to search for in URLScan.io

### Example Commands

```bash
# Run normally
python main.py

# Run in test mode
python main.py -t

# Run with debug logging
python main.py -d

# Only process active URLs
python main.py -a

# Search for specific domain
python main.py example.com
```

## Enrichment Process

1. When a Domain-Name or URL observable is selected for enrichment:
   - The connector fetches data from URLScan.io
   - Creates relationships with related domains and IPs
   - Adds labels based on verdicts
   - Creates detailed comments with threat intelligence

2. For malicious URLs:
   - Adds "malicious" and "urlscan-malicious" labels
   - Creates relationships with targeted sectors
   - Adds detailed comments about the malicious activity

3. The connector maintains a 30-second update frequency to check for new data

## Output

The connector creates:
- Relationships between observables
- Labels based on URLScan.io verdicts
- Detailed comments with threat intelligence
- Knowledge entries for relationships

## Requirements

- Python 3.7+
- OpenCTI Platform
- URLScan.io API access

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Configure environment variables
4. Run the connector

## License

This project is licensed under the MIT License - see the LICENSE file for details. 