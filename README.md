# URLScan.io OpenCTI Connector

A powerful connector that enriches OpenCTI observables with data from URLScan.io, providing detailed analysis of URLs and domains for threat intelligence.

## Features

- **Automated Enrichment**: Automatically enriches URLs and domains in OpenCTI with URLScan.io data
- **Comprehensive Analysis**: Includes verdicts, targeting information, and technical details
- **Smart Rate Limiting**: Respects URLScan.io's limit of 100 requests per hour
- **Relationship Mapping**: Creates relationships between URLs, domains, IPs, and targeted sectors
- **Label Management**: Automatically adds relevant labels based on analysis results
- **External References**: Links to detailed URLScan.io reports
- **Note Creation**: Generates detailed analysis notes with verdicts and findings

## Prerequisites

- Python 3.8 or higher
- OpenCTI platform (version 5.0 or higher)
- URLScan.io API access
- Required Python packages (see `requirements.txt`)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/opencti-urlscan.git
cd opencti-urlscan
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.example .env
```

Edit the `.env` file with your configuration:
```env
OPENCTI_API_URL=http://localhost:8080
OPENCTI_API_KEY=your-api-key
CONNECTOR_SCOPE=Domain-Name,Url
CONFIDENCE_LEVEL=60
CONNECTOR_AUTO=true
ONLY_ACTIVE_URLS=false
UPDATE_EXISTING_DATA=true
```

## Docker Setup

1. Create a `Dockerfile`:
```dockerfile
FROM python:3.8-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "main.py"]
```

2. Build and run:
```bash
docker build -t urlscan-connector .
docker run -d --name urlscan-connector urlscan-connector
```

## Usage

### Running as a Service

1. Start the connector in normal mode:
```bash
python main.py
```

The connector will:
- Listen for new observables in OpenCTI
- Automatically enrich them with URLScan.io data
- Create relationships and notes
- Add relevant labels

### Testing Mode

Test the connector with a specific domain:
```bash
python main.py -t example.com
```

Additional options:
- `-d, --debug`: Enable debug logging
- `-a, --active-only`: Only process URLs with status code 200
- `-t, --test`: Run in test mode

## Configuration Options

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `OPENCTI_API_URL` | OpenCTI API URL | `http://localhost:8080` |
| `OPENCTI_API_KEY` | OpenCTI API key | Required |
| `CONNECTOR_SCOPE` | Types of observables to process | `Domain-Name,Url` |
| `CONFIDENCE_LEVEL` | Confidence level for enrichment | `60` |
| `CONNECTOR_AUTO` | Enable automatic enrichment | `true` |
| `ONLY_ACTIVE_URLS` | Only process active URLs | `false` |
| `UPDATE_EXISTING_DATA` | Update existing data | `true` |

## Rate Limiting

The connector implements rate limiting to respect URLScan.io's limit of 100 requests per hour:
- Tracks request count and timing in memory
- Automatically waits when limit is reached
- Resets counter after one hour
- Provides warning messages when waiting

## Enrichment Details

The connector enriches observables with:

1. **Verdicts**:
   - Overall malicious status
   - URLScan.io analysis
   - Community verdicts
   - Engine results

2. **Targeting Information**:
   - Targeted brands
   - Categories
   - Sectors

3. **Technical Details**:
   - Page information
   - TLS details
   - IP and ASN information
   - Status codes

4. **Relationships**:
   - URL to Domain
   - URL to IP
   - URL to Sectors
   - URL to Organizations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please:
1. Check the [documentation](docs/)
2. Open an issue in the repository
3. Contact the maintainers

## Acknowledgments

- [OpenCTI](https://www.opencti.io/)
- [URLScan.io](https://urlscan.io/)
- All contributors and users of this connector 