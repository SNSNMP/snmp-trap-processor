# SNMP Trap Processor

A Python-based SNMP trap listener and processor with a web interface for monitoring and managing network events.

## Features

- Asynchronous SNMP trap listener
- Dynamic trap processing with configurable extraction rules
- Web interface for real-time trap monitoring
- Configurable trap filtering and blocking
- Support for multiple trap types through configuration
- Logging and event tracking
- Enrichment capabilities for trap data

## Requirements

- Python 3.11 or higher
- Required Python packages (see requirements.txt)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/snmp-trap-processor.git
cd snmp-trap-processor
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

The system is configured through `config.yaml`. Key configuration sections:

- `trap_listener`: SNMP trap listener settings
- `trap_processor`: Processing and web interface settings
- `extraction_rules`: Dynamic rules for processing different trap types
- `enrichments`: Configuration for enriching trap data

Example configuration for Fortinet VPN traps:
```yaml
extraction_rules:
  ".1.3.6.1.4.1.12356.103.0":
    instance_name:
      - pattern: 'devname="([^"]+)"'
        varbind_oid: ".1.3.6.1.4.1.12356.100.1.3.1.1.0"
    event_name:
      - pattern: 'vpntunnel="([^"]+)"'
        varbind_oid: ".1.3.6.1.4.1.12356.100.1.3.1.1.0"
```

## Usage

1. Start the web interface:
```bash
python web_interface.py
```

2. Access the web interface at `http://localhost:5000`

3. Configure your SNMP devices to send traps to port 1162 (default)

## Project Structure

```
snmp-trap-processor/
├── config.yaml           # Configuration file
├── requirements.txt      # Python dependencies
├── trap_listener.py     # SNMP trap listener
├── trap_processor.py    # Trap processing logic
├── web_interface.py     # Web interface
├── templates/           # HTML templates
│   └── index.html      # Main web interface template
└── logs/               # Log files directory
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 