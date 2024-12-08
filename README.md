# ScanMaster - Web Vulnerability Scanner

![Version](https://img.shields.io/badge/version-1.0-blue)
![Python](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

ScanMaster is a comprehensive web vulnerability scanner designed to identify potential security risks and vulnerabilities in web applications. It performs various security checks including SSL/TLS configuration, security headers, domain analysis, and phishing detection.

```ascii
   _____                 __  ___           __           
  / ___/_________ ___  /  |/  /___ ______/ /____  _____
  \__ \/ ___/ __ `__ \/ /|_/ / __ `/ ___/ __/ _ \/ ___/
 ___/ / /__/ / / / / / /  / / /_/ (__  ) /_/  __/ /    
/____/\___/_/ /_/ /_/_/  /_/\__,_/____/\__/\___/_/     
```

## Features

- 🔒 **SSL/TLS Analysis**
  - Certificate validation
  - Expiration checking
  - Protocol security assessment

- 🛡️ **Security Headers Check**
  - X-XSS-Protection
  - X-Frame-Options
  - Content-Security-Policy
  - HSTS
  - And more...

- 🔍 **Directory Enumeration**
  - Common sensitive directories
  - Backup files
  - Configuration files

- 🌐 **Domain Analysis**
  - Age verification
  - DNS record checking
  - Similarity with legitimate domains

- 🚨 **Phishing Detection**
  - URL pattern analysis
  - Domain reputation check
  - Security indicators

- 📊 **Risk Assessment**
  - Color-coded findings (High, Medium, Low)
  - Detailed vulnerability descriptions
  - Summary reports

## Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/scanmaster.git
cd scanmaster
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python scan_master.py -u <target_url>
```

Options:
- `-u, --url`: Target URL to scan (required)
- `-t, --threads`: Number of threads for scanning (default: 5)

Example:
```bash
python scan_master.py -u example.com -t 10
```

## Output

The scanner provides a detailed report with:
- Color-coded risk levels (High, Medium, Low)
- Tabulated findings with descriptions
- Summary statistics
- Visual indicators

## Dependencies

- requests>=2.31.0: HTTP library
- python-whois>=0.8.0: Domain information retrieval
- tldextract>=3.4.4: URL parsing
- dnspython>=2.4.2: DNS toolkit
- colorama>=0.4.6: Colored terminal output
- tabulate>=0.9.0: Table formatting

## Security Considerations

- Always obtain proper authorization before scanning any website
- Be aware that aggressive scanning might trigger security measures
- Some checks might be blocked by firewalls or WAFs
- Use responsibly and ethically

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and ethical testing purposes only. Users are responsible for obtaining proper authorization before scanning any systems they don't own. The authors are not responsible for any misuse or damage caused by this program.
