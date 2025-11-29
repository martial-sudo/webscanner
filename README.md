# webscanner
Automated Web Application Penetration Testing ToolA modular, multi-threaded Command Line Interface (CLI) tool designed to automate the reconnaissance and vulnerability scanning phases of web application penetration testing.

⚠️ DISCLAIMER: This tool is for educational purposes and ethical testing only. Usage of this tool for attacking targets without prior mutual consent is illegal. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.

🚀 Features

🔍 Subdomain Enumeration: Multi-threaded DNS and HTTP validation to discover active subdomains.

🕷️ Intelligent Crawling: Recursively crawls the target to map URLs, forms, and inputs.

💉 Vulnerability Scanning:

SQL Injection (SQLi): Detects error-based SQL injection in URL parameters and forms.

Cross-Site Scripting (XSS): Tests for reflected XSS vulnerabilities.

Local File Inclusion (LFI): Checks for directory traversal patterns.

CSRF: Identifies forms missing Anti-CSRF tokens.

🛡️ Security Header Analysis: Checks for missing headers like X-Frame-Options, HSTS, and CSP.

📊 Reporting: Generates comprehensive HTML reports and JSON logs.

⚡ Performance: Uses concurrent.futures for fast, parallel processing.

⚙️ Customizable: Supports custom wordlists for subdomains and payloads.


🛠️ Installation

Clone the repository:

git clone https://github.com/martial-sudo/webscanner.git

cd webscanner

Install dependencies:This tool requires Python 3 and a few external libraries.

pip install requests beautifulsoup4


📖 Usage

Basic Scan

Perform a standard crawl and vulnerability scan on a target URL:

python webscanner.py -u http://example.com

Enable Subdomain Enumeration
Scan for vulnerabilities and enumerate subdomains (default 10 threads): 

python webscanner.py -u http://example.com --scan-subdomains

Full Custom Scan

Run a comprehensive scan with custom wordlists and JSON output: 

python webscanner.py -u http://example.com \
    --scan-subdomains \
    --subdomain-wordlist wordlists/subdomains.txt \
    --sql-wordlist wordlists/sqli.txt \
    --json results.json \
    --verbose
    
Command Line Arguments and Argument Description

-u, --url Target URL to scan (Required)

-e, --exclude Comma-separated list of URLs to exclude from crawling

-o, --output Output HTML report filename (Default: report.html)

--json Save results as a JSON file

--scan-subdomains Enable subdomain enumeration

--subdomain-threads Number of threads for subdomain checking (Default: 10)

-v, --verbose Enable verbose (debug) logging📊 

Sample Report

The tool generates a clean HTML report highlighting:

Scan duration and scope.

Summary of High/Medium/Low severity risks.

Detailed breakdown of found subdomains.

Specific URLs, payloads, and evidence for every vulnerability found.


📂 Project Structure

webscanner.py: Main entry point and logic.

SubdomainEnumerator: Class handling multi-threaded DNS/HTTP checks.

WebScanner: Core class for crawling and payload injection.

setup_logging: Configures console and file-based logging.

🤝 Contributing

Contributions are welcome!

Please feel free to submit a Pull Request.

Fork the project.

Create your feature branch (git checkout -b feature/AmazingFeature).

Commit your changes (git commit -m 'Add some AmazingFeature').

Push to the branch (git push origin feature/AmazingFeature).

Open a Pull Request.

📝 License

Distributed under the MIT License. See LICENSE for more information.
