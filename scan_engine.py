import logging
import time
import re
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from config import Config
from models import Vulnerability

logger = logging.getLogger(__name__)

class ScanEngine:
    def __init__(self, target_url, scan_type, scan_result=None):
        self.target_url = target_url
        self.scan_type = scan_type
        self.scan_result = scan_result
        self.vulnerabilities = []
        self.config = Config.SCAN_TYPES.get(scan_type, Config.SCAN_TYPES['light'])
        self.timeout = self.config.get('timeout', 60)
        self.checks = self.config.get('checks', [])
        self.headers = {
            'User-Agent': 'PhantomStrike Vulnerability Scanner',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        self.session = requests.Session()
        self.visited_urls = set()
        self.stop_scan = threading.Event()
        self._open_ports = {}  # Track open ports for network scans
        
    def validate_url(self):
        """Validate if the target URL is properly formatted and accessible."""
        try:
            parsed_url = urlparse(self.target_url)
            if not parsed_url.scheme or not parsed_url.netloc:
                return False, "Invalid URL format. Please use format: http(s)://example.com"
            
            # Check if the URL is accessible
            response = self.session.get(
                self.target_url, 
                headers=self.headers, 
                timeout=10, 
                allow_redirects=True,
                verify=False  # Not verifying SSL for scanning purposes
            )
            response.raise_for_status()
            return True, None
        except requests.exceptions.RequestException as e:
            return False, f"Error accessing URL: {str(e)}"
    
    def run_scan(self):
        """Run the main scan process based on the scan type."""
        logger.info(f"Starting {self.scan_type} scan on {self.target_url}")
        
        valid, error_message = self.validate_url()
        if not valid:
            logger.error(f"URL validation failed: {error_message}")
            return False, error_message
        
        try:
            # For network scan type, run nmap-style scan
            if self.scan_type == 'network':
                logger.info(f"Running network scan on {self.target_url}")
                self._run_network_scan()
            else:
                # For web vulnerability scans (light, medium, deep)
                logger.info(f"Running {self.scan_type} web vulnerability scan with checks: {self.checks}")
                self._run_web_vulnerability_scan()
                
            return True, "Scan completed successfully"
        except Exception as e:
            logger.exception(f"Error during scan: {str(e)}")
            return False, f"Scan failed: {str(e)}"
    
    def _run_web_vulnerability_scan(self):
        """Run web vulnerability scanning tests."""
        # First discover pages to scan
        discovered_urls = self._discover_urls()
        logger.info(f"Discovered {len(discovered_urls)} URLs to scan")
        
        # Run the appropriate checks based on scan type
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            
            for url in discovered_urls:
                if self.stop_scan.is_set():
                    logger.info("Scan was stopped by user.")
                    break
                
                # Get the scan checks based on scan type
                for check in self.checks:
                    checker_name = f"_check_{check}"
                    if hasattr(self, checker_name):
                        logger.info(f"Submitting {check} check for URL: {url}")
                        checker_method = getattr(self, checker_name)
                        futures.append(executor.submit(checker_method, url))
                    else:
                        logger.warning(f"Check '{check}' is configured but not implemented")
            
            # Process the results as they complete
            completed_checks = 0
            for future in as_completed(futures):
                try:
                    future.result()
                    completed_checks += 1
                    logger.info(f"Completed check {completed_checks}/{len(futures)}")
                except Exception as e:
                    logger.exception(f"Error in vulnerability check: {str(e)}")
        
        logger.info(f"Web vulnerability scan completed with {len(self.vulnerabilities)} findings")
    
    def _discover_urls(self):
        """Discover URLs to scan by crawling the site."""
        discovered_urls = set([self.target_url])
        to_visit = [self.target_url]
        max_urls = 20  # Limit to prevent too much crawling
        
        while to_visit and len(discovered_urls) < max_urls:
            if self.stop_scan.is_set():
                break
                
            current_url = to_visit.pop(0)
            self.visited_urls.add(current_url)
            
            try:
                response = self.session.get(
                    current_url, 
                    headers=self.headers, 
                    timeout=10,
                    verify=False
                )
                
                # Skip non-HTML responses
                if 'text/html' not in response.headers.get('Content-Type', ''):
                    continue
                    
                soup = BeautifulSoup(response.text, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    # Create absolute URL
                    if not href.startswith(('http://', 'https://')):
                        href = urljoin(current_url, href)
                    
                    # Ensure we stay on the same domain
                    if urlparse(href).netloc == urlparse(self.target_url).netloc:
                        if href not in discovered_urls and href not in to_visit:
                            discovered_urls.add(href)
                            to_visit.append(href)
            
            except Exception as e:
                logger.warning(f"Error discovering URL {current_url}: {str(e)}")
        
        return discovered_urls
    
    def _run_network_scan(self):
        """Run a simple network port scan on the target."""
        logger.info("Starting network port scan")
        
        # Parse hostname from URL
        hostname = urlparse(self.target_url).netloc
        if ':' in hostname:
            hostname = hostname.split(':')[0]
            
        # Resolve IP address
        try:
            ip_address = socket.gethostbyname(hostname)
            logger.info(f"Resolved {hostname} to {ip_address}")
        except socket.gaierror as e:
            logger.error(f"Could not resolve hostname {hostname}: {str(e)}")
            raise ValueError(f"Could not resolve hostname {hostname}")
            
        # Determine port range to scan
        port_range = range(1, 1001)  # Default to scan ports 1-1000
        port_range_str = "1-1000"  # For logging
        
        if 'ports' in self.config:
            try:
                port_range_str = self.config['ports']
                if '-' in self.config['ports']:
                    start_port, end_port = map(int, self.config['ports'].split('-'))
                    port_range = range(start_port, end_port + 1)
                else:
                    port_range = [int(port) for port in self.config['ports'].split(',')]
                logger.info(f"Using configured port range: {port_range_str}")
            except (ValueError, IndexError) as e:
                logger.warning(f"Invalid port range configuration: {self.config['ports']}: {str(e)}. Using default 1-1000.")
        
        logger.info(f"Scanning {ip_address} on port range {port_range_str}")
        
        # Track open ports for reporting
        open_ports = []
        total_ports = len(list(port_range))
        
        # Use a thread pool to scan ports in parallel
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._check_port, ip_address, port): port for port in port_range}
            
            # Process results as they complete
            completed = 0
            for future in as_completed(futures):
                port = futures[future]
                try:
                    is_open = future.result()
                    
                    # If port is open, record it as a vulnerability
                    if is_open:
                        open_ports.append(port)
                        self._open_ports[port] = True
                        self._record_network_vulnerability(ip_address, port)
                        logger.info(f"Found open port: {port}")
                except Exception as e:
                    logger.warning(f"Error checking port {port}: {str(e)}")
                
                # Update progress periodically
                completed += 1
                if completed % 100 == 0 or completed == total_ports:
                    progress = (completed / total_ports) * 100
                    logger.info(f"Network scan progress: {progress:.1f}% ({completed}/{total_ports})")
        
        logger.info(f"Network scan completed. Found {len(open_ports)} open ports.")
    
    def _check_port(self, ip_address, port):
        """Check if a port is open on the target IP."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_address, port))
        sock.close()
        return result == 0
    
    def _record_network_vulnerability(self, ip_address, port):
        """Record a network vulnerability finding."""
        # Common ports and their associated services
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            1433: 'MS-SQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        
        # Get service name
        service = common_ports.get(port, 'Unknown')
        
        # Basic description for all open ports
        description = f"Open port {port} ({service}) detected on {ip_address}"
        severity = "low"  # Default severity
        remediation = "Consider closing this port if the service is not required. If needed, implement proper authentication and encryption."
        remediation_code = None
        
        # Customize severity and recommendations based on port/service
        if port in [21, 23]:
            # Unencrypted protocols
            severity = "high"
            description += ". This service transmits data in cleartext and should be avoided."
            remediation = "Replace FTP with SFTP or FTPS. Replace Telnet with SSH. Disable these legacy unencrypted services if possible."
        
        elif port in [3389, 445, 1433, 3306, 5432, 27017]:
            # Database and admin services
            severity = "medium"
            description += ". This service provides administrative or database access and should be restricted."
            remediation = "Restrict access to this port to trusted IP addresses only. Ensure strong authentication is enforced."
            
            if port == 3306:
                remediation_code = "# MySQL firewall rule example (Linux)\niptables -A INPUT -p tcp -s trusted_ip_address --dport 3306 -j ACCEPT\niptables -A INPUT -p tcp --dport 3306 -j DROP"
            elif port == 5432:
                remediation_code = "# PostgreSQL pg_hba.conf example\nhost    all    all    trusted_ip_address/32    md5\nhost    all    all    0.0.0.0/0    reject"
        
        elif port in [80, 8080]:
            # HTTP - check if HTTPS is also available
            if 443 not in [p for p, is_open in getattr(self, '_open_ports', {}).items() if is_open]:
                description += ". HTTP service without HTTPS detected."
                remediation = "Consider implementing HTTPS with valid certificates to encrypt web traffic."
                remediation_code = "# Nginx HTTPS configuration example\nserver {\n    listen 443 ssl;\n    ssl_certificate /path/to/cert.pem;\n    ssl_certificate_key /path/to/key.pem;\n    # ...\n}"
        
        # Create vulnerability record
        vulnerability = Vulnerability(
            scan_result_id=self.scan_result.id if self.scan_result else None,
            vulnerability_type="Open Port",
            description=description,
            location=f"{ip_address}:{port}",
            severity=severity,
            evidence=f"Port {port} ({service}) is open and accepting connections.",
            remediation=remediation,
            remediation_code=remediation_code
        )
        
        # Add to findings list
        self.vulnerabilities.append(vulnerability)
        logger.info(f"Recorded network vulnerability: {description} (Severity: {severity})")
    
    def _check_xss(self, url):
        """Check for Cross-Site Scripting vulnerabilities."""
        logger.debug(f"Checking XSS on {url}")
        
        # Common XSS payloads for testing
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '\'><img src=x onerror=alert(1)>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>'
        ]
        
        # Extract forms from the page
        try:
            response = self.session.get(
                url, 
                headers=self.headers, 
                timeout=10,
                verify=False
            )
            
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return
                
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            # Check GET parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parsed_url.query.split('&')
                for param in query_params:
                    if '=' in param:
                        param_name = param.split('=')[0]
                        
                        for payload in xss_payloads:
                            test_url = url.replace(param, f"{param_name}={payload}")
                            
                            try:
                                test_response = self.session.get(
                                    test_url, 
                                    headers=self.headers, 
                                    timeout=10,
                                    verify=False
                                )
                                
                                if payload in test_response.text:
                                    self._record_vulnerability(
                                        "XSS",
                                        f"Reflected XSS vulnerability found in GET parameter '{param_name}'",
                                        url,
                                        "high",
                                        f"Parameter '{param_name}' reflects unfiltered input: {payload}",
                                        "Implement proper input validation and output encoding. Consider using Content-Security-Policy.",
                                        "response.write(escapeHtml(userInput));"
                                    )
                                    break
                            except:
                                continue
            
            # Check each form
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                # Create absolute URL for form action
                if form_action and not form_action.startswith(('http://', 'https://')):
                    form_action = urljoin(url, form_action)
                else:
                    form_action = url
                
                # Get all input fields
                inputs = form.find_all(['input', 'textarea'])
                input_data = {}
                
                for input_field in inputs:
                    input_name = input_field.get('name')
                    if input_name:
                        input_data[input_name] = 'test'
                
                # Skip if no inputs
                if not input_data:
                    continue
                
                # Test each field with XSS payloads
                for input_name in input_data.keys():
                    for payload in xss_payloads:
                        test_data = input_data.copy()
                        test_data[input_name] = payload
                        
                        try:
                            if form_method == 'post':
                                test_response = self.session.post(
                                    form_action, 
                                    data=test_data, 
                                    headers=self.headers, 
                                    timeout=10,
                                    verify=False
                                )
                            else:
                                test_response = self.session.get(
                                    form_action, 
                                    params=test_data, 
                                    headers=self.headers, 
                                    timeout=10,
                                    verify=False
                                )
                                
                            if payload in test_response.text:
                                self._record_vulnerability(
                                    "XSS",
                                    f"Reflected XSS vulnerability found in {form_method.upper()} parameter '{input_name}'",
                                    url,
                                    "high",
                                    f"Form field '{input_name}' reflects unfiltered input: {payload}",
                                    "Implement proper input validation and output encoding. Consider using Content-Security-Policy.",
                                    "response.write(escapeHtml(userInput));"
                                )
                                break
                        except:
                            continue
                            
        except Exception as e:
            logger.warning(f"Error during XSS check on {url}: {str(e)}")
    
    def _check_sqli(self, url):
        """Check for SQL Injection vulnerabilities."""
        logger.debug(f"Checking SQL Injection on {url}")
        
        # Common SQL Injection payloads
        sqli_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1 --",
            "\" OR 1=1 --",
            "' OR '1'='1' --",
            "1' OR '1'='1",
            "admin'--",
            "1;DROP TABLE users",
            "1' UNION SELECT 1,2,3--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--"
        ]
        
        # Error patterns that might indicate SQL injection
        sql_error_patterns = [
            "SQL syntax",
            "mysql_fetch_array",
            "ORA-",
            "MySQL server version",
            "Unclosed quotation mark",
            "PostgreSQL query failed",
            "quotation mark after the character string",
            "SQLite3::query",
            "Microsoft OLE DB Provider for SQL Server",
            "Microsoft OLE DB Provider for ODBC"
        ]
        
        # Extract forms and parameters
        try:
            response = self.session.get(
                url, 
                headers=self.headers, 
                timeout=10,
                verify=False
            )
            
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return
                
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            # Check GET parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parsed_url.query.split('&')
                for param in query_params:
                    if '=' in param:
                        param_name = param.split('=')[0]
                        
                        for payload in sqli_payloads:
                            test_url = url.replace(param, f"{param_name}={payload}")
                            
                            try:
                                test_response = self.session.get(
                                    test_url, 
                                    headers=self.headers, 
                                    timeout=10,
                                    verify=False
                                )
                                
                                # Check for SQL errors in the response
                                for pattern in sql_error_patterns:
                                    if pattern in test_response.text:
                                        self._record_vulnerability(
                                            "SQLi",
                                            f"SQL Injection vulnerability found in GET parameter '{param_name}'",
                                            url,
                                            "high",
                                            f"SQL error detected when using payload: {payload}",
                                            "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.",
                                            "const results = await db.query('SELECT * FROM users WHERE id = ?', [userId]);"
                                        )
                                        break
                            except:
                                continue
            
            # Check each form
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                # Create absolute URL for form action
                if form_action and not form_action.startswith(('http://', 'https://')):
                    form_action = urljoin(url, form_action)
                else:
                    form_action = url
                
                # Get all input fields
                inputs = form.find_all(['input', 'textarea'])
                input_data = {}
                
                for input_field in inputs:
                    input_name = input_field.get('name')
                    if input_name:
                        input_data[input_name] = 'test'
                
                # Skip if no inputs
                if not input_data:
                    continue
                
                # Test each field with SQL injection payloads
                for input_name in input_data.keys():
                    for payload in sqli_payloads:
                        test_data = input_data.copy()
                        test_data[input_name] = payload
                        
                        try:
                            if form_method == 'post':
                                test_response = self.session.post(
                                    form_action, 
                                    data=test_data, 
                                    headers=self.headers, 
                                    timeout=10,
                                    verify=False
                                )
                            else:
                                test_response = self.session.get(
                                    form_action, 
                                    params=test_data, 
                                    headers=self.headers, 
                                    timeout=10,
                                    verify=False
                                )
                                
                            # Check for SQL errors in the response
                            for pattern in sql_error_patterns:
                                if pattern in test_response.text:
                                    self._record_vulnerability(
                                        "SQLi",
                                        f"SQL Injection vulnerability found in {form_method.upper()} parameter '{input_name}'",
                                        url,
                                        "high",
                                        f"SQL error detected when using payload: {payload}",
                                        "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.",
                                        "const results = await db.query('SELECT * FROM users WHERE id = ?', [userId]);"
                                    )
                                    break
                        except:
                            continue
        
        except Exception as e:
            logger.warning(f"Error during SQL Injection check on {url}: {str(e)}")
    
    def _check_csrf(self, url):
        """Check for Cross-Site Request Forgery vulnerabilities."""
        logger.debug(f"Checking CSRF on {url}")
        
        try:
            response = self.session.get(
                url, 
                headers=self.headers, 
                timeout=10,
                verify=False
            )
            
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form', method=re.compile('post', re.I))
            
            for form in forms:
                csrf_found = False
                
                # Look for common CSRF token field names
                csrf_fields = [
                    'csrf', 'csrftoken', 'csrf_token', 'anti-csrf', 'csrfmiddlewaretoken',
                    '_csrf', '_token', 'token', 'authenticity_token', 'xsrf', 'xsrf_token'
                ]
                
                for field_name in csrf_fields:
                    if form.find('input', attrs={'name': re.compile(field_name, re.I)}):
                        csrf_found = True
                        break
                
                if not csrf_found:
                    # Form with POST method but no CSRF protection
                    form_action = form.get('action', '')
                    if form_action and not form_action.startswith(('http://', 'https://')):
                        form_action = urljoin(url, form_action)
                    else:
                        form_action = url
                    
                    self._record_vulnerability(
                        "CSRF",
                        "Cross-Site Request Forgery vulnerability found",
                        url,
                        "medium",
                        f"Form with action '{form_action}' uses POST method but lacks CSRF protection",
                        "Implement CSRF tokens for all forms that modify state. Use the SameSite cookie attribute.",
                        "<!-- Add to your form -->\n<input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\">"
                    )
        
        except Exception as e:
            logger.warning(f"Error during CSRF check on {url}: {str(e)}")
    
    def _check_lfi(self, url):
        """Check for Local File Inclusion vulnerabilities."""
        logger.debug(f"Checking LFI on {url}")
        
        # LFI test payloads
        lfi_payloads = [
            "/etc/passwd",
            "../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "../../../../../../etc/passwd%00",
            "/windows/win.ini",
            "../../../../windows/win.ini",
            "C:\\Windows\\win.ini",
            "../../../../../../../../../../../windows/win.ini"
        ]
        
        # LFI detection patterns
        lfi_patterns = [
            "root:x:",
            "daemon:x:",
            "bin:x:",
            "sys:x:",
            "sync:x:",
            "games:x:",
            "man:x:",
            "lp:x:",
            "mail:x:",
            "[fonts]",
            "[extensions]",
            "[mci extensions]",
            "[files]",
            "[Mail]"
        ]
        
        parsed_url = urlparse(url)
        if parsed_url.query:
            query_params = parsed_url.query.split('&')
            for param in query_params:
                if '=' in param:
                    param_name, param_value = param.split('=', 1)
                    
                    for payload in lfi_payloads:
                        test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={payload}")
                        
                        try:
                            test_response = self.session.get(
                                test_url, 
                                headers=self.headers, 
                                timeout=10,
                                verify=False
                            )
                            
                            for pattern in lfi_patterns:
                                if pattern in test_response.text:
                                    self._record_vulnerability(
                                        "LFI",
                                        f"Local File Inclusion vulnerability found in parameter '{param_name}'",
                                        url,
                                        "high",
                                        f"File content disclosed when using payload: {payload}",
                                        "Implement proper input validation. Never use user input directly in file operations. Use a whitelist approach.",
                                        "// Instead of:\ninclude($_GET['page']);\n// Use:\n$allowed_pages = ['home', 'about', 'contact'];\nif (in_array($_GET['page'], $allowed_pages)) {\n    include($_GET['page'] . '.php');\n}"
                                    )
                                    break
                        except:
                            continue
    
    def _check_rfi(self, url):
        """Check for Remote File Inclusion vulnerabilities."""
        logger.debug(f"Checking RFI on {url}")
        
        # Remote test URL that returns a unique identifier
        rfi_test_url = "https://example.com/rfi_test.txt"
        unique_marker = "RFI_TEST_MARKER_" + str(int(time.time()))
        
        parsed_url = urlparse(url)
        if parsed_url.query:
            query_params = parsed_url.query.split('&')
            for param in query_params:
                if '=' in param:
                    param_name, param_value = param.split('=', 1)
                    
                    test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={rfi_test_url}")
                    
                    try:
                        # We don't actually request external URLs for testing
                        # This is a simulation of RFI testing
                        
                        # In a real scenario, you would host a file with a unique marker
                        # and check if the response contains that marker
                        
                        # For now, we'll check if the URL parameter is directly reflected in the response
                        # which might indicate inadequate filtering
                        test_response = self.session.get(
                            test_url, 
                            headers=self.headers, 
                            timeout=10,
                            verify=False
                        )
                        
                        if rfi_test_url in test_response.text:
                            self._record_vulnerability(
                                "RFI",
                                f"Potential Remote File Inclusion vulnerability in parameter '{param_name}'",
                                url,
                                "high",
                                f"The URL parameter value is reflected in the response",
                                "Implement proper input validation. Never use user input directly in file operations. Use a whitelist approach.",
                                "// Instead of:\ninclude($_GET['page']);\n// Use:\n$allowed_pages = ['home', 'about', 'contact'];\nif (in_array($_GET['page'], $allowed_pages)) {\n    include($_GET['page'] . '.php');\n}"
                            )
                    except:
                        continue
    
    def _check_directory_traversal(self, url):
        """Check for Directory Traversal vulnerabilities."""
        logger.debug(f"Checking Directory Traversal on {url}")
        
        # Directory traversal payloads
        traversal_payloads = [
            "../",
            "../../",
            "../../../",
            "../../../../",
            "../../../../../",
            "..\\..\\",
            "..\\..\\..\\",
            "..\\..\\..\\..\\",
            "..\\..\\..\\..\\..\\",
            "%2e%2e%2f",
            "%252e%252e%252f",
            "..%2f",
            "%2e%2e\\",
            "..%5c",
            "%2e%2e%5c"
        ]
        
        parsed_url = urlparse(url)
        
        # Check path components
        path_parts = parsed_url.path.split('/')
        for i in range(len(path_parts)):
            for payload in traversal_payloads:
                new_path_parts = path_parts.copy()
                if new_path_parts[i]:  # Skip empty parts
                    new_path_parts[i] = payload
                    new_path = '/'.join(new_path_parts)
                    test_url = url.replace(parsed_url.path, new_path)
                    
                    try:
                        original_response = self.session.get(
                            url, 
                            headers=self.headers, 
                            timeout=10,
                            verify=False
                        )
                        
                        test_response = self.session.get(
                            test_url, 
                            headers=self.headers, 
                            timeout=10,
                            verify=False
                        )
                        
                        # If the response changes significantly, it might indicate a traversal issue
                        if (test_response.status_code != original_response.status_code or
                            abs(len(test_response.text) - len(original_response.text)) > 100):
                            self._record_vulnerability(
                                "Directory Traversal",
                                "Potential Directory Traversal vulnerability",
                                url,
                                "high",
                                f"Response changed significantly when using payload: {payload} in path component {i}",
                                "Implement proper input validation for file paths. Use a whitelist approach or avoid using user input in file operations.",
                                "// Instead of:\nfile_get_contents(user_supplied_path);\n// Use:\n$base_dir = '/safe/directory/';\n$file_path = realpath($base_dir . $user_input);\nif (strpos($file_path, $base_dir) === 0) {\n    file_get_contents($file_path);\n}"
                            )
                            break
                    except:
                        continue
        
        # Check query parameters
        if parsed_url.query:
            query_params = parsed_url.query.split('&')
            for param in query_params:
                if '=' in param:
                    param_name, param_value = param.split('=', 1)
                    
                    for payload in traversal_payloads:
                        test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={payload}")
                        
                        try:
                            original_response = self.session.get(
                                url, 
                                headers=self.headers, 
                                timeout=10,
                                verify=False
                            )
                            
                            test_response = self.session.get(
                                test_url, 
                                headers=self.headers, 
                                timeout=10,
                                verify=False
                            )
                            
                            # If the response changes significantly, it might indicate a traversal issue
                            if (test_response.status_code != original_response.status_code or
                                abs(len(test_response.text) - len(original_response.text)) > 100):
                                self._record_vulnerability(
                                    "Directory Traversal",
                                    f"Potential Directory Traversal vulnerability in parameter '{param_name}'",
                                    url,
                                    "high",
                                    f"Response changed significantly when using payload: {payload}",
                                    "Implement proper input validation for file paths. Use a whitelist approach or avoid using user input in file operations.",
                                    "// Instead of:\nfile_get_contents(user_supplied_path);\n// Use:\n$base_dir = '/safe/directory/';\n$file_path = realpath($base_dir . $user_input);\nif (strpos($file_path, $base_dir) === 0) {\n    file_get_contents($file_path);\n}"
                                )
                                break
                        except:
                            continue
    
    def _check_auth_issues(self, url):
        """Check for Authentication related issues."""
        logger.debug(f"Checking Authentication issues on {url}")
        
        try:
            response = self.session.get(
                url, 
                headers=self.headers, 
                timeout=10,
                verify=False
            )
            
            if 'text/html' not in response.headers.get('Content-Type', ''):
                return
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for login forms
            login_forms = []
            for form in soup.find_all('form'):
                # Look for forms with password fields
                password_field = form.find('input', {'type': 'password'})
                if password_field:
                    login_forms.append(form)
            
            for form in login_forms:
                form_action = form.get('action', '')
                if form_action and not form_action.startswith(('http://', 'https://')):
                    form_action = urljoin(url, form_action)
                else:
                    form_action = url
                
                # Check if the form is submitted over HTTPS
                if form_action.startswith('http:'):
                    self._record_vulnerability(
                        "Insecure Authentication",
                        "Login form submits data over unencrypted HTTP",
                        url,
                        "high",
                        f"Login form with action '{form_action}' uses HTTP instead of HTTPS",
                        "Always use HTTPS for login forms. Redirect HTTP to HTTPS. Set the 'Secure' flag on cookies.",
                        "<!-- Change form action to HTTPS -->\n<form action=\"https://example.com/login\" method=\"post\">"
                    )
                
                # Check for CSRF protection in login forms
                csrf_field = None
                for input_field in form.find_all('input'):
                    input_name = input_field.get('name', '').lower()
                    if any(token in input_name for token in ['csrf', 'token', 'xsrf']):
                        csrf_field = input_field
                        break
                
                if not csrf_field:
                    self._record_vulnerability(
                        "CSRF",
                        "Login form lacks CSRF protection",
                        url,
                        "medium",
                        f"Login form with action '{form_action}' has no CSRF token field",
                        "Implement CSRF tokens for login forms to prevent login CSRF attacks.",
                        "<!-- Add to your login form -->\n<input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\">"
                    )
            
            # Check for password in URL
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parsed_url.query.split('&')
                for param in query_params:
                    if '=' in param:
                        param_name, param_value = param.split('=', 1)
                        if param_name.lower() in ['password', 'passwd', 'pass', 'pwd']:
                            self._record_vulnerability(
                                "Password Exposure",
                                "Password transmitted in URL query string",
                                url,
                                "high",
                                f"Password parameter '{param_name}' found in URL",
                                "Never transmit passwords or other sensitive data in URLs. Use POST requests with HTTPS instead.",
                                "<!-- Use POST method instead of GET -->\n<form method=\"post\" action=\"/login\">\n  <!-- form fields -->\n</form>"
                            )
            
            # Check for HTTP Basic Auth
            www_authenticate = response.headers.get('WWW-Authenticate', '')
            if 'Basic' in www_authenticate:
                self._record_vulnerability(
                    "Basic Authentication",
                    "HTTP Basic Authentication is in use",
                    url,
                    "medium",
                    "HTTP Basic Authentication detected in the response headers",
                    "HTTP Basic Authentication transmits credentials as base64 encoded strings which are easily decoded. Consider using a more secure authentication method.",
                    "// Implement a form-based authentication system with secure session management instead of HTTP Basic Auth"
                )
        
        except Exception as e:
            logger.warning(f"Error during Authentication check on {url}: {str(e)}")
    
    def _check_security_misconfigurations(self, url):
        """Check for security misconfigurations."""
        logger.debug(f"Checking security misconfigurations on {url}")
        
        try:
            response = self.session.get(
                url, 
                headers=self.headers, 
                timeout=10,
                verify=False
            )
            
            # Check for security headers
            security_headers = {
                'X-Frame-Options': "Missing X-Frame-Options header - site may be vulnerable to clickjacking",
                'X-XSS-Protection': "Missing X-XSS-Protection header - browser XSS filtering not enabled",
                'X-Content-Type-Options': "Missing X-Content-Type-Options header - MIME-sniffing vulnerabilities possible",
                'Content-Security-Policy': "Missing Content-Security-Policy header - no CSP protection",
                'Strict-Transport-Security': "Missing HSTS header - secure connections not enforced"
            }
            
            for header, message in security_headers.items():
                if header not in response.headers:
                    severity = "medium" if header in ['X-Frame-Options', 'Content-Security-Policy'] else "low"
                    self._record_vulnerability(
                        "Security Misconfiguration",
                        f"Missing security header: {header}",
                        url,
                        severity,
                        message,
                        f"Add the {header} header to HTTP responses to enhance security.",
                        f"# Example for {header}:\n# In Flask:\n@app.after_request\ndef add_security_headers(response):\n    response.headers['{header}'] = 'value'\n    return response"
                    )
            
            # Check for server information disclosure
            server_header = response.headers.get('Server', '')
            if server_header and not server_header.startswith('cloudflare'):
                self._record_vulnerability(
                    "Information Disclosure",
                    "Server header reveals server information",
                    url,
                    "low",
                    f"Server header discloses '{server_header}'",
                    "Configure your web server to omit or obfuscate the Server header to avoid revealing software versions.",
                    "# For Apache:\nServerTokens Prod\nServerSignature Off\n\n# For Nginx:\nserver_tokens off;"
                )
            
            # Check for verbose error messages
            error_patterns = [
                "stack trace", "traceback", "syntax error", "runtime error",
                "exception", "undefined variable", "undefined index",
                "database error", "sql syntax", "odbc driver", "jdbc driver"
            ]
            
            for pattern in error_patterns:
                if pattern in response.text.lower():
                    self._record_vulnerability(
                        "Information Disclosure",
                        "Verbose error messages detected",
                        url,
                        "medium",
                        f"Error details may be exposed to users: found '{pattern}' in response",
                        "Configure proper error handling to prevent leaking technical details in production.",
                        "# In Flask:\n@app.errorhandler(Exception)\ndef handle_exception(e):\n    app.logger.error(f'Unhandled exception: {str(e)}')\n    return render_template('error.html'), 500"
                    )
                    break
            
            # Check for common sensitive files
            common_files = [
                "/robots.txt", "/.git/HEAD", "/.env", "/config.php", "/wp-config.php",
                "/.htaccess", "/admin/", "/phpinfo.php", "/info.php", "/.svn/entries",
                "/.DS_Store", "/backup/", "/database.sql", "/users.sql"
            ]
            
            for file_path in common_files:
                try:
                    file_url = urljoin(url, file_path)
                    file_response = self.session.get(
                        file_url, 
                        headers=self.headers, 
                        timeout=5,
                        verify=False
                    )
                    
                    if file_response.status_code == 200:
                        file_size = len(file_response.content)
                        
                        # Skip empty files
                        if file_size > 0:
                            self._record_vulnerability(
                                "Sensitive File Exposure",
                                f"Sensitive file or directory exposed: {file_path}",
                                file_url,
                                "high" if '.git' in file_path or '.env' in file_path else "medium",
                                f"File exists and is accessible ({file_size} bytes)",
                                "Restrict access to sensitive files and directories. Configure server to deny access to configuration, backup, and version control files.",
                                "# Apache .htaccess:\n<Files ~ \"^\\.(.+)\">\n    Order allow,deny\n    Deny from all\n</Files>\n\n# Nginx:\nlocation ~ /\\.git {\n    deny all;\n}"
                            )
                except:
                    continue
        
        except Exception as e:
            logger.warning(f"Error during Security Misconfiguration check on {url}: {str(e)}")
    
    def _check_sensitive_data_exposure(self, url):
        """Check for sensitive data exposure."""
        logger.debug(f"Checking sensitive data exposure on {url}")
        
        try:
            response = self.session.get(
                url, 
                headers=self.headers, 
                timeout=10,
                verify=False
            )
            
            # Check for HTTP instead of HTTPS
            parsed_url = urlparse(url)
            if parsed_url.scheme.lower() == 'http':
                self._record_vulnerability(
                    "Insecure Communication",
                    "Website uses HTTP instead of HTTPS",
                    url,
                    "high",
                    "Communication is not encrypted with TLS/SSL",
                    "Implement HTTPS across the entire site. Redirect all HTTP traffic to HTTPS.",
                    "# Apache:\n<VirtualHost *:80>\n    RewriteEngine On\n    RewriteRule ^(.*)$ https://%{HTTP_HOST}$1 [R=301,L]\n</VirtualHost>\n\n# Nginx:\nserver {\n    listen 80;\n    return 301 https://$host$request_uri;\n}"
                )
            
            # Check for mixed content
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check for mixed content in resources
                mixed_content = []
                if parsed_url.scheme.lower() == 'https':
                    for tag, attr in [('img', 'src'), ('script', 'src'), ('link', 'href'), ('iframe', 'src')]:
                        for element in soup.find_all(tag, attrs={attr: True}):
                            resource_url = element[attr]
                            if resource_url.startswith('http://'):
                                mixed_content.append(f"{tag}[{attr}]: {resource_url}")
                
                if mixed_content:
                    self._record_vulnerability(
                        "Mixed Content",
                        "Page includes mixed (HTTP/HTTPS) content",
                        url,
                        "medium",
                        f"Found {len(mixed_content)} HTTP resources on HTTPS page: {', '.join(mixed_content[:3])}...",
                        "Ensure all resources (images, scripts, styles, etc.) are loaded over HTTPS.",
                        "// Update resource URLs to use HTTPS or protocol-relative URLs:\n<script src=\"https://example.com/script.js\"></script>\n// Or use protocol-relative URLs:\n<script src=\"//example.com/script.js\"></script>"
                    )
            
            # Check for insecure cookies
            for cookie in response.cookies:
                if not cookie.secure:
                    self._record_vulnerability(
                        "Insecure Cookies",
                        "Cookies set without Secure flag",
                        url,
                        "medium",
                        f"Cookie '{cookie.name}' is set without the Secure flag",
                        "Set the Secure flag on all cookies to ensure they're only sent over HTTPS.",
                        "# In Flask:\napp.config['SESSION_COOKIE_SECURE'] = True\n\n# Setting a cookie directly:\nresponse.set_cookie('name', 'value', secure=True)"
                    )
                
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    self._record_vulnerability(
                        "Insecure Cookies",
                        "Cookies set without HttpOnly flag",
                        url,
                        "medium",
                        f"Cookie '{cookie.name}' is set without the HttpOnly flag",
                        "Set the HttpOnly flag on all cookies to mitigate the risk of client-side script accessing cookies.",
                        "# In Flask:\napp.config['SESSION_COOKIE_HTTPONLY'] = True\n\n# Setting a cookie directly:\nresponse.set_cookie('name', 'value', httponly=True)"
                    )
            
            # Search for potential sensitive data in the response
            sensitive_patterns = [
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
                r"\b(?:\d[ -]*?){13,16}\b",  # Credit card number
                r"\b\d{3}[ -]?\d{2}[ -]?\d{4}\b",  # SSN
                r"password[=:][^\s;]{3,}",  # Password in URL or JSON
                r"api[_-]?key[=:][^\s;]{3,}"  # API key
            ]
            
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, response.text)
                if matches:
                    # Remove duplicates
                    unique_matches = list(set(matches))
                    if len(unique_matches) > 0:
                        evidence = unique_matches[0]
                        # Mask most of the evidence for privacy
                        if len(evidence) > 6:
                            evidence = evidence[:3] + '****' + evidence[-3:]
                        self._record_vulnerability(
                            "Sensitive Data Exposure",
                            "Potential sensitive data exposed in response",
                            url,
                            "high",
                            f"Found pattern matching sensitive data: {evidence}",
                            "Review the page for sensitive data exposure. Do not include sensitive data in responses that could be viewed by unauthorized users.",
                            "// Instead of exposing sensitive data directly, use placeholders or masked values:\n// Instead of: user.email = 'john@example.com';\n// Use: user.email = 'j**n@example.com';"
                        )
        
        except Exception as e:
            logger.warning(f"Error during Sensitive Data Exposure check on {url}: {str(e)}")
    
    def _check_idor(self, url):
        """Check for Insecure Direct Object References."""
        logger.debug(f"Checking IDOR on {url}")
        
        # Parse the URL for numeric IDs
        parsed_url = urlparse(url)
        path_segments = parsed_url.path.split('/')
        
        # Test for IDOR in path segments
        for i, segment in enumerate(path_segments):
            # Check if segment looks like an ID (numeric or UUID)
            is_numeric = segment.isdigit()
            is_uuid = re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', segment)
            
            if is_numeric or is_uuid:
                original_response = None
                try:
                    original_response = self.session.get(
                        url, 
                        headers=self.headers, 
                        timeout=10,
                        verify=False
                    )
                except:
                    continue
                
                # Test with a different ID
                test_segments = path_segments.copy()
                if is_numeric:
                    # Try an adjacent ID
                    test_segments[i] = str(int(segment) + 1)
                elif is_uuid:
                    # Modify one character of the UUID
                    uid_chars = list(segment)
                    # Modify a character in the UUID that's not a hyphen
                    for j, c in enumerate(uid_chars):
                        if c != '-':
                            uid_chars[j] = 'f' if c != 'f' else 'e'
                            break
                    test_segments[i] = ''.join(uid_chars)
                
                test_path = '/'.join(test_segments)
                test_url = url.replace(parsed_url.path, test_path)
                
                try:
                    test_response = self.session.get(
                        test_url, 
                        headers=self.headers, 
                        timeout=10,
                        verify=False
                    )
                    
                    # If we get a success response (200) for both requests
                    # but they have similar content sizes, this might indicate IDOR
                    if (original_response.status_code == 200 and test_response.status_code == 200 and
                        abs(len(original_response.text) - len(test_response.text)) < 1000):
                        
                        self._record_vulnerability(
                            "IDOR",
                            "Potential Insecure Direct Object Reference",
                            url,
                            "high",
                            f"Changing ID parameter '{segment}' in URL path allows access to different resource",
                            "Implement proper access control checks. Validate that the user has permission to access the requested resource.",
                            "// Example access control check in Node.js/Express:\napp.get('/resource/:id', function(req, res) {\n  const resourceId = req.params.id;\n  // Check if user has permission to access this resource\n  if (!hasAccess(req.user, resourceId)) {\n    return res.status(403).send('Forbidden');\n  }\n  // Proceed with resource access\n});"
                        )
                except:
                    continue
        
        # Test for IDOR in query parameters
        if parsed_url.query:
            query_params = parsed_url.query.split('&')
            for param in query_params:
                if '=' in param:
                    param_name, param_value = param.split('=', 1)
                    
                    # Check if parameter value looks like an ID (numeric or UUID)
                    is_numeric = param_value.isdigit()
                    is_uuid = re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', param_value)
                    
                    if is_numeric or is_uuid:
                        original_response = None
                        try:
                            original_response = self.session.get(
                                url, 
                                headers=self.headers, 
                                timeout=10,
                                verify=False
                            )
                        except:
                            continue
                        
                        # Test with a different ID
                        if is_numeric:
                            test_value = str(int(param_value) + 1)
                        elif is_uuid:
                            # Modify one character of the UUID
                            uid_chars = list(param_value)
                            for j, c in enumerate(uid_chars):
                                if c != '-':
                                    uid_chars[j] = 'f' if c != 'f' else 'e'
                                    break
                            test_value = ''.join(uid_chars)
                        
                        test_url = url.replace(f"{param_name}={param_value}", f"{param_name}={test_value}")
                        
                        try:
                            test_response = self.session.get(
                                test_url, 
                                headers=self.headers, 
                                timeout=10,
                                verify=False
                            )
                            
                            # If we get a success response (200) for both requests
                            # but they have similar content sizes, this might indicate IDOR
                            if (original_response.status_code == 200 and test_response.status_code == 200 and
                                abs(len(original_response.text) - len(test_response.text)) < 1000):
                                
                                self._record_vulnerability(
                                    "IDOR",
                                    "Potential Insecure Direct Object Reference",
                                    url,
                                    "high",
                                    f"Changing ID parameter '{param_name}' in query string allows access to different resource",
                                    "Implement proper access control checks. Validate that the user has permission to access the requested resource.",
                                    "// Example access control check in Node.js/Express:\napp.get('/resource', function(req, res) {\n  const resourceId = req.query.id;\n  // Check if user has permission to access this resource\n  if (!hasAccess(req.user, resourceId)) {\n    return res.status(403).send('Forbidden');\n  }\n  // Proceed with resource access\n});"
                                )
                        except:
                            continue
    
    def _record_vulnerability(self, vulnerability_type, description, location, severity, evidence, remediation, remediation_code=None):
        """Record a vulnerability finding."""
        vulnerability = Vulnerability(
            scan_result_id=self.scan_result.id if self.scan_result else None,
            vulnerability_type=vulnerability_type,
            description=description,
            location=location,
            severity=severity,
            evidence=evidence,
            remediation=remediation,
            remediation_code=remediation_code
        )
        
        self.vulnerabilities.append(vulnerability)
        logger.info(f"Recorded vulnerability: {vulnerability_type} at {location}")
