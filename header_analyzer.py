import argparse
import requests
import re
import json
import urllib.parse
import base64
import html
from bs4 import BeautifulSoup
import random
import string
import os
import time
import warnings
from urllib3.exceptions import InsecureRequestWarning
import concurrent.futures
from datetime import datetime

# Suppress SSL warnings
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

# ASCII Art Banner
BANNER = r"""
  ____                             _     ____                           _                 
 / ___|  ___  ___ _   _ _ __ ___  / \   / ___|  ___ _ __ __ _ _ __   ___| |_ ___ _ __ ___  
 \___ \ / _ \/ __| | | | '__/ _ \/ _ \  \___ \ / __| '__/ _` | '_ \ / _ \ __/ _ \ '_ ` _ \ 
  ___) |  __/ (__| |_| | | |  __/ ___ \  ___) | (__| | | (_| | | | |  __/ ||  __/ | | | | |
 |____/ \___|\___|\__,_|_|  \___/_/   \_\ |____/ \___|_|  \__,_|_| |_|\___|\__\___|_| |_| |_|
 
 >> Advanced Security Scanner by kcoof <<
 >> GitHub: https://github.com/kcoof/security-scanner <<
"""

class SecurityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecurityScanner/1.0 (+https://github.com/kcoof)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })
        self.vuln_payloads = {
            'xss': self.generate_xss_payloads(),
            'sqli': self.generate_sqli_payloads()
        }
        self.results = {}
        self.scan_stats = {
            'total_targets': 0,
            'vulnerable_targets': 0,
            'total_vulns': 0,
            'start_time': time.time()
        }
    
    def print_banner(self):
        """Print the tool banner"""
        print("\033[1;36m" + BANNER + "\033[0m")
        print(f"\033[1;33mScan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\033[0m\n")
    
    def scan_targets(self, targets):
        """Scan multiple targets"""
        self.scan_stats['total_targets'] = len(targets)
        
        print(f"\033[1;34m[•] Scanning {len(targets)} targets\033[0m")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(self.scan, target): target for target in targets}
            for future in concurrent.futures.as_completed(future_to_url):
                target = future_to_url[future]
                try:
                    result = future.result()
                    if result and result['vulnerabilities']:
                        self.scan_stats['vulnerable_targets'] += 1
                        self.scan_stats['total_vulns'] += len(result['vulnerabilities'])
                except Exception as e:
                    print(f"\033[1;31m[!] Error scanning {target}: {str(e)}\033[0m")
        
        self.generate_summary_report()
    
    def scan(self, target_url):
        """Scan a single target"""
        # Ensure URL has a scheme
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        result = {
            'target': target_url,
            'final_url': None,
            'tech_stack': [],
            'vulnerabilities': [],
            'headers': {}
        }
        
        try:
            if not self.fetch_target(target_url, result):
                return result
            
            self.detect_tech_stack(result)
            self.test_header_vulns(result)
            self.test_reflected_params(result)
            self.test_form_based_vulns(result)
            
            # Print results for this target
            if result['vulnerabilities']:
                print(f"\n\033[1;32m[✓] {target_url} - {len(result['vulnerabilities'])} vulnerabilities found\033[0m")
            else:
                print(f"\033[1;34m[•] {target_url} - No vulnerabilities found\033[0m")
            
            # Save individual report
            self.save_report(result)
            
        except Exception as e:
            print(f"\033[1;31m[!] Error scanning {target_url}: {str(e)}\033[0m")
        
        return result
    
    def fetch_target(self, target_url, result):
        """Fetch target with anti-bot bypass attempts"""
        try:
            response = self.session.get(
                target_url,
                allow_redirects=True,
                timeout=15,
                verify=False
            )
            result['final_url'] = response.url
            result['headers'] = dict(response.headers)
            result['cookies'] = response.cookies.get_dict()
            result['content'] = response.text
            
            # Handle Cloudflare
            if "cloudflare" in result['headers'].get('server', '').lower() or "just a moment" in response.text.lower():
                print(f"\033[1;33m[!] Cloudflare detected on {target_url}, attempting bypass...\033[0m")
                self.session.headers.update({
                    'User-Agent': random.choice(self.get_user_agents()),
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Cache-Control': 'no-cache'
                })
                response = self.session.get(
                    result['final_url'],
                    params={'bypass': random.randint(1000,9999)},
                    timeout=20
                )
                result['content'] = response.text
                
            result['soup'] = BeautifulSoup(result['content'], 'html.parser')
            return True
        except Exception as e:
            print(f"\033[1;31m[!] Fetch error for {target_url}: {str(e)}\033[0m")
            return False

    def detect_tech_stack(self, result):
        """Detect technologies with version fingerprinting"""
        tech_signatures = {
            'server': {
                'Nginx': r'nginx',
                'Apache': r'Apache',
                'IIS': r'Microsoft-IIS',
                'Cloudflare': r'cloudflare'
            },
            'x-powered-by': {
                'PHP': r'PHP',
                'ASP.NET': r'ASP\.NET',
                'Node.js': r'Node\.js',
                'Express': r'Express'
            },
            'content': {
                'React': r'react',
                'Angular': r'angular',
                'Vue.js': r'vue',
                'jQuery': r'jquery'
            }
        }
        
        # Header-based detection
        for header, value in result['headers'].items():
            for category, signatures in tech_signatures.items():
                for tech, pattern in signatures.items():
                    if re.search(pattern, value, re.IGNORECASE):
                        if tech not in result['tech_stack']:
                            result['tech_stack'].append(tech)
        
        # HTML-based detection
        if 'soup' in result:
            for script in result['soup'].find_all('script'):
                src = script.get('src', '')
                for tech, pattern in tech_signatures['content'].items():
                    if re.search(pattern, src, re.IGNORECASE):
                        if tech not in result['tech_stack']:
                            result['tech_stack'].append(tech)
    
    def test_header_vulns(self, result):
        """Test vulnerabilities from missing headers"""
        header_tests = {
            'Content-Security-Policy': {
                'type': 'Missing CSP',
                'test': self.test_xss_vulnerable,
                'risk': 'Critical'
            },
            'X-Frame-Options': {
                'type': 'Clickjacking',
                'test': self.test_clickjacking,
                'risk': 'Medium'
            },
            'X-Content-Type-Options': {
                'type': 'MIME Sniffing',
                'test': self.test_mime_sniffing,
                'risk': 'Medium'
            },
            'Permissions-Policy': {
                'type': 'Feature Abuse',
                'test': self.test_feature_abuse,
                'risk': 'Medium'
            }
        }
        
        for header, details in header_tests.items():
            if header not in result['headers']:
                test_result = details['test'](result)
                if test_result['vulnerable']:
                    result['vulnerabilities'].append({
                        'type': details['type'],
                        'risk': details['risk'],
                        'evidence': test_result['evidence'],
                        'payload': test_result['payload']
                    })

    def test_reflected_params(self, result):
        """Test all URL parameters for vulnerabilities"""
        parsed = urllib.parse.urlparse(result['final_url'])
        params = urllib.parse.parse_qs(parsed.query)
        
        for param, values in params.items():
            for value in values:
                # Test XSS
                xss_result = self.test_param_xss(result, param, value)
                if xss_result['vulnerable']:
                    result['vulnerabilities'].append({
                        'type': 'XSS',
                        'risk': 'Critical',
                        'evidence': xss_result['evidence'],
                        'payload': xss_result['payload']
                    })
                
                # Test SQLi
                sqli_result = self.test_param_sqli(result, param, value)
                if sqli_result['vulnerable']:
                    result['vulnerabilities'].append({
                        'type': 'SQL Injection',
                        'risk': 'Critical',
                        'evidence': sqli_result['evidence'],
                        'payload': sqli_result['payload']
                    })

    def test_form_based_vulns(self, result):
        """Test all forms for vulnerabilities"""
        if 'soup' not in result:
            return
            
        for form in result['soup'].find_all('form'):
            form_action = form.get('action') or result['final_url']
            method = form.get('method', 'get').lower()
            
            # Prepare form data
            form_data = {}
            for input_tag in form.find_all('input'):
                if input_tag.get('type') in ['text', 'hidden', 'password', 'email', 'search']:
                    name = input_tag.get('name')
                    if name:
                        form_data[name] = input_tag.get('value', '')
            
            # Test each form field
            for field in form_data.keys():
                # Test XSS
                xss_result = self.test_form_xss(result, form_action, method, field, form_data.copy())
                if xss_result['vulnerable']:
                    result['vulnerabilities'].append({
                        'type': 'XSS',
                        'risk': 'Critical',
                        'evidence': xss_result['evidence'],
                        'payload': xss_result['payload']
                    })
                
                # Test SQLi
                sqli_result = self.test_form_sqli(result, form_action, method, field, form_data.copy())
                if sqli_result['vulnerable']:
                    result['vulnerabilities'].append({
                        'type': 'SQL Injection',
                        'risk': 'Critical',
                        'evidence': sqli_result['evidence'],
                        'payload': sqli_result['payload']
                    })
    
    # --------------------------
    # Vulnerability Test Methods
    # --------------------------
    
    def test_xss_vulnerable(self, result):
        """Verify if XSS is possible due to missing CSP"""
        test_url = result['final_url'] + f"?test_xss={urllib.parse.quote('<script>alert(1)</script>')}"
        try:
            response = self.session.get(test_url, verify=False)
            if '<script>alert(1)</script>' in response.text:
                return {
                    'vulnerable': True,
                    'evidence': f"XSS payload reflected at {test_url}",
                    'payload': '<script>alert(1)</script>'
                }
        except:
            pass
        return {'vulnerable': False}
    
    def test_clickjacking(self, result):
        """Verify clickjacking vulnerability"""
        domain = urllib.parse.urlparse(result['final_url']).netloc
        filename = f"clickjack_{domain}.html"
        
        test_html = f"""
        <html>
        <head><title>Clickjacking Test: {domain}</title></head>
        <body>
        <h1>Clickjacking Test for {domain}</h1>
        <iframe src="{result['final_url']}" style="opacity:0.3;border:2px dashed red;position:fixed;top:0;left:0;width:100%;height:100%"></iframe>
        </body></html>
        """
        
        with open(filename, 'w') as f:
            f.write(test_html)
        
        return {
            'vulnerable': True,
            'evidence': f"Clickjacking PoC saved to {filename}",
            'payload': '<iframe> embedding'
        }
    
    def test_mime_sniffing(self, result):
        """Test MIME sniffing vulnerability"""
        domain = urllib.parse.urlparse(result['final_url']).netloc
        filename = f"mime_test_{domain}.gif"
        test_content = "GIF89a/*<script>alert('MIME_Sniffing')</script>*/"
        
        with open(filename, 'w') as f:
            f.write(test_content)
        
        return {
            'vulnerable': True,
            'evidence': f"MIME sniffing test file created: {filename}",
            'payload': test_content
        }
    
    def test_feature_abuse(self, result):
        """Test browser feature abuse vulnerability"""
        domain = urllib.parse.urlparse(result['final_url']).netloc
        filename = f"feature_test_{domain}.html"
        
        test_html = f"""
        <html>
        <head>
            <title>Feature Abuse Test: {domain}</title>
            <script>
            function testFeatures() {{
                const results = {{}};
                
                // Test geolocation
                if (navigator.geolocation) {{
                    navigator.geolocation.getCurrentPosition(
                        pos => results.geolocation = `${{pos.coords.latitude}},${{pos.coords.longitude}}`,
                        err => results.geolocation = err.message
                    );
                }}
                
                // Test camera access
                if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {{
                    navigator.mediaDevices.getUserMedia({{ video: true }})
                        .then(stream => {{ 
                            results.camera = "Accessible"; 
                            stream.getTracks().forEach(track => track.stop());
                        }})
                        .catch(err => results.camera = err.message);
                }}
                
                // Show results after 3 seconds
                setTimeout(() => {{
                    document.getElementById('results').innerText = JSON.stringify(results, null, 2);
                }}, 3000);
            }}
            </script>
        </head>
        <body onload="testFeatures()">
            <h1>Feature Abuse Test</h1>
            <pre id="results">Testing browser features...</pre>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(test_html)
        
        return {
            'vulnerable': True,
            'evidence': f"Feature abuse test saved to {filename}",
            'payload': "Browser feature access"
        }
    
    def test_param_xss(self, result, param, original_value):
        """Test XSS in URL parameter with multiple payloads"""
        for payload in self.vuln_payloads['xss']:
            try:
                # Handle URLs with and without existing query parameters
                if '?' in result['final_url']:
                    test_url = result['final_url'].replace(
                        f"{param}={original_value}",
                        f"{param}={payload['encoded']}"
                    )
                else:
                    test_url = f"{result['final_url']}?{param}={payload['encoded']}"
                
                response = self.session.get(test_url, verify=False)
                
                # Check if payload appears in response
                if payload['check_string'] in response.text:
                    return {
                        'vulnerable': True,
                        'evidence': f"XSS payload reflected in {param} parameter",
                        'payload': payload['raw']
                    }
            except:
                continue
        return {'vulnerable': False}
    
    def test_form_xss(self, result, action, method, field, form_data):
        """Test XSS in form field with multiple payloads"""
        for payload in self.vuln_payloads['xss']:
            try:
                form_data[field] = payload['raw']
                
                if method == 'post':
                    response = self.session.post(action, data=form_data, verify=False)
                else:
                    response = self.session.get(action, params=form_data, verify=False)
                
                if payload['check_string'] in response.text:
                    return {
                        'vulnerable': True,
                        'evidence': f"XSS payload reflected in {field} form field",
                        'payload': payload['raw']
                    }
            except:
                continue
        return {'vulnerable': False}
    
    def test_param_sqli(self, result, param, original_value):
        """Test SQLi in URL parameter"""
        for payload in self.vuln_payloads['sqli']:
            try:
                # Handle URLs with and without existing query parameters
                if '?' in result['final_url']:
                    test_url = result['final_url'].replace(
                        f"{param}={original_value}",
                        f"{param}={payload['encoded']}"
                    )
                else:
                    test_url = f"{result['final_url']}?{param}={payload['encoded']}"
                
                response = self.session.get(test_url, verify=False)
                
                if payload['error_indicator'] in response.text:
                    return {
                        'vulnerable': True,
                        'evidence': f"SQLi error in response from {param} parameter",
                        'payload': payload['raw']
                    }
            except:
                continue
        return {'vulnerable': False}
    
    def test_form_sqli(self, result, action, method, field, form_data):
        """Test SQLi in form field"""
        for payload in self.vuln_payloads['sqli']:
            try:
                form_data[field] = payload['raw']
                
                if method == 'post':
                    response = self.session.post(action, data=form_data, verify=False)
                else:
                    response = self.session.get(action, params=form_data, verify=False)
                
                if payload['error_indicator'] in response.text:
                    return {
                        'vulnerable': True,
                        'evidence': f"SQLi error in response from {field} form field",
                        'payload': payload['raw']
                    }
            except:
                continue
        return {'vulnerable': False}
    
    # --------------------------
    # Payload Generators
    # --------------------------
    
    def generate_xss_payloads(self):
        """Generate XSS payloads with various encodings"""
        payloads = []
        base_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '" onmouseover=alert(1) x="',
            "' onfocus=alert(1) autofocus='",
            'javascript:alert(1)'
        ]
        
        for payload in base_payloads:
            # URL encoding
            payloads.append({
                'raw': payload,
                'encoded': urllib.parse.quote(payload),
                'check_string': payload
            })
            
            # Double encoding
            double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
            payloads.append({
                'raw': payload,
                'encoded': double_encoded,
                'check_string': payload
            })
            
            # HTML entity encoding
            entity_encoded = html.escape(payload)
            payloads.append({
                'raw': payload,
                'encoded': entity_encoded,
                'check_string': payload
            })
        
        return payloads
    
    def generate_sqli_payloads(self):
        """Generate SQLi payloads for various databases"""
        payloads = []
        base_payloads = [
            {"payload": "' OR '1'='1", "error": "SQL syntax"},
            {"payload": "' OR SLEEP(5)-- -", "error": "sleep"},
            {"payload": "' UNION SELECT NULL,@@version-- -", "error": "@@version"},
            {"payload": "1 AND (SELECT * FROM (SELECT(SLEEP(5)))", "error": "sleep"}
        ]
        
        for item in base_payloads:
            payload = item['payload']
            payloads.append({
                'raw': payload,
                'encoded': urllib.parse.quote(payload),
                'error_indicator': item['error']
            })
            
            # Double encoding
            payloads.append({
                'raw': payload,
                'encoded': urllib.parse.quote(urllib.parse.quote(payload)),
                'error_indicator': item['error']
            })
        
        return payloads
    
    # --------------------------
    # Utility Methods
    # --------------------------
    
    def get_user_agents(self):
        """Return list of user agents for bypassing WAF"""
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
            'curl/8.6.0',
            'SecurityScanner/1.0 (+https://github.com/kcoof)'
        ]
    
    def save_report(self, result):
        """Save individual report to file"""
        if not result['vulnerabilities']:
            return
            
        domain = urllib.parse.urlparse(result['target']).netloc
        filename = f"scan_report_{domain}.json"
        
        report = {
            'scan_date': datetime.now().isoformat(),
            'target': result['target'],
            'final_url': result['final_url'],
            'tech_stack': result['tech_stack'],
            'vulnerabilities': result['vulnerabilities'],
            'headers': result['headers']
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
    
    def generate_summary_report(self):
        """Generate final summary report"""
        elapsed = time.time() - self.scan_stats['start_time']
        
        print("\n\033[1;35m" + "=" * 60)
        print(" SCAN SUMMARY")
        print("=" * 60 + "\033[0m")
        print(f" \033[1;36m• Targets Scanned: {self.scan_stats['total_targets']}")
        print(f" \033[1;32m• Vulnerable Targets: {self.scan_stats['vulnerable_targets']}")
        print(f" \033[1;31m• Total Vulnerabilities: {self.scan_stats['total_vulns']}")
        print(f" \033[1;34m• Time Elapsed: {elapsed:.2f} seconds\033[0m")
        print("\033[1;35m" + "=" * 60 + "\033[0m")
        
        # Save summary to file
        with open('scan_summary.txt', 'w') as f:
            f.write(f"Security Scan Summary\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Targets Scanned: {self.scan_stats['total_targets']}\n")
            f.write(f"Vulnerable Targets: {self.scan_stats['vulnerable_targets']}\n")
            f.write(f"Total Vulnerabilities: {self.scan_stats['total_vulns']}\n")
            f.write(f"Time Elapsed: {elapsed:.2f} seconds\n")
        
        print("\n\033[1;32mScan completed. Summary saved to scan_summary.txt\033[0m")

def main():
    parser = argparse.ArgumentParser(description='Advanced Security Scanner by kcoof')
    parser.add_argument('target', help='Single URL or file containing list of URLs')
    parser.add_argument('--output', '-o', help='Output directory for reports', default='reports')
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    os.chdir(args.output)
    
    scanner = SecurityScanner()
    scanner.print_banner()
    
    targets = []
    
    # Check if target is a file
    if os.path.isfile(args.target):
        with open(args.target, 'r') as f:
            targets = [line.strip() for line in f.readlines() if line.strip()]
    else:
        targets = [args.target]
    
    # Normalize targets - ensure they have a scheme
    normalized_targets = []
    for target in targets:
        if not target.startswith(('http://', 'https://')):
            normalized_targets.append('https://' + target)
        else:
            normalized_targets.append(target)
    
    scanner.scan_targets(normalized_targets)

if __name__ == "__main__":
    main()
