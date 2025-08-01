#!/usr/bin/env python3

import requests
import json
import os
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init()

# ASCII Art Logo
LOGO = '''
    ███████╗ █████╗ ██╗   ██╗███████╗██████╗ ██╗     ██╗███╗   ██╗██╗   ██╗██╗  ██╗
    ██╔════╝██╔══██╗╚██╗ ██╔╝██╔════╝██╔══██╗██║     ██║████╗  ██║██║   ██║╚██╗██╔╝
    ███████╗███████║ ╚████╔╝ █████╗  ██████╔╝██║     ██║██╔██╗ ██║██║   ██║ ╚███╔╝ 
    ╚════██║██╔══██║  ╚██╔╝  ██╔══╝  ██╔══██╗██║     ██║██║╚██╗██║██║   ██║ ██╔██╗ 
    ███████║██║  ██║   ██║   ███████╗██║  ██║███████╗██║██║ ╚████║╚██████╔╝██╔╝ ██╗
    ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
                                                        By: SayerLinux@gmail.com
'''

class Attack:
    def __init__(self, target_url):
        self.target_url = target_url
        self.discovered_paths = set()
        self.cdn_info = {}
        self.vulnerable_endpoints = []
        self.results = {
            'target': target_url,
            'discovered_paths': [],
            'cdn_analysis': {},
            'vulnerable_endpoints': [],
            'source_maps': [],
            'unprotected_apis': [],
            'matomo_analysis': None
        }

    def scan_directory_traversal(self):
        common_paths = [
            '../', '../../', '../../../',
            '%2e%2e%2f', '%252e%252e%252f',
            '..\\', '..%5c', '%2e%2e%5c'
        ]
        
        for path in common_paths:
            test_url = urljoin(self.target_url, path)
            try:
                response = requests.get(test_url, allow_redirects=False)
                if response.status_code == 200:
                    self.discovered_paths.add(test_url)
                    print(f"{Fore.GREEN}[+] Directory Traversal Found: {test_url}{Style.RESET_ALL}")
            except:
                continue

    def find_source_maps(self, js_content, js_url):
        sourcemap_pattern = r'//[#@]\s*sourceMappingURL=(.+\.map)'
        matches = re.findall(sourcemap_pattern, js_content)
        
        for map_path in matches:
            map_url = urljoin(js_url, map_path)
            try:
                response = requests.get(map_url)
                if response.status_code == 200:
                    self.results['source_maps'].append({
                        'js_file': js_url,
                        'map_file': map_url
                    })
                    print(f"{Fore.YELLOW}[!] Source Map Found: {map_url}{Style.RESET_ALL}")
            except:
                continue

    def check_xss_csrf(self, url):
        xss_payloads = ['<script>alert(1)</script>', '"><script>alert(1)</script>']
        
        for payload in xss_payloads:
            try:
                response = requests.get(f"{url}?test={payload}")
                if payload in response.text:
                    self.vulnerable_endpoints.append({
                        'url': url,
                        'type': 'XSS',
                        'payload': payload
                    })
                    print(f"{Fore.RED}[!] XSS Vulnerability Found: {url}{Style.RESET_ALL}")
            except:
                continue

        # Check for CSRF
        try:
            response = requests.get(url)
            if 'csrf' not in response.cookies.keys() and 'CSRF' not in response.headers:
                self.vulnerable_endpoints.append({
                    'url': url,
                    'type': 'CSRF',
                    'details': 'No CSRF protection detected'
                })
                print(f"{Fore.RED}[!] Potential CSRF Vulnerability: {url}{Style.RESET_ALL}")
        except:
            pass

    def analyze_cdn(self):
        try:
            response = requests.get(self.target_url)
            headers = response.headers
            
            cdn_headers = ['x-cdn', 'x-fastly', 'x-cloudfront', 'cf-ray', 'server']
            for header in cdn_headers:
                if header in headers:
                    self.cdn_info[header] = headers[header]
                    
            if self.cdn_info:
                print(f"{Fore.BLUE}[+] CDN Information Found:{Style.RESET_ALL}")
                for k, v in self.cdn_info.items():
                    print(f"    {k}: {v}")
        except:
            print(f"{Fore.RED}[-] Failed to analyze CDN{Style.RESET_ALL}")

    def analyze_matomo(self, js_url):
        try:
            response = requests.get(js_url)
            if response.status_code == 200:
                js_content = response.text
                
                # تحليل إعدادات Matomo
                matomo_settings = {
                    'siteId': re.findall(r'setSiteId["\(]*(\d+)', js_content),
                    'trackerUrl': re.findall(r'setTrackerUrl["\(]*([^"\)]+)', js_content),
                    'version': None,  # سيتم تحديثه لاحقاً
                    'sensitive_endpoints': [],
                    'vulnerabilities': []
                }
                
                # محاولة استخراج الإصدار
                try:
                    version_url = urljoin(js_url, '../version.php')
                    version_response = requests.get(version_url)
                    if version_response.status_code == 200:
                        matomo_settings['version'] = version_response.text.strip()
                except:
                    pass
                
                # فحص الروابط الحساسة
                sensitive_paths = [
                    '/index.php?module=API',
                    '/index.php?module=Login',
                    '/index.php?module=CoreAdminHome',
                    '/index.php?module=UsersManager',
                    '/config/config.ini.php',
                    '/tmp/',
                    '/console'
                ]
                
                base_url = '/'.join(js_url.split('/')[:-2])  # استخراج URL الأساسي
                for path in sensitive_paths:
                    try:
                        test_url = urljoin(base_url, path)
                        response = requests.get(test_url)
                        if response.status_code != 404:
                            matomo_settings['sensitive_endpoints'].append({
                                'url': test_url,
                                'status_code': response.status_code
                            })
                    except:
                        continue
                
                # فحص الثغرات المعروفة
                if matomo_settings['version']:
                    version = matomo_settings['version']
                    known_vulnerabilities = {
                        '4.15.3': {
                            'cve': 'CVE-2023-6923',
                            'description': 'Reflected XSS via idsite parameter',
                            'severity': 'High'
                        },
                        '3.9.1': {
                            'cve': 'CVE-2019-XXXX',
                            'description': 'Path disclosure vulnerability',
                            'severity': 'Low'
                        }
                    }
                    
                    for vuln_version, vuln_info in known_vulnerabilities.items():
                        if version.startswith(vuln_version):
                            matomo_settings['vulnerabilities'].append(vuln_info)
                
                if matomo_settings['siteId'] or matomo_settings['trackerUrl']:
                    print(f"\n{Fore.YELLOW}[!] Matomo Analytics Configuration Found: {js_url}{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}[*] Configuration Details:{Style.RESET_ALL}")
                    
                    # عرض معلومات الإصدار
                    if matomo_settings['version']:
                        print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Version: {matomo_settings['version']}")
                    
                    # عرض الإعدادات الأساسية
                    if matomo_settings['siteId']:
                        print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Site ID: {matomo_settings['siteId'][0]}")
                    if matomo_settings['trackerUrl']:
                        print(f"    {Fore.GREEN}✓{Style.RESET_ALL} Tracker URL: {matomo_settings['trackerUrl'][0]}")
                    
                    # عرض الروابط الحساسة
                    if matomo_settings['sensitive_endpoints']:
                        print(f"\n    {Fore.RED}[!] Sensitive Endpoints Found:{Style.RESET_ALL}")
                        for endpoint in matomo_settings['sensitive_endpoints']:
                            print(f"    {Fore.RED}→{Style.RESET_ALL} {endpoint['url']} (Status: {endpoint['status_code']})")
                    
                    # عرض الثغرات المكتشفة
                    if matomo_settings['vulnerabilities']:
                        print(f"\n    {Fore.RED}[!] Known Vulnerabilities Found:{Style.RESET_ALL}")
                        for vuln in matomo_settings['vulnerabilities']:
                            print(f"    {Fore.RED}→{Style.RESET_ALL} {vuln['cve']}: {vuln['description']} (Severity: {vuln['severity']})")
                    
                    self.results['matomo_analysis'] = matomo_settings
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Error analyzing Matomo: {str(e)}{Style.RESET_ALL}")

    def crawl_smart(self, max_depth=3):
        visited = set()
        to_visit = [(self.target_url, 0)]
        
        while to_visit:
            url, depth = to_visit.pop(0)
            if depth > max_depth or url in visited:
                continue
                
            visited.add(url)
            try:
                response = requests.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all links
                for link in soup.find_all(['a', 'script', 'link']):
                    href = link.get('href') or link.get('src')
                    if href:
                        full_url = urljoin(url, href)
                        if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                            to_visit.append((full_url, depth + 1))
                            self.discovered_paths.add(full_url)
                            
                            # Check for JavaScript files
                            if full_url.endswith('.js'):
                                self.find_source_maps(response.text, full_url)
                                if 'matomo' in full_url.lower():
                                    self.analyze_matomo(full_url)
                            
                            # Security checks
                            self.check_xss_csrf(full_url)
                            
            except Exception as e:
                print(f"{Fore.RED}[-] Error crawling {url}: {str(e)}{Style.RESET_ALL}")

    def export_results(self):
        self.results['discovered_paths'] = list(self.discovered_paths)
        self.results['cdn_analysis'] = self.cdn_info
        self.results['vulnerable_endpoints'] = self.vulnerable_endpoints
        
        with open('attack_results.json', 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"{Fore.GREEN}[+] Results exported to attack_results.json{Style.RESET_ALL}")

    def run(self):
        print(Fore.CYAN + LOGO + Style.RESET_ALL)
        print(f"{Fore.YELLOW}[*] Starting Attack on {self.target_url}{Style.RESET_ALL}")
        
        self.analyze_cdn()
        self.scan_directory_traversal()
        self.crawl_smart()
        self.export_results()
        
        print(f"{Fore.GREEN}[+] Attack completed! Check attack_results.json for detailed results{Style.RESET_ALL}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Attack - Advanced Web Security Analysis Tool')
    parser.add_argument('url', help='Target URL to analyze')
    args = parser.parse_args()
    
    attack = Attack(args.url)
    attack.run()