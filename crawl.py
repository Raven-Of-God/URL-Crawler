#!/usr/bin/env python3
"""
 URL CRAWLER
==================
Comprehensive URL crawler with banner extraction and parameter analysis
"""

import requests
import urllib.parse
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
import re
import json
import time
import random
from collections import defaultdict
import argparse
import sys
from datetime import datetime
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import platform

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    GRAY = '\033[90m'

class Crawler:
    def __init__(self, max_threads=10, delay=1, max_depth=3):
        self.max_threads = max_threads
        self.delay = delay
        self.max_depth = max_depth
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        self.results = []
        self.crawled_urls = set()
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'start_time': None,
            'end_time': None,
            'total_parameters_found': 0,
            'total_forms_found': 0,
            'total_links_found': 0
        }
        self.banner_art = f"""
{Colors.CYAN}__________                               ________           .___
\\______   \\_____ ___  __ ____   ____    /  _____/  ____   __| _/
 |       _/\\__  \\\\  \\/ // __ \\ /    \\  /   \\  ___ /  _ \\ / __ | 
 |    |   \\ / __ \\\\   /\\  ___/|   |  \\ \\    \\_\\  (  <_> ) /_/ | 
 |____|_  /(____  /\\_/  \\___  >___|  /  \\______  /\\____/\\____ | 
        \\/      \\/          \\/     \\/          \\/            \\/ {Colors.END}
        """
    
    def print_banner(self):
        """Print the ASCII art banner with colors"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print(self.banner_art)
        print(f"{Colors.BOLD}{Colors.GREEN} URL CRAWLER - Deep Web Crawler{Colors.END}")
        print(f"{Colors.YELLOW}{'=' * 60}{Colors.END}")
        print(f"{Colors.CYAN}Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}")
        print(f"{Colors.CYAN}Platform: {platform.system()} {platform.release()}{Colors.END}")
        print(f"{Colors.YELLOW}{'=' * 60}{Colors.END}")
    
    def print_colored(self, message, color=Colors.WHITE, bold=False):
        """Print colored message"""
        style = Colors.BOLD if bold else ""
        print(f"{style}{color}{message}{Colors.END}")
    
    def print_detailed_info(self, title, data, color=Colors.CYAN):
        """Print detailed information in a formatted way"""
        print(f"\n{Colors.YELLOW}{'─' * 50}{Colors.END}")
        self.print_colored(f"🔍 {title}", color, bold=True)
        print(f"{Colors.YELLOW}{'─' * 50}{Colors.END}")
        
        if isinstance(data, dict):
            for key, value in data.items():
                if value:  # Only show non-empty values
                    if isinstance(value, list):
                        self.print_colored(f"  📋 {key}:", Colors.BLUE)
                        for item in value[:5]:  # Show first 5 items
                            print(f"    • {item}")
                        if len(value) > 5:
                            print(f"    ... and {len(value) - 5} more")
                    else:
                        self.print_colored(f"  📋 {key}: {value}", Colors.BLUE)
        elif isinstance(data, list):
            for item in data[:10]:  # Show first 10 items
                print(f"  • {item}")
            if len(data) > 10:
                print(f"  ... and {len(data) - 10} more")
        else:
            print(f"  {data}")
    
    def get_urls_interactively(self):
        """Get URLs from user interactively"""
        urls = []
        print(f"\n{Colors.YELLOW}[?] Enter URLs to crawl (one per line, press Enter twice when done):{Colors.END}")
        print(f"{Colors.GRAY}[?] Example: https://example.com{Colors.END}")
        print(f"{Colors.GRAY}[!] IMPORTANT: URLs must start with http:// or https://{Colors.END}")
        print(f"{Colors.GRAY}[?] Press Enter twice to start crawling{Colors.END}\n")
        
        while True:
            try:
                url = input(f"{Colors.CYAN}URL: {Colors.END}").strip()
                if not url:  # Empty line means done
                    if urls:  # If we have URLs, break
                        break
                    else:  # If no URLs yet, ask again
                        self.print_colored("[!] Please enter at least one URL", Colors.RED)
                        continue
                
                # Validate URL format
                if not url.startswith(('http://', 'https://')):
                    self.print_colored(f"[!] URL must start with http:// or https:// - Adding https:// to: {url}", Colors.YELLOW)
                    url = 'https://' + url
                
                try:
                    parsed = urlparse(url)
                    if not parsed.netloc:
                        self.print_colored(f"[!] Invalid URL format: {url}", Colors.RED)
                        continue
                except Exception:
                    self.print_colored(f"[!] Invalid URL format: {url}", Colors.RED)
                    continue
                
                urls.append(url)
                self.print_colored(f"[+] Added: {url}", Colors.GREEN)
                
            except KeyboardInterrupt:
                print(f"\n{Colors.RED}[!] Cancelled by user{Colors.END}")
                sys.exit(1)
        
        return urls
    
    def get_crawler_settings(self):
        """Get crawler settings interactively"""
        print(f"\n{Colors.YELLOW}[?] Crawler Settings:{Colors.END}")
        
        # Threads
        while True:
            try:
                threads_input = input(f"{Colors.CYAN}Number of threads (default: 10): {Colors.END}").strip()
                if not threads_input:
                    threads = 10
                    break
                threads = int(threads_input)
                if threads > 0 and threads <= 100:
                    break
                else:
                    self.print_colored("[!] Threads must be between 1 and 100", Colors.RED)
            except ValueError:
                self.print_colored("[!] Please enter a valid number", Colors.RED)
        
        # Delay
        while True:
            try:
                delay_input = input(f"{Colors.CYAN}Delay between requests in seconds (default: 1.0): {Colors.END}").strip()
                if not delay_input:
                    delay = 1.0
                    break
                delay = float(delay_input)
                if delay >= 0:
                    break
                else:
                    self.print_colored("[!] Delay must be 0 or greater", Colors.RED)
            except ValueError:
                self.print_colored("[!] Please enter a valid number", Colors.RED)
        
        # Max Depth
        while True:
            try:
                depth_input = input(f"{Colors.CYAN}Max crawl depth (default: 3): {Colors.END}").strip()
                if not depth_input:
                    max_depth = 3
                    break
                max_depth = int(depth_input)
                if max_depth > 0 and max_depth <= 10:
                    break
                else:
                    self.print_colored("[!] Depth must be between 1 and 10", Colors.RED)
            except ValueError:
                self.print_colored("[!] Please enter a valid number", Colors.RED)
        
        return threads, delay, max_depth
    
    def extract_banners(self, url):
        """Extract server banners and headers"""
        banners = {}
        try:
            self.print_colored(f"\n🔍 Extracting banners from: {url}", Colors.CYAN)
            
            # HTTP headers
            response = self.session.get(url, timeout=15, allow_redirects=True)
            banners['http_headers'] = dict(response.headers)
            banners['status_code'] = response.status_code
            banners['final_url'] = response.url
            banners['content_length'] = len(response.content)
            banners['response_time'] = response.elapsed.total_seconds()
            
            # Display basic info
            self.print_colored(f"  📊 Status Code: {response.status_code}", Colors.GREEN if response.status_code == 200 else Colors.YELLOW)
            self.print_colored(f"  ⏱️  Response Time: {response.elapsed.total_seconds():.2f}s", Colors.CYAN)
            self.print_colored(f"  📏 Content Length: {len(response.content):,} bytes", Colors.BLUE)
            self.print_colored(f"  🔗 Final URL: {response.url}", Colors.PURPLE)
            
            # Server banner
            if 'Server' in response.headers:
                banners['server_banner'] = response.headers['Server']
                self.print_colored(f"  🖥️  Server: {response.headers['Server']}", Colors.GREEN)
            
            # Security headers
            security_headers = ['X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version', 
                              'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
                              'Strict-Transport-Security', 'Content-Security-Policy']
            banners['security_headers'] = {k: response.headers.get(k) for k in security_headers if k in response.headers}
            
            if banners['security_headers']:
                self.print_colored("  🔒 Security Headers Found:", Colors.YELLOW)
                for header, value in banners['security_headers'].items():
                    self.print_colored(f"    • {header}: {value}", Colors.GRAY)
            
            # Technology detection
            tech_stack = []
            if 'X-Powered-By' in response.headers:
                tech_stack.append(response.headers['X-Powered-By'])
            if 'Server' in response.headers:
                tech_stack.append(response.headers['Server'])
            
            banners['detected_technologies'] = tech_stack
            
            # Display all headers
            self.print_colored("  📋 All Headers:", Colors.BLUE)
            for header, value in response.headers.items():
                print(f"    • {header}: {value}")
            
        except requests.exceptions.SSLError:
            error_msg = "SSL Certificate Error - Try with http:// instead of https://"
            self.print_colored(f"  ❌ {error_msg}", Colors.RED)
            banners['error'] = error_msg
        except requests.exceptions.ConnectionError:
            error_msg = "Connection Error - Check if URL is accessible"
            self.print_colored(f"  ❌ {error_msg}", Colors.RED)
            banners['error'] = error_msg
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.print_colored(f"  ❌ {error_msg}", Colors.RED)
            banners['error'] = error_msg
        
        return banners
    
    def extract_parameters(self, url):
        """Extract all URL parameters"""
        self.print_colored(f"\n🔍 Analyzing URL parameters: {url}", Colors.CYAN)
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        param_analysis = {
            'base_url': f"{parsed.scheme}://{parsed.netloc}",
            'path': parsed.path,
            'parameters': params,
            'parameter_count': len(params),
            'parameter_types': {},
            'potential_vulnerabilities': [],
            'all_urls_with_params': []
        }
        
        self.print_colored(f"  🔗 Base URL: {param_analysis['base_url']}", Colors.BLUE)
        self.print_colored(f"  📁 Path: {parsed.path}", Colors.BLUE)
        self.print_colored(f"  📊 Parameter Count: {len(params)}", Colors.GREEN)
        
        if not params:
            self.print_colored("  ℹ️  No URL parameters found", Colors.GRAY)
            return param_analysis
        
        # Analyze parameter types and potential vulnerabilities
        for param, values in params.items():
            self.print_colored(f"  📋 Parameter: {param}", Colors.YELLOW)
            self.print_colored(f"    Values: {values}", Colors.GRAY)
            
            param_analysis['parameter_types'][param] = {
                'values': values,
                'count': len(values),
                'patterns': self.analyze_parameter_patterns(values),
                'risk_level': self.assess_parameter_risk(param, values)
            }
            
            risk_level = param_analysis['parameter_types'][param]['risk_level']
            risk_color = Colors.RED if risk_level == 'high' else Colors.YELLOW if risk_level == 'medium' else Colors.GREEN
            self.print_colored(f"    Risk Level: {risk_level.upper()}", risk_color)
            
            # Check for potential vulnerabilities
            if any(vuln in param.lower() for vuln in ['id', 'user', 'admin', 'password', 'token']):
                param_analysis['potential_vulnerabilities'].append({
                    'parameter': param,
                    'type': 'sensitive_parameter',
                    'risk': 'high'
                })
                self.print_colored(f"    ⚠️  POTENTIAL VULNERABILITY: Sensitive parameter detected!", Colors.RED)
        
        return param_analysis
    
    def assess_parameter_risk(self, param, values):
        """Assess risk level of parameter"""
        param_lower = param.lower()
        sensitive_keywords = ['id', 'user', 'admin', 'password', 'token', 'key', 'secret']
        
        if any(keyword in param_lower for keyword in sensitive_keywords):
            return 'high'
        elif any(value.isdigit() for value in values):
            return 'medium'
        else:
            return 'low'
    
    def analyze_parameter_patterns(self, values):
        """Analyze parameter value patterns"""
        patterns = {
            'numeric': 0,
            'alphanumeric': 0,
            'email': 0,
            'date': 0,
            'id_like': 0,
            'hash_like': 0,
            'uuid_like': 0,
            'base64_like': 0
        }
        
        for value in values:
            if value.isdigit():
                patterns['numeric'] += 1
            elif re.match(r'^[a-zA-Z0-9]+$', value):
                patterns['alphanumeric'] += 1
            elif re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
                patterns['email'] += 1
            elif re.match(r'^\d{4}-\d{2}-\d{2}$', value):
                patterns['date'] += 1
            elif re.match(r'^[a-zA-Z0-9_-]+$', value) and len(value) < 20:
                patterns['id_like'] += 1
            elif re.match(r'^[a-fA-F0-9]{32,}$', value):
                patterns['hash_like'] += 1
            elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.IGNORECASE):
                patterns['uuid_like'] += 1
            elif re.match(r'^[A-Za-z0-9+/]{4,}={0,2}$', value):
                patterns['base64_like'] += 1
        
        return patterns
    
    def extract_links(self, url, depth=0):
        """Extract all links from the page with recursive crawling"""
        self.print_colored(f"\n🔍 Extracting links from: {url} (Depth: {depth})", Colors.CYAN)
        
        links = {
            'internal': [],
            'external': [],
            'forms': [],
            'scripts': [],
            'stylesheets': [],
            'images': [],
            'api_endpoints': [],
            'social_media': [],
            'submitted_forms': [],
            'javascript_variables': [],
            'meta_tags': [],
            'comments': []
        }
        
        try:
            response = self.session.get(url, timeout=15)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract all links
            all_links = soup.find_all('a', href=True)
            self.print_colored(f"  🔗 Found {len(all_links)} total links", Colors.BLUE)
            
            for link in all_links:
                href = link['href']
                full_url = urljoin(url, href)
                
                link_data = {
                    'url': full_url,
                    'text': link.get_text(strip=True),
                    'title': link.get('title', ''),
                    'rel': link.get('rel', []),
                    'target': link.get('target', '')
                }
                
                if self.is_internal_link(url, full_url):
                    links['internal'].append(link_data)
                    
                    # Recursive crawling for internal links
                    if depth < self.max_depth and full_url not in self.crawled_urls:
                        self.crawled_urls.add(full_url)
                        self.print_colored(f"    🔄 Recursively crawling: {full_url}", Colors.PURPLE)
                        sub_links = self.extract_links(full_url, depth + 1)
                        # Merge results
                        for key in links:
                            if isinstance(links[key], list) and isinstance(sub_links.get(key, []), list):
                                links[key].extend(sub_links[key])
                else:
                    links['external'].append(link_data)
                
                # Detect API endpoints
                if any(api in full_url.lower() for api in ['/api/', '/rest/', '/v1/', '/v2/', '/v3/', '/graphql']):
                    links['api_endpoints'].append(full_url)
                    self.print_colored(f"    🚀 API Endpoint: {full_url}", Colors.PURPLE)
                
                # Detect social media links
                social_platforms = ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'youtube.com', 'tiktok.com']
                if any(platform in full_url.lower() for platform in social_platforms):
                    links['social_media'].append(full_url)
                    self.print_colored(f"    📱 Social Media: {full_url}", Colors.YELLOW)
            
            # Extract forms with submission testing
            forms = soup.find_all('form')
            self.print_colored(f"  📝 Found {len(forms)} forms", Colors.GREEN)
            
            for i, form in enumerate(forms, 1):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET'),
                    'enctype': form.get('enctype', ''),
                    'inputs': [],
                    'submission_test': {}
                }
                
                self.print_colored(f"    📋 Form {i}: {form_data['method']} -> {form_data['action']}", Colors.CYAN)
                
                # Test form submission
                try:
                    test_data = {}
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        input_data = {
                            'type': input_tag.get('type', 'text'),
                            'name': input_tag.get('name', ''),
                            'id': input_tag.get('id', ''),
                            'value': input_tag.get('value', ''),
                            'required': input_tag.get('required') is not None,
                            'placeholder': input_tag.get('placeholder', ''),
                            'pattern': input_tag.get('pattern', '')
                        }
                        form_data['inputs'].append(input_data)
                        
                        if input_data['name']:
                            self.print_colored(f"      • {input_data['type']}: {input_data['name']}", Colors.GRAY)
                            # Add test data for form submission
                            if input_data['type'] in ['text', 'email', 'password']:
                                test_data[input_data['name']] = 'test_value'
                            elif input_data['type'] == 'number':
                                test_data[input_data['name']] = '123'
                    
                    # Test form submission
                    if test_data and form_data['action']:
                        test_url = urljoin(url, form_data['action'])
                        if form_data['method'].upper() == 'POST':
                            test_response = self.session.post(test_url, data=test_data, timeout=10)
                        else:
                            test_response = self.session.get(test_url, params=test_data, timeout=10)
                        
                        form_data['submission_test'] = {
                            'status_code': test_response.status_code,
                            'response_length': len(test_response.content),
                            'redirect_url': test_response.url
                        }
                        self.print_colored(f"      🧪 Form submission tested - Status: {test_response.status_code}", Colors.YELLOW)
                
                except Exception as e:
                    form_data['submission_test'] = {'error': str(e)}
                    self.print_colored(f"      ❌ Form submission test failed: {e}", Colors.RED)
                
                links['forms'].append(form_data)
            
            # Extract scripts and analyze JavaScript
            scripts = soup.find_all('script')
            self.print_colored(f"  📜 Found {len(scripts)} scripts", Colors.BLUE)
            
            for script in scripts:
                if script.get('src'):
                    script_url = urljoin(url, script['src'])
                    links['scripts'].append(script_url)
                else:
                    # Analyze inline JavaScript
                    script_content = script.string
                    if script_content:
                        # Extract JavaScript variables
                        js_vars = re.findall(r'var\s+(\w+)\s*=', script_content)
                        js_consts = re.findall(r'const\s+(\w+)\s*=', script_content)
                        js_lets = re.findall(r'let\s+(\w+)\s*=', script_content)
                        
                        all_vars = js_vars + js_consts + js_lets
                        if all_vars:
                            links['javascript_variables'].extend(all_vars)
                            self.print_colored(f"    📜 JS Variables found: {all_vars[:5]}", Colors.CYAN)
            
            # Extract stylesheets
            stylesheets = soup.find_all('link', rel='stylesheet')
            self.print_colored(f"  🎨 Found {len(stylesheets)} stylesheets", Colors.BLUE)
            
            for link in stylesheets:
                if link.get('href'):
                    links['stylesheets'].append(urljoin(url, link['href']))
            
            # Extract images
            images = soup.find_all('img', src=True)
            self.print_colored(f"  🖼️  Found {len(images)} images", Colors.BLUE)
            
            for img in images:
                links['images'].append(urljoin(url, img['src']))
            
            # Extract meta tags
            meta_tags = soup.find_all('meta')
            self.print_colored(f"  📋 Found {len(meta_tags)} meta tags", Colors.BLUE)
            
            for meta in meta_tags:
                meta_data = {
                    'name': meta.get('name', ''),
                    'content': meta.get('content', ''),
                    'property': meta.get('property', '')
                }
                if meta_data['name'] or meta_data['property']:
                    links['meta_tags'].append(meta_data)
            
            # Extract HTML comments
            comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
            self.print_colored(f"  💬 Found {len(comments)} HTML comments", Colors.BLUE)
            
            for comment in comments:
                if comment.strip():
                    links['comments'].append(comment.strip())
                    
        except Exception as e:
            error_msg = f"Error extracting links: {str(e)}"
            self.print_colored(f"  ❌ {error_msg}", Colors.RED)
            links['error'] = error_msg
        
        return links
    
    def is_internal_link(self, base_url, link_url):
        """Check if link is internal to the same domain"""
        base_domain = urlparse(base_url).netloc
        link_domain = urlparse(link_url).netloc
        return base_domain == link_domain
    
    def crawl_url(self, url):
        """Comprehensive URL crawling"""
        self.stats['total_requests'] += 1
        self.print_colored(f"\n{'='*60}", Colors.YELLOW)
        self.print_colored(f"🚀 CRAWLING: {url}", Colors.BOLD + Colors.CYAN, bold=True)
        print(f"{Colors.YELLOW}{'='*60}{Colors.END}")
        
        try:
            result = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'banners': self.extract_banners(url),
                'parameters': self.extract_parameters(url),
                'links': self.extract_links(url, depth=0)
            }
            
            # Add summary statistics
            result['summary'] = {
                'total_links': len(result['links']['internal']) + len(result['links']['external']),
                'internal_links': len(result['links']['internal']),
                'external_links': len(result['links']['external']),
                'forms_found': len(result['links']['forms']),
                'scripts_found': len(result['links']['scripts']),
                'stylesheets_found': len(result['links']['stylesheets']),
                'images_found': len(result['links']['images']),
                'api_endpoints_found': len(result['links']['api_endpoints']),
                'social_media_found': len(result['links']['social_media']),
                'javascript_variables_found': len(result['links']['javascript_variables']),
                'meta_tags_found': len(result['links']['meta_tags']),
                'comments_found': len(result['links']['comments']),
                'parameters_found': result['parameters']['parameter_count'],
                'vulnerabilities_found': len(result['parameters']['potential_vulnerabilities'])
            }
            
            # Update global stats
            self.stats['total_parameters_found'] += result['summary']['parameters_found']
            self.stats['total_forms_found'] += result['summary']['forms_found']
            self.stats['total_links_found'] += result['summary']['total_links']
            
            # Display detailed results
            self.print_detailed_info("INTERNAL LINKS", result['links']['internal'][:10], Colors.GREEN)
            self.print_detailed_info("EXTERNAL LINKS", result['links']['external'][:10], Colors.BLUE)
            self.print_detailed_info("API ENDPOINTS", result['links']['api_endpoints'], Colors.PURPLE)
            self.print_detailed_info("SOCIAL MEDIA LINKS", result['links']['social_media'], Colors.YELLOW)
            self.print_detailed_info("SCRIPTS", result['links']['scripts'][:10], Colors.CYAN)
            self.print_detailed_info("STYLESHEETS", result['links']['stylesheets'][:10], Colors.BLUE)
            self.print_detailed_info("JAVASCRIPT VARIABLES", result['links']['javascript_variables'], Colors.PURPLE)
            self.print_detailed_info("META TAGS", result['links']['meta_tags'][:10], Colors.YELLOW)
            self.print_detailed_info("HTML COMMENTS", result['links']['comments'][:5], Colors.GRAY)
            
            self.stats['successful_requests'] += 1
            return result
            
        except Exception as e:
            self.stats['failed_requests'] += 1
            self.print_colored(f"[✗] Error crawling {url}: {e}", Colors.RED)
            return None
    
    def crawl_multiple_urls(self, urls):
        """Crawl multiple URLs with threading"""
        self.print_colored(f"[*] Starting crawl of {len(urls)} URLs with {self.max_threads} threads", Colors.YELLOW, bold=True)
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_url = {executor.submit(self.crawl_url, url): url for url in urls}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                        self.print_colored(f"[✓] Completed: {url}", Colors.GREEN)
                        
                        # Show quick stats
                        summary = result['summary']
                        self.print_colored(f"   ├─ Links: {summary['total_links']} | Forms: {summary['forms_found']} | Scripts: {summary['scripts_found']}", Colors.GRAY)
                        self.print_colored(f"   ├─ Parameters: {summary['parameters_found']} | Vulnerabilities: {summary['vulnerabilities_found']}", Colors.GRAY)
                        self.print_colored(f"   └─ JS Vars: {summary['javascript_variables_found']} | Meta Tags: {summary['meta_tags_found']}", Colors.GRAY)
                    
                    # Add delay between requests
                    time.sleep(self.delay)
                    
                except Exception as e:
                    self.print_colored(f"[✗] Error crawling {url}: {e}", Colors.RED)
    
    def save_results(self, filename=None):
        """Save results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"crawler_results_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        self.print_colored(f"[+] Results saved to: {filename}", Colors.GREEN)
        return filename
    
    def print_summary(self):
        """Print crawl summary with colors"""
        if not self.results:
            self.print_colored("[!] No results to summarize", Colors.RED)
            return
        
        print(f"\n{Colors.YELLOW}{'=' * 60}{Colors.END}")
        self.print_colored("DEEP CRAWL SUMMARY", Colors.BOLD + Colors.CYAN, bold=True)
        print(f"{Colors.YELLOW}{'=' * 60}{Colors.END}")
        
        total_urls = len(self.results)
        total_links = sum(r['summary']['total_links'] for r in self.results)
        total_forms = sum(r['summary']['forms_found'] for r in self.results)
        total_parameters = sum(r['summary']['parameters_found'] for r in self.results)
        total_vulnerabilities = sum(r['summary']['vulnerabilities_found'] for r in self.results)
        total_api_endpoints = sum(r['summary']['api_endpoints_found'] for r in self.results)
        total_js_vars = sum(r['summary']['javascript_variables_found'] for r in self.results)
        total_meta_tags = sum(r['summary']['meta_tags_found'] for r in self.results)
        
        self.print_colored(f"URLs crawled: {total_urls}", Colors.GREEN)
        self.print_colored(f"Total links found: {total_links}", Colors.BLUE)
        self.print_colored(f"Total forms found: {total_forms}", Colors.PURPLE)
        self.print_colored(f"Total parameters found: {total_parameters}", Colors.CYAN)
        self.print_colored(f"Potential vulnerabilities: {total_vulnerabilities}", Colors.RED if total_vulnerabilities > 0 else Colors.GREEN)
        self.print_colored(f"API endpoints found: {total_api_endpoints}", Colors.YELLOW)
        self.print_colored(f"JavaScript variables found: {total_js_vars}", Colors.PURPLE)
        self.print_colored(f"Meta tags found: {total_meta_tags}", Colors.BLUE)
        
        # Show unique domains
        domains = set()
        for result in self.results:
            domain = urlparse(result['url']).netloc
            domains.add(domain)
        
        self.print_colored(f"Unique domains: {len(domains)}", Colors.BLUE)
        
        # Show request statistics
        success_rate = (self.stats['successful_requests'] / self.stats['total_requests']) * 100 if self.stats['total_requests'] > 0 else 0
        self.print_colored(f"Success rate: {success_rate:.1f}%", Colors.GREEN if success_rate > 80 else Colors.YELLOW)
        
        print(f"{Colors.YELLOW}{'=' * 60}{Colors.END}")

def main():
    # Show banner first
    crawler = Crawler()
    crawler.print_banner()
    
    # Get URLs interactively
    urls = crawler.get_urls_interactively()
    
    # Get settings interactively
    threads, delay, max_depth = crawler.get_crawler_settings()
    
    # Update crawler settings
    crawler.max_threads = threads
    crawler.delay = delay
    crawler.max_depth = max_depth
    crawler.stats['start_time'] = datetime.now()
    
    crawler.print_colored(f"\n[*] Starting deep crawl with {threads} threads, {delay}s delay, depth {max_depth}", Colors.YELLOW, bold=True)
    print(f"{Colors.YELLOW}{'=' * 60}{Colors.END}")
    
    # Start crawling
    if len(urls) == 1:
        # Single URL
        result = crawler.crawl_url(urls[0])
        if result:
            crawler.results.append(result)
    else:
        # Multiple URLs
        crawler.crawl_multiple_urls(urls)
    
    # Print summary
    crawler.stats['end_time'] = datetime.now()
    crawler.print_summary()
    
    # Save results
    output_file = crawler.save_results()
    
    # Calculate total time
    if crawler.stats['start_time'] and crawler.stats['end_time']:
        total_time = (crawler.stats['end_time'] - crawler.stats['start_time']).total_seconds()
        crawler.print_colored(f"Total crawl time: {total_time:.2f} seconds", Colors.CYAN)
    
    crawler.print_colored(f"\n[+] Deep crawl completed! Results saved to: {output_file}", Colors.GREEN, bold=True)
    crawler.print_colored(" CRAWLER - Mission Accomplished! 🚀", Colors.BOLD + Colors.GREEN, bold=True)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Crawl interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {e}{Colors.END}")
        sys.exit(1)
