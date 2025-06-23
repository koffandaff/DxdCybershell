import re
import requests
import whois
import tldextract
from urllib.parse import urlparse, urljoin
import socket
import time
from datetime import datetime
import numpy as np
from bs4 import BeautifulSoup

class URLPhishingDetector:
    def __init__(self):
        # Pre-compile regex patterns for better performance
        self.ip_pattern = re.compile(r'http[s]?://\d+\.\d+\.\d+\.\d+')
        self.hex_pattern = re.compile(r'%[0-9a-fA-F]{2}')
        self.shortener_domains = {
            'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 
            'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee'
        }
        self.suspicious_tlds = {
            'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'pw', 'club', 
            'top', 'site', 'online', 'space'
        }
        self.common_phishing_keywords = {
            'login', 'verify', 'account', 'banking', 'secure', 
            'update', 'confirm', 'service', 'payment', 'alert'
        }
        self.current_year = datetime.now().year

    def check_url_features(self, url):
        """Comprehensive URL feature analysis"""
        report = {}
        
        try:
            # Basic URL features
            report['url_length'] = len(url)
            report['is_long_url'] = len(url) > 75
            report['has_at_symbol'] = '@' in url
            report['has_redirect'] = '//' in url.replace('://', '')
            
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            
            # Domain features
            ext = tldextract.extract(url)
            report['domain'] = ext.domain
            report['tld'] = ext.suffix
            report['subdomain'] = ext.subdomain
            
            report['has_ip'] = bool(self.ip_pattern.match(url))
            report['has_hyphens'] = '-' in domain
            report['hyphen_count'] = domain.count('-')
            report['has_many_hyphens'] = domain.count('-') > 3
            
            # Subdomain analysis
            subdomain_parts = ext.subdomain.split('.') if ext.subdomain else []
            report['subdomain_depth'] = len(subdomain_parts)
            report['is_deep_subdomain'] = report['subdomain_depth'] > 2
            report['has_suspicious_subdomain'] = any(
                part in self.common_phishing_keywords for part in subdomain_parts
            )
            
            # TLD analysis
            report['is_suspicious_tld'] = ext.suffix.split('.')[-1] in self.suspicious_tlds
            report['is_shortener'] = any(
                shortener in domain for shortener in self.shortener_domains
            )
            
            # Path analysis
            report['path_length'] = len(path)
            report['has_hex_encoding'] = bool(self.hex_pattern.search(url))
            report['has_phishing_keywords'] = any(
                kw in url.lower() for kw in self.common_phishing_keywords
            )
            report['has_double_extension'] = re.search(r'\.\w+\.\w+$', path) is not None
            
            # WHOIS information
            report.update(self.get_whois_info(domain))
            
            # Content analysis (if we can fetch the page)
            report.update(self.analyze_page_content(url))
            
            # HTTPS and certificate info
            report.update(self.check_ssl(url))
            
        except Exception as e:
            report['error'] = str(e)
            
        return report
    
    def get_whois_info(self, domain):
        """Retrieve WHOIS information with better error handling"""
        whois_info = {
            'domain_age_years': -1,
            'is_new_domain': True,
            'whois_registrar': None,
            'whois_country': None
        }
        
        try:
            w = whois.whois(domain)
            
            # Handle different whois response formats
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = min(creation_date)
                
            if creation_date:
                if isinstance(creation_date, str):
                    try:
                        creation_date = datetime.strptime(creation_date.split(' ')[0], '%Y-%m-%d')
                    except:
                        creation_date = datetime.strptime(creation_date.split('T')[0], '%Y-%m-%d')
                
                whois_info['domain_age_years'] = self.current_year - creation_date.year
                whois_info['is_new_domain'] = whois_info['domain_age_years'] < 1
                
            whois_info['whois_registrar'] = w.registrar if w.registrar else None
            whois_info['whois_country'] = w.country if w.country else None
            
        except Exception:
            pass
            
        return whois_info
    
    def check_ssl(self, url):
        """Check SSL/TLS features"""
        ssl_info = {
            'has_ssl': False,
            'is_valid_ssl': False,
            'is_https': False
        }
        
        try:
            parsed = urlparse(url)
            ssl_info['is_https'] = parsed.scheme == 'https'
            
            if ssl_info['is_https']:
                import ssl
                from socket import create_connection
                from OpenSSL import SSL
                
                hostname = parsed.netloc
                port = 443
                
                # Create a socket and connect to the server
                sock = create_connection((hostname, port))
                context = SSL.Context(SSL.SSLv23_METHOD)
                
                # Set up SSL connection
                ssl_sock = SSL.Connection(context, sock)
                ssl_sock.set_connect_state()
                ssl_sock.set_tlsext_host_name(hostname.encode())
                ssl_sock.do_handshake()
                
                ssl_info['has_ssl'] = True
                
                # Verify certificate
                cert = ssl_sock.get_peer_certificate()
                not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                ssl_info['is_valid_ssl'] = not_after > datetime.now()
                
                # Check certificate subject
                subject = cert.get_subject()
                ssl_info['cert_organization'] = subject.organizationName if subject.organizationName else None
                
                ssl_sock.close()
                sock.close()
                
        except Exception:
            pass
            
        return ssl_info
    
    def analyze_page_content(self, url):
        """Analyze page content if accessible"""
        content_info = {
            'has_login_form': False,
            'has_external_resources': False,
            'external_domain_mismatch': False,
            'page_title': None,
            'meta_description': None
        }
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            final_url = response.url
            
            # Check if redirected
            content_info['was_redirected'] = final_url != url
            
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for login forms
            content_info['has_login_form'] = bool(soup.find('input', {'type': 'password'}))
            
            # Get page title
            title = soup.find('title')
            content_info['page_title'] = title.text if title else None
            
            # Get meta description
            meta = soup.find('meta', attrs={'name': 'description'})
            content_info['meta_description'] = meta['content'] if meta else None
            
            # Check for external resources
            domain = urlparse(final_url).netloc
            external_resources = 0
            
            for tag in soup.find_all(['img', 'script', 'link', 'iframe']):
                src = tag.get('src') or tag.get('href')
                if src and not src.startswith(('data:', 'about:')):
                    res_domain = urlparse(src).netloc
                    if res_domain and res_domain != domain:
                        external_resources += 1
            
            content_info['external_resources_count'] = external_resources
            content_info['has_external_resources'] = external_resources > 3
            
        except Exception:
            pass
            
        return content_info
    
    def classify(self, report):
        """Classification with weighted scoring"""
        weights = {
            'is_long_url': 1,
            'has_at_symbol': 2,
            'has_ip': 3,
            'has_many_hyphens': 1,
            'is_deep_subdomain': 2,
            'is_new_domain': 2,
            'is_suspicious_tld': 2,
            'is_shortener': 2,
            'has_hex_encoding': 1,
            'has_phishing_keywords': 1,
            'has_double_extension': 2,
            'has_suspicious_subdomain': 2,
            'was_redirected': 1,
            'has_login_form': 1,
            'has_external_resources': 1,
            'external_domain_mismatch': 2,
            'is_valid_ssl': -2,  # Negative weight for positive indicators
            'domain_age_years': -0.1  # Older domains are safer
        }
        
        # Calculate weighted score
        score = 0
        for feature, weight in weights.items():
            if feature in report:
                value = report[feature]
                if isinstance(value, bool):
                    score += weight if value else 0
                elif isinstance(value, (int, float)):
                    # For numeric values, multiply by weight
                    score += value * weight
        
        # Normalize score based on possible max
        max_possible = sum(abs(w) for w in weights.values())
        normalized_score = score / max_possible
        
        # Determine classification
        if normalized_score > 0.3:
            return "Phishing", normalized_score
        elif normalized_score > 0.15:
            return "Suspicious", normalized_score
        else:
            return "Safe", normalized_score

def main():
    detector = URLPhishingDetector()
    
    print("=== URL Phishing Detector ===")
    url = input("Enter URL to analyze: ").strip()
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    print("\n[+] Analyzing URL...")
    start_time = time.time()
    
    report = detector.check_url_features(url)
    classification, confidence = detector.classify(report)
    
    elapsed_time = time.time() - start_time
    
    print("\n[+] Analysis Report:")
    print(f"URL: {url}")
    print(f"Classification: {classification} (confidence: {confidence:.2%})")
    print(f"Analysis time: {elapsed_time:.2f} seconds\n")
    
    print("Key Indicators:")
    print(f"- URL Length: {report.get('url_length', 'N/A')} chars {'(long)' if report.get('is_long_url') else ''}")
    print(f"- Uses IP: {'Yes' if report.get('has_ip') else 'No'}")
    print(f"- Hyphens in domain: {report.get('hyphen_count', 0)} {'(many)' if report.get('has_many_hyphens') else ''}")
    print(f"- Subdomains: {report.get('subdomain_depth', 0)} {'(deep)' if report.get('is_deep_subdomain') else ''}")
    print(f"- Domain Age: {report.get('domain_age_years', 'N/A')} years {'(new)' if report.get('is_new_domain') else ''}")
    print(f"- Suspicious TLD: {'Yes' if report.get('is_suspicious_tld') else 'No'}")
    print(f"- URL Shortener: {'Yes' if report.get('is_shortener') else 'No'}")
    print(f"- HTTPS: {'Yes' if report.get('is_https') else 'No'}")
    print(f"- Valid SSL: {'Yes' if report.get('is_valid_ssl') else 'No'}")
    print(f"- Phishing Keywords: {'Yes' if report.get('has_phishing_keywords') else 'No'}")
    
    if 'error' in report:
        print(f"\n[!] Errors encountered: {report['error']}")

if __name__ == "__main__":
    main()