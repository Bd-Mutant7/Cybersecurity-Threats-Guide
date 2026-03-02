#!/usr/bin/env python3
"""
SSL Strip Detector

This script detects SSL stripping attacks by monitoring network traffic for
HTTPS downgrade attempts, certificate anomalies, and suspicious HTTP activity.
"""

import scapy.all as scapy
import threading
import time
import argparse
import os
import sys
import signal
from collections import defaultdict
from datetime import datetime
import json
import re
import socket
import ssl
from urllib.parse import urlparse
from colorama import init, Fore, Style

init(autoreset=True)

class SSLStripDetector:
    def __init__(self, interface="eth0", check_interval=10, timeout=5, log_file="ssl_alerts.log"):
        """
        Initialize SSL Strip Detector
        
        Args:
            interface: Network interface to monitor
            check_interval: Seconds between checks
            timeout: Connection timeout in seconds
            log_file: File to log alerts
        """
        self.interface = interface
        self.check_interval = check_interval
        self.timeout = timeout
        self.log_file = log_file
        
        # Data structures
        self.http_requests = defaultdict(list)  # IP -> list of HTTP requests
        self.https_expected = set()  # Domains that should use HTTPS
        self.suspicious_certs = defaultdict(list)  # IP -> suspicious certificates
        self.redirect_chains = defaultdict(list)  # IP -> redirect chain
        
        # Common HTTPS domains (should be updated)
        self.common_https_domains = [
            'google.com', 'facebook.com', 'twitter.com', 'github.com',
            'amazon.com', 'paypal.com', 'bankofamerica.com', 'chase.com',
            'gmail.com', 'outlook.com', 'yahoo.com', 'linkedin.com',
            'instagram.com', 'reddit.com', 'netflix.com', 'spotify.com'
        ]
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'http_packets': 0,
            'https_packets': 0,
            'suspicious_http': 0,
            'cert_anomalies': 0,
            'alerts_triggered': 0,
            'start_time': time.time()
        }
        
        # Control flags
        self.running = True
        
    def packet_handler(self, packet):
        """Process captured packets"""
        if not self.running:
            return
        
        self.stats['total_packets'] += 1
        
        # Check for TCP packets
        if packet.haslayer(scapy.TCP):
            ip_layer = packet.getlayer(scapy.IP)
            tcp_layer = packet.getlayer(scapy.TCP)
            
            if ip_layer and tcp_layer:
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                dst_port = tcp_layer.dport
                
                # Check for HTTP (port 80)
                if dst_port == 80 and packet.haslayer(scapy.Raw):
                    self.stats['http_packets'] += 1
                    self.analyze_http(packet, src_ip, dst_ip)
                
                # Check for HTTPS (port 443)
                elif dst_port == 443:
                    self.stats['https_packets'] += 1
                    self.analyze_https(packet, src_ip, dst_ip)
                
                # Check for redirects (HTTP 3xx)
                if dst_port == 80 and packet.haslayer(scapy.Raw):
                    self.analyze_redirect(packet, src_ip, dst_ip)
    
    def analyze_http(self, packet, src_ip, dst_ip):
        """Analyze HTTP traffic for suspicious patterns"""
        try:
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            
            # Extract Host header
            host_match = re.search(r'Host: ([^\r\n]+)', payload)
            if host_match:
                host = host_match.group(1).strip()
                
                # Check if this domain should use HTTPS
                for domain in self.common_https_domains:
                    if domain in host:
                        # This is suspicious - sensitive domain using HTTP
                        self.stats['suspicious_http'] += 1
                        
                        alert_data = {
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'host': host,
                            'timestamp': time.time()
                        }
                        
                        self.trigger_alert(
                            "SENSITIVE_HTTP",
                            f"Sensitive domain {host} accessed over HTTP",
                            alert_data
                        )
                        
                        # Store in history
                        self.http_requests[src_ip].append({
                            'host': host,
                            'time': time.time()
                        })
                
                # Check for login forms over HTTP
                if 'password' in payload.lower() or 'login' in payload.lower():
                    self.trigger_alert(
                        "LOGIN_OVER_HTTP",
                        f"Login form detected over HTTP from {src_ip} to {host}",
                        {'src_ip': src_ip, 'host': host}
                    )
        
        except:
            pass
    
    def analyze_https(self, packet, src_ip, dst_ip):
        """Analyze HTTPS traffic for anomalies"""
        try:
            # Check for Server Hello with certificate
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
                
                # Look for TLS handshake
                if len(payload) > 0 and payload[0] == 0x16:  # TLS Handshake
                    # Try to get certificate info (simplified)
                    # In practice, you'd need to parse TLS properly
                    
                    # Check for suspicious certificate indicators
                    if b'self-signed' in payload or b'untrusted' in payload:
                        self.stats['cert_anomalies'] += 1
                        self.trigger_alert(
                            "SUSPICIOUS_CERT",
                            f"Possible self-signed or untrusted certificate detected",
                            {'src_ip': src_ip, 'dst_ip': dst_ip}
                        )
        
        except:
            pass
    
    def analyze_redirect(self, packet, src_ip, dst_ip):
        """Analyze HTTP redirects for SSL stripping"""
        try:
            payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
            
            # Check for 3xx redirects
            if re.search(r'HTTP/1.[01] 30[1237]', payload):
                # Extract Location header
                location_match = re.search(r'Location: (https?://[^\r\n]+)', payload)
                if location_match:
                    location = location_match.group(1)
                    
                    # Check if redirect is to HTTP (possible SSL strip)
                    if location.startswith('http://'):
                        # Extract original request if possible
                        original_host = re.search(r'Host: ([^\r\n]+)', payload)
                        original_host = original_host.group(1) if original_host else 'unknown'
                        
                        self.stats['cert_anomalies'] += 1
                        
                        alert_data = {
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'original_host': original_host,
                            'redirect_to': location
                        }
                        
                        self.trigger_alert(
                            "SSL_STRIP",
                            f"Possible SSL stripping: Redirect to HTTP from {original_host}",
                            alert_data
                        )
                        
                        # Store in redirect chain
                        self.redirect_chains[src_ip].append({
                            'from': original_host,
                            'to': location,
                            'time': time.time()
                        })
        
        except:
            pass
    
    def verify_certificate(self, hostname, port=443):
        """Verify SSL certificate for a hostname"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    from datetime import datetime
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        if expiry < datetime.now():
                            return False, "Certificate expired"
                    
                    # Check if certificate is self-signed (simplified)
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    
                    if issuer == subject:
                        return False, "Self-signed certificate"
                    
                    return True, "Certificate valid"
                    
        except ssl.SSLCertVerificationError as e:
            return False, f"Certificate verification failed: {e}"
        except Exception as e:
            return False, f"Connection failed: {e}"
    
    def check_known_domains(self):
        """Periodically check known domains for HTTPS"""
        while self.running:
            try:
                for domain in self.common_https_domains:
                    # Try HTTPS connection
                    valid, message = self.verify_certificate(domain)
                    
                    if not valid and message != "Connection failed":
                        self.trigger_alert(
                            "DOMAIN_CERT_ISSUE",
                            f"Certificate issue for {domain}: {message}",
                            {'domain': domain, 'message': message}
                        )
                    
                    time.sleep(1)  # Be nice to servers
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error checking domains: {e}{Style.RESET_ALL}")
                time.sleep(self.check_interval)
    
    def analyze_client_behavior(self):
        """Analyze client behavior for SSL strip patterns"""
        while self.running:
            try:
                current_time = time.time()
                
                # Check clients with suspicious HTTP activity
                for ip, requests in list(self.http_requests.items()):
                    # Clean old requests
                    requests = [r for r in requests 
                               if current_time - r['time'] < 300]  # 5 minutes
                    
                    if len(requests) > 10:  # Many HTTP requests to sensitive sites
                        self.trigger_alert(
                            "EXCESSIVE_HTTP",
                            f"Client {ip} making excessive HTTP requests to sensitive sites",
                            {'ip': ip, 'count': len(requests)}
                        )
                    
                    self.http_requests[ip] = requests
                
                # Check redirect chains
                for ip, chains in list(self.redirect_chains.items()):
                    recent_chains = [c for c in chains 
                                    if current_time - c['time'] < 60]  # 1 minute
                    
                    if len(recent_chains) > 5:  # Many redirects
                        self.trigger_alert(
                            "REDIRECT_CHAIN",
                            f"Client {ip} experiencing multiple redirects - possible SSL strip",
                            {'ip': ip, 'count': len(recent_chains)}
                        )
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error in behavior analysis: {e}{Style.RESET_ALL}")
                time.sleep(30)
    
    def trigger_alert(self, alert_type, message, data=None):
        """Trigger security alert"""
        self.stats['alerts_triggered'] += 1
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        alert = {
            'timestamp': timestamp,
            'type': alert_type,
            'message': message,
            'data': data or {}
        }
        
        # Print alert
        print(f"\n{Fore.RED}🚨 SSL ALERT [{timestamp}]{Style.RESET_ALL}")
        print(f"{Fore.RED}   Type: {alert_type}{Style.RESET_ALL}")
        print(f"{Fore.RED}   Message: {message}{Style.RESET_ALL}")
        if data:
            print(f"{Fore.YELLOW}   Data: {json.dumps(data)}{Style.RESET_ALL}")
        
        # Log to file
        with open(self.log_file, 'a') as f:
            f.write(f"[{timestamp}] {alert_type}: {message}\n")
            if data:
                f.write(f"    Data: {json.dumps(data)}\n")
        
        # Save to JSON
        try:
            with open('ssl_alerts.json', 'a') as f:
                f.write(json.dumps(alert) + '\n')
        except:
            pass
    
    def start_monitoring(self):
        """Start SSL strip detection"""
        print(f"\n{Fore.CYAN}🚀 Starting SSL Strip Detector...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}   Interface: {self.interface}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}   Check Interval: {self.check_interval}s{Style.RESET_ALL}")
        
        # Start domain checking thread
        domain_thread = threading.Thread(target=self.check_known_domains)
        domain_thread.daemon = True
        domain_thread.start()
        
        # Start behavior analysis thread
        behavior_thread = threading.Thread(target=self.analyze_client_behavior)
        behavior_thread.daemon = True
        behavior_thread.start()
        
        # Start packet capture
        print(f"{Fore.GREEN}[*] Monitoring for SSL stripping attacks...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}   Press Ctrl+C to stop{Style.RESET_ALL}\n")
        
        try:
            # Capture TCP packets on ports 80 and 443
            scapy.sniff(iface=self.interface, 
                       filter="tcp port 80 or tcp port 443", 
                       prn=self.packet_handler, 
                       store=False)
        except PermissionError:
            print(f"{Fore.RED}[!] Permission denied. Run with sudo.{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
            sys.exit(1)
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        
        # Print statistics
        duration = time.time() - self.stats['start_time']
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 DETECTOR STATISTICS{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"  Runtime: {duration:.2f} seconds")
        print(f"  Total Packets: {self.stats['total_packets']}")
        print(f"  HTTP Packets: {self.stats['http_packets']}")
        print(f"  HTTPS Packets: {self.stats['https_packets']}")
        print(f"  Suspicious HTTP: {self.stats['suspicious_http']}")
        print(f"  Certificate Anomalies: {self.stats['cert_anomalies']}")
        print(f"  Alerts Triggered: {self.stats['alerts_triggered']}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

def signal_handler(sig, frame):
    """Handle Ctrl+C"""
    print(f"\n{Fore.YELLOW}[*] Stopping detector...{Style.RESET_ALL}")
    detector.stop()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='SSL Strip Detector')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface')
    parser.add_argument('-c', '--check-interval', type=int, default=10,
                       help='Seconds between domain checks')
    parser.add_argument('-t', '--timeout', type=int, default=5,
                       help='Connection timeout in seconds')
    parser.add_argument('-l', '--log', default='ssl_alerts.log', help='Log file')
    
    args = parser.parse_args()
    
    print(f"""
    {Fore.CYAN}╔═══════════════════════════════════════╗
    ║       SSL Strip Detector             ║
    ║    Man-in-the-Middle Detection       ║
    ║       FOR EDUCATIONAL USE ONLY       ║
    ╚═══════════════════════════════════════╝{Style.RESET_ALL}
    """)
    
    # Check root privileges
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] This script requires root privileges.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Please run with: sudo python3 ssl_strip_detector.py{Style.RESET_ALL}")
        sys.exit(1)
    
    global detector
    detector = SSLStripDetector(args.interface, args.check_interval, 
                                args.timeout, args.log)
    
    # Set signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start monitoring
    detector.start_monitoring()

if __name__ == "__main__":
    main()
