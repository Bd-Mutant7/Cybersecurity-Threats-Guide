#!/usr/bin/env python3
"""
Firewall Configuration for Port Scan Prevention

This script configures firewall rules (iptables/nftables) to prevent
and mitigate port scanning activities.
"""

import subprocess
import argparse
import os
import sys
import time
import re
from datetime import datetime
import json
from colorama import init, Fore, Style

init(autoreset=True)

class FirewallConfig:
    def __init__(self, interface="eth0"):
        """
        Initialize firewall configuration
        
        Args:
            interface: Network interface to protect
        """
        self.interface = interface
        self.rules_applied = []
        self.backup_file = f"firewall_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.rules"
        
    def run_command(self, command):
        """Run shell command and return output"""
        try:
            result = subprocess.run(command, shell=True, check=True, 
                                  capture_output=True, text=True)
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            return False, e.stderr
    
    def backup_current_rules(self):
        """Backup current iptables rules"""
        print(f"{Fore.CYAN}[*] Backing up current rules to {self.backup_file}{Style.RESET_ALL}")
        
        success, output = self.run_command("iptables-save")
        if success:
            with open(self.backup_file, 'w') as f:
                f.write(output)
            print(f"{Fore.GREEN}[✓] Rules backed up successfully{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[✗] Failed to backup rules{Style.RESET_ALL}")
            return False
    
    def restore_backup(self):
        """Restore firewall rules from backup"""
        if os.path.exists(self.backup_file):
            print(f"{Fore.CYAN}[*] Restoring rules from {self.backup_file}{Style.RESET_ALL}")
            success, _ = self.run_command(f"iptables-restore < {self.backup_file}")
            if success:
                print(f"{Fore.GREEN}[✓] Rules restored{Style.RESET_ALL}")
                return True
        print(f"{Fore.RED}[✗] No backup found or restore failed{Style.RESET_ALL}")
        return False
    
    # ==================== BASIC PROTECTION ====================
    
    def configure_basic_protection(self):
        """Configure basic firewall protection"""
        print(f"\n{Fore.CYAN}🔒 Configuring Basic Protection{Style.RESET_ALL}")
        
        rules = [
            # Default policies
            "iptables -P INPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables -P OUTPUT ACCEPT",
            
            # Allow established connections
            "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
            
            # Allow loopback
            "iptables -A INPUT -i lo -j ACCEPT",
            "iptables -A OUTPUT -o lo -j ACCEPT",
            
            # Allow SSH (adjust as needed)
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            
            # Allow HTTP/HTTPS
            "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 443 -j ACCEPT",
            
            # Allow ICMP (ping) with rate limiting
            "iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT",
        ]
        
        for rule in rules:
            success, _ = self.run_command(rule)
            if success:
                print(f"{Fore.GREEN}  [✓] {rule}{Style.RESET_ALL}")
                self.rules_applied.append(rule)
            else:
                print(f"{Fore.RED}  [✗] {rule}{Style.RESET_ALL}")
    
    # ==================== SCAN PREVENTION ====================
    
    def configure_scan_prevention(self):
        """Configure rules to prevent port scanning"""
        print(f"\n{Fore.CYAN}🛡️ Configuring Scan Prevention{Style.RESET_ALL}")
        
        rules = [
            # 1. Rate limiting for new connections
            "iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT",
            "iptables -A INPUT -p tcp --syn -j DROP",
            
            # 2. Port scan detection and blocking
            "iptables -N PORT_SCAN",
            "iptables -A INPUT -p tcp -j PORT_SCAN",
            
            # 3. Block XMAS packets
            "iptables -A INPUT -p tcp --tcp-flags FIN,PSH,URG FIN,PSH,URG -j DROP",
            
            # 4. Block NULL packets
            "iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP",
            
            # 5. Block SYN-FIN packets
            "iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP",
            
            # 6. Block SYN-RST packets
            "iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP",
            
            # 7. Limit connections per IP
            "iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 50 --connlimit-mask 32 -j DROP",
            
            # 8. Recent module for tracking
            "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH",
            "iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 --name SSH -j DROP",
        ]
        
        for rule in rules:
            success, _ = self.run_command(rule)
            if success:
                print(f"{Fore.GREEN}  [✓] {rule}{Style.RESET_ALL}")
                self.rules_applied.append(rule)
            else:
                print(f"{Fore.RED}  [✗] {rule}{Style.RESET_ALL}")
    
    def configure_advanced_scan_prevention(self):
        """Configure advanced scan prevention techniques"""
        print(f"\n{Fore.CYAN}🔐 Configuring Advanced Scan Prevention{Style.RESET_ALL}")
        
        rules = [
            # 1. Hashlimit for finer control
            "iptables -A INPUT -p tcp --syn -m hashlimit --hashlimit-name syn_flood --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-above 20/minute --hashlimit-burst 40 -j DROP",
            
            # 2. UDP flood protection
            "iptables -A INPUT -p udp -m limit --limit 10/s -j ACCEPT",
            "iptables -A INPUT -p udp -j DROP",
            
            # 3. ICMP flood protection
            "iptables -A INPUT -p icmp -m limit --limit 5/s -j ACCEPT",
            "iptails -A INPUT -p icmp -j DROP",
            
            # 4. Fragment attack prevention
            "iptables -A INPUT -f -j DROP",
            
            # 5. Invalid packets
            "iptables -A INPUT -m state --state INVALID -j DROP",
            
            # 6. Port knocking simulation (log then drop)
            "iptables -A INPUT -p tcp --dport 12345 -j LOG --log-prefix 'PORT_KNOCK_1: '",
            "iptables -A INPUT -p tcp --dport 23456 -j LOG --log-prefix 'PORT_KNOCK_2: '",
            "iptables -A INPUT -p tcp --dport 34567 -j LOG --log-prefix 'PORT_KNOCK_3: '",
        ]
        
        for rule in rules:
            success, _ = self.run_command(rule)
            if success:
                print(f"{Fore.GREEN}  [✓] {rule}{Style.RESET_ALL}")
                self.rules_applied.append(rule)
            else:
                print(f"{Fore.RED}  [✗] {rule}{Style.RESET_ALL}")
    
    # ==================== SERVICE PROTECTION ====================
    
    def protect_service(self, port, protocol='tcp', max_connections=10):
        """Protect a specific service port"""
        print(f"\n{Fore.CYAN}🛡️ Protecting service on port {port}/{protocol}{Style.RESET_ALL}")
        
        rules = [
            # Rate limit connections to this port
            f"iptables -A INPUT -p {protocol} --dport {port} -m state --state NEW -m recent --set --name SERVICE_{port}",
            f"iptables -A INPUT -p {protocol} --dport {port} -m state --state NEW -m recent --update --seconds 60 --hitcount {max_connections} --name SERVICE_{port} -j DROP",
            
            # Connection limit
            f"iptables -A INPUT -p {protocol} --dport {port} -m connlimit --connlimit-above {max_connections * 2} -j DROP",
            
            # Accept legitimate traffic
            f"iptables -A INPUT -p {protocol} --dport {port} -j ACCEPT",
        ]
        
        for rule in rules:
            success, _ = self.run_command(rule)
            if success:
                print(f"{Fore.GREEN}  [✓] Protected port {port}{Style.RESET_ALL}")
                self.rules_applied.append(rule)
            else:
                print(f"{Fore.RED}  [✗] Failed to protect port {port}{Style.RESET_ALL}")
    
    # ==================== GEOIP BLOCKING ====================
    
    def setup_geoip_blocking(self, countries=None):
        """Block traffic from specific countries (requires iptables geoip)"""
        if countries is None:
            countries = []
        print(f"\n{Fore.CYAN}🌍 Setting up GeoIP blocking for: {', '.join(countries)}{Style.RESET_ALL}")
        
        for country in countries:
            rule = f"iptables -A INPUT -m geoip --src-cc {country} -j DROP"
            success, _ = self.run_command(rule)
            if success:
                print(f"{Fore.GREEN}  [✓] Blocked country: {country}{Style.RESET_ALL}")
                self.rules_applied.append(rule)
            else:
                print(f"{Fore.YELLOW}  [!] GeoIP may not be installed for {country}{Style.RESET_ALL}")
    
    # ==================== PORT KNOCKING ====================
    
    def setup_port_knocking(self, knock_ports=None, target_port=22):
        """Setup port knocking sequence"""
        if knock_ports is None:
            knock_ports = []
        print(f"\n{Fore.CYAN}🔑 Setting up port knocking for SSH{Style.RESET_ALL}")
        
        # This is a simplified example - real port knocking is more complex
        rules = [
            # Create chains
            "iptables -N KNOCK1",
            "iptables -N KNOCK2",
            "iptables -N KNOCK3",
            "iptables -N PASSED",
            
            # Initial state
            f"iptables -A INPUT -p tcp --dport {knock_ports[0]} -m recent --name KNOCK1 --set -j DROP",
            f"iptables -A INPUT -p tcp --dport {knock_ports[1]} -m recent --name KNOCK1 --rcheck -m recent --name KNOCK2 --set -j DROP",
            f"iptables -A INPUT -p tcp --dport {knock_ports[2]} -m recent --name KNOCK2 --rcheck -m recent --name PASSED --set -j DROP",
            
            # Allow SSH if sequence completed
            f"iptables -A INPUT -p tcp --dport {target_port} -m recent --name PASSED --rcheck --seconds 30 -j ACCEPT",
        ]
        
        for rule in rules:
            success, _ = self.run_command(rule)
            if success:
                print(f"{Fore.GREEN}  [✓] {rule[:50]}...{Style.RESET_ALL}")
                self.rules_applied.append(rule)
    
    # ==================== NFTABLES CONFIG ====================
    
    def generate_nftables_config(self):
        """Generate nftables configuration"""
        config = f"""
#!/usr/sbin/nft -f

# NFTables configuration for port scan prevention
# Generated by firewall_config.py on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

flush ruleset

table inet filter {{
    chain input {{
        type filter hook input priority 0; policy drop;
        
        # Allow established/related
        ct state established,related accept
        
        # Allow loopback
        iif lo accept
        
        # Rate limit ICMP
        ip protocol icmp icmp type echo-request limit rate 1/second accept
        
        # SSH (with rate limit)
        tcp dport 22 ct state new limit rate 10/minute accept
        tcp dport 22 accept
        
        # Web services
        tcp dport {{80,443}} accept
        
        # Port scan protection
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop
        tcp flags & (fin|syn) == (fin|syn) drop
        tcp flags & (syn|rst) == (syn|rst) drop
        
        # Rate limit new TCP connections
        tcp flags syn limit rate 1000/second accept
        tcp flags syn drop
        
        # Log and drop everything else
        log prefix "FILTER-INPUT-DROP: " counter drop
    }}
    
    chain forward {{
        type filter hook forward priority 0; policy drop;
    }}
    
    chain output {{
        type filter hook output priority 0; policy accept;
    }}
}}
"""
        return config
    
    # ==================== IP BLACKLIST ====================
    
    def setup_ip_blacklist(self, blacklist_file="blacklist.txt"):
        """Block IPs from blacklist file"""
        print(f"\n{Fore.CYAN}📋 Loading IP blacklist from {blacklist_file}{Style.RESET_ALL}")
        
        if not os.path.exists(blacklist_file):
            print(f"{Fore.YELLOW}[!] Blacklist file not found{Style.RESET_ALL}")
            return
        
        # Create ipset for blacklist
        self.run_command("ipset create blacklist hash:ip 2>/dev/null")
        
        with open(blacklist_file, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith('#'):
                    rule = f"ipset add blacklist {ip}"
                    success, _ = self.run_command(rule)
                    if success:
                        print(f"{Fore.GREEN}  [✓] Blocked IP: {ip}{Style.RESET_ALL}")
        
        # Apply ipset to iptables
        rule = "iptables -I INPUT -m set --match-set blacklist src -j DROP"
        success, _ = self.run_command(rule)
        if success:
            print(f"{Fore.GREEN}[✓] Blacklist applied{Style.RESET_ALL}")
    
    # ==================== MONITORING ====================
    
    def setup_monitoring(self):
        """Setup monitoring rules"""
        print(f"\n{Fore.CYAN}📊 Setting up monitoring{Style.RESET_ALL}")
        
        rules = [
            # Log scan attempts
            "iptables -A INPUT -m recent --name SCAN --rcheck --seconds 60 -j LOG --log-prefix 'PORT_SCAN: '",
            
            # Log blocked packets
            "iptables -A INPUT -j LOG --log-prefix 'FW_BLOCKED: ' --log-level 4",
        ]
        
        for rule in rules:
            success, _ = self.run_command(rule)
            if success:
                print(f"{Fore.GREEN}  [✓] Monitoring enabled{Style.RESET_ALL}")
                self.rules_applied.append(rule)
    
    # ==================== APPLY CONFIG ====================
    
    def apply_all(self, options):
        """Apply all selected protections"""
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🔧 Applying Firewall Configuration{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        
        # Backup current rules
        if options.backup:
            self.backup_current_rules()
        
        # Clear existing rules
        if options.clear:
            print(f"\n{Fore.YELLOW}[!] Clearing existing rules{Style.RESET_ALL}")
            self.run_command("iptables -F")
            self.run_command("iptables -X")
            self.run_command("iptables -t nat -F")
            self.run_command("iptables -t mangle -F")
        
        # Apply protections
        if options.basic:
            self.configure_basic_protection()
        
        if options.scan_prevent:
            self.configure_scan_prevention()
        
        if options.advanced:
            self.configure_advanced_scan_prevention()
        
        if options.services:
            for service in options.services.split(','):
                port, proto = service.split('/') if '/' in service else (service, 'tcp')
                self.protect_service(int(port), proto)
        
        if options.geoip:
            self.setup_geoip_blocking(options.geoip.split(','))
        
        if options.knock:
            self.setup_port_knocking()
        
        if options.monitor:
            self.setup_monitoring()
        
        if options.blacklist:
            self.setup_ip_blacklist(options.blacklist)
        
        # Save rules
        if options.save:
            save_file = options.save
            success, _ = self.run_command(f"iptables-save > {save_file}")
            if success:
                print(f"{Fore.GREEN}[✓] Rules saved to {save_file}{Style.RESET_ALL}")
        
        # Generate nftables config
        if options.nftables:
            nft_config = self.generate_nftables_config()
            with open(options.nftables, 'w') as f:
                f.write(nft_config)
            print(f"{Fore.GREEN}[✓] NFTables config saved to {options.nftables}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[✓] Configuration complete! {len(self.rules_applied)} rules applied{Style.RESET_ALL}")
        
        # Show summary
        self.show_rules()
    
    def show_rules(self):
        """Display current iptables rules"""
        print(f"\n{Fore.CYAN}📋 Current Rules:{Style.RESET_ALL}")
        success, output = self.run_command("iptables -L -n -v")
        if success:
            print(output)
    
    def cleanup(self):
        """Cleanup and restore"""
        print(f"\n{Fore.YELLOW}[*] Cleaning up...{Style.RESET_ALL}")
        self.restore_backup()

def main():
    parser = argparse.ArgumentParser(description='Firewall Configuration for Port Scan Prevention')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface')
    parser.add_argument('--basic', action='store_true', help='Apply basic protection')
    parser.add_argument('--scan-prevent', action='store_true', help='Apply scan prevention')
    parser.add_argument('--advanced', action='store_true', help='Apply advanced protection')
    parser.add_argument('--services', help='Protect specific services (e.g., "22/tcp,80/tcp,53/udp")')
    parser.add_argument('--geoip', help='Block countries (comma-separated, e.g., "CN,RU")')
    parser.add_argument('--knock', action='store_true', help='Setup port knocking')
    parser.add_argument('--monitor', action='store_true', help='Setup monitoring')
    parser.add_argument('--blacklist', help='IP blacklist file')
    parser.add_argument('--save', help='Save rules to file')
    parser.add_argument('--nftables', help='Generate nftables config file')
    parser.add_argument('--clear', action='store_true', help='Clear existing rules first')
    parser.add_argument('--backup', action='store_true', help='Backup current rules')
    parser.add_argument('--restore', action='store_true', help='Restore from backup')
    parser.add_argument('--show', action='store_true', help='Show current rules')
    parser.add_argument('--all', action='store_true', help='Apply all protections')
    
    args = parser.parse_args()
    
    print(f"""
    {Fore.CYAN}╔═══════════════════════════════════════╗
    ║     Firewall Configuration Tool       ║
    ║    Port Scan Prevention              ║
    ╚═══════════════════════════════════════╝{Style.RESET_ALL}
    """)
    
    # Check root privileges
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] This script requires root privileges.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Please run with: sudo python3 firewall_config.py{Style.RESET_ALL}")
        sys.exit(1)
    
    config = FirewallConfig(args.interface)
    
    if args.restore:
        config.restore_backup()
        sys.exit(0)
    
    if args.show:
        config.show_rules()
        sys.exit(0)
    
    if args.all:
        args.basic = True
        args.scan_prevent = True
        args.advanced = True
        args.monitor = True
        args.backup = True
    
    # Confirm with user
    print(f"{Fore.YELLOW}[?] This will modify firewall rules. Continue? (yes/no): {Style.RESET_ALL}", end='')
    response = input().lower()
    if response != 'yes':
        print(f"{Fore.RED}[!] Exiting{Style.RESET_ALL}")
        sys.exit(0)
    
    try:
        config.apply_all(args)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted{Style.RESET_ALL}")
        config.cleanup()
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        config.cleanup()

if __name__ == "__main__":
    main()
