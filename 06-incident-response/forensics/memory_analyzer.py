#!/usr/bin/env python3
"""
Memory Forensics Analyzer
Location: 06-incident-response/forensics/memory_analyzer.py

This script analyzes memory dumps for signs of compromise including:
- Suspicious processes
- Network connections
- Loaded modules
- Process injection
- Rootkit indicators

Requires: volatility3 (install separately)
"""

import os
import sys
import json
import argparse
import subprocess
import tempfile
from datetime import datetime
import re

class MemoryAnalyzer:
    """
    Memory dump analysis using Volatility 3
    """
    
    def __init__(self, volatility_path='vol'):
        """
        Initialize memory analyzer
        
        Args:
            volatility_path: Path to volatility3 executable
        """
        self.vol_path = volatility_path
        self.results = {}
        
    def check_volatility(self):
        """Check if volatility is available"""
        try:
            result = subprocess.run([self.vol_path, '-h'], 
                                   capture_output=True, text=True)
            return result.returncode == 0
        except FileNotFoundError:
            return False
    
    def get_profile_info(self, memory_dump):
        """Get memory profile information"""
        print(f"[*] Detecting memory profile for {memory_dump}")
        
        try:
            cmd = [self.vol_path, '-f', memory_dump, 'windows.info']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                info = {}
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        info[key.strip()] = value.strip()
                return info
            else:
                return None
        except subprocess.TimeoutExpired:
            print("[!] Profile detection timed out")
            return None
    
    def run_volatility_command(self, memory_dump, plugin, profile=None):
        """Run volatility command and return output"""
        cmd = [self.vol_path, '-f', memory_dump]
        if profile:
            cmd.extend(['--profile', profile])
        cmd.extend(plugin)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"[!] Command timed out: {' '.join(plugin)}"
    
    def analyze_processes(self, memory_dump):
        """Analyze running processes"""
        print("[*] Analyzing processes...")
        
        # Get process list
        output = self.run_volatility_command(memory_dump, ['windows.psscan.PsScan'])
        
        processes = []
        suspicious = []
        
        lines = output.split('\n')
        for line in lines[2:]:  # Skip header
            parts = line.split()
            if len(parts) >= 6:
                try:
                    proc = {
                        'pid': parts[1],
                        'ppid': parts[2],
                        'name': parts[5] if len(parts) > 5 else 'unknown',
                        'offset': parts[0]
                    }
                    processes.append(proc)
                    
                    # Check for suspicious processes
                    if self.is_suspicious_process(proc['name']):
                        suspicious.append(proc)
                except:
                    pass
        
        return {
            'total': len(processes),
            'processes': processes[:20],  # First 20 for preview
            'suspicious': suspicious
        }
    
    def analyze_network(self, memory_dump):
        """Analyze network connections"""
        print("[*] Analyzing network connections...")
        
        output = self.run_volatility_command(memory_dump, ['windows.netscan.NetScan'])
        
        connections = []
        suspicious = []
        
        lines = output.split('\n')
        for line in lines[2:]:
            parts = line.split()
            if len(parts) >= 8 and 'TCP' in line:
                conn = {
                    'protocol': parts[0],
                    'local': f"{parts[1]}:{parts[2]}",
                    'remote': f"{parts[3]}:{parts[4]}",
                    'state': parts[5] if len(parts) > 5 else 'unknown',
                    'pid': parts[6] if len(parts) > 6 else 'unknown'
                }
                connections.append(conn)
                
                # Check for suspicious connections
                if self.is_suspicious_connection(conn):
                    suspicious.append(conn)
        
        return {
            'total': len(connections),
            'connections': connections[:20],
            'suspicious': suspicious
        }
    
    def analyze_modules(self, memory_dump):
        """Analyze loaded modules/DLLs"""
        print("[*] Analyzing loaded modules...")
        
        output = self.run_volatility_command(memory_dump, ['windows.dlllist.DllList'])
        
        modules = []
        suspicious = []
        
        lines = output.split('\n')
        for line in lines[2:]:
            parts = line.split()
            if len(parts) >= 4:
                module = {
                    'pid': parts[0],
                    'process': parts[1],
                    'base': parts[2],
                    'path': parts[3] if len(parts) > 3 else 'unknown'
                }
                modules.append(module)
                
                # Check for suspicious modules
                if self.is_suspicious_module(module['path']):
                    suspicious.append(module)
        
        return {
            'total': len(modules),
            'modules': modules[:20],
            'suspicious': suspicious
        }
    
    def analyze_malware_indicators(self, memory_dump):
        """Analyze malware indicators"""
        print("[*] Scanning for malware indicators...")
        
        indicators = []
        
        # Check for process injection
        malfind = self.run_volatility_command(memory_dump, ['windows.malfind.Malfind'])
        if malfind and 'PAGE_EXECUTE_READWRITE' in malfind:
            indicators.append({
                'type': 'process_injection',
                'description': 'Detected RWX memory regions (possible code injection)',
                'details': malfind[:500]
            })
        
        # Check for hollowed processes
        hollowfind = self.run_volatility_command(memory_dump, ['windows.hollowfind.HollowFind'])
        if hollowfind and 'hollow' in hollowfind.lower():
            indicators.append({
                'type': 'process_hollowing',
                'description': 'Detected possible process hollowing',
                'details': hollowfind[:500]
            })
        
        # Check for API hooks
        apihooks = self.run_volatility_command(memory_dump, ['windows.apihooks.ApiHooks'])
        if apihooks and 'Hook' in apihooks:
            indicators.append({
                'type': 'api_hooks',
                'description': 'Detected API hooks (possible rootkit)',
                'details': apihooks[:500]
            })
        
        return indicators
    
    def is_suspicious_process(self, name):
        """Check if process name is suspicious"""
        suspicious_names = [
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
            'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'certutil.exe',
            'bitsadmin.exe', 'wmic.exe', 'schtasks.exe', 'taskkill.exe',
            'net.exe', 'net1.exe', 'sc.exe', 'reg.exe', 'vssadmin.exe'
        ]
        
        name_lower = name.lower()
        for sus in suspicious_names:
            if sus in name_lower and 'system32' not in name_lower:
                return True
        return False
    
    def is_suspicious_connection(self, conn):
        """Check if network connection is suspicious"""
        suspicious_ports = [4444, 1337, 6667, 8080, 8443, 31337, 12345, 27374]
        
        try:
            remote = conn['remote']
            if '*:*' in remote:
                return False
            
            port = int(remote.split(':')[-1])
            if port in suspicious_ports:
                return True
        except:
            pass
        
        return False
    
    def is_suspicious_module(self, path):
        """Check if module path is suspicious"""
        suspicious_paths = [
            '\\temp\\', '\\tmp\\', '\\users\\public\\',
            '\\programdata\\', '\\windows\\temp\\', '\\appdata\\'
        ]
        
        path_lower = path.lower()
        for sus in suspicious_paths:
            if sus in path_lower:
                return True
        return False
    
    def generate_report(self, memory_dump):
        """Generate comprehensive memory analysis report"""
        print(f"\n{'='*60}")
        print("🔍 MEMORY FORENSICS ANALYSIS REPORT")
        print(f"{'='*60}")
        print(f"Memory Dump: {memory_dump}")
        print(f"Analysis Time: {datetime.now().isoformat()}")
        print(f"{'='*60}\n")
        
        # Get profile
        profile_info = self.get_profile_info(memory_dump)
        if profile_info:
            print("📊 System Information:")
            for key, value in profile_info.items():
                print(f"  {key}: {value}")
        
        # Analyze processes
        print("\n📋 Process Analysis:")
        procs = self.analyze_processes(memory_dump)
        print(f"  Total Processes: {procs['total']}")
        if procs['suspicious']:
            print(f"  ⚠️ Suspicious Processes Found: {len(procs['suspicious'])}")
            for p in procs['suspicious']:
                print(f"    • PID {p['pid']}: {p['name']}")
        
        # Analyze network
        print("\n🌐 Network Analysis:")
        net = self.analyze_network(memory_dump)
        print(f"  Total Connections: {net['total']}")
        if net['suspicious']:
            print(f"  ⚠️ Suspicious Connections: {len(net['suspicious'])}")
            for c in net['suspicious']:
                print(f"    • {c['protocol']} {c['local']} -> {c['remote']}")
        
        # Analyze modules
        print("\n📦 Module Analysis:")
        mods = self.analyze_modules(memory_dump)
        print(f"  Total Modules: {mods['total']}")
        if mods['suspicious']:
            print(f"  ⚠️ Suspicious Modules: {len(mods['suspicious'])}")
            for m in mods['suspicious'][:5]:
                print(f"    • PID {m['pid']}: {os.path.basename(m['path'])}")
        
        # Malware indicators
        print("\n🦠 Malware Indicators:")
        indicators = self.analyze_malware_indicators(memory_dump)
        if indicators:
            for i in indicators:
                print(f"  ⚠️ {i['type']}: {i['description']}")
        else:
            print("  ✓ No obvious malware indicators found")
        
        # Summary
        print(f"\n{'='*60}")
        risk_level = 'HIGH' if (len(procs['suspicious']) + len(net['suspicious'])) > 0 else 'LOW'
        print(f"🎯 Risk Level: {risk_level}")
        print(f"{'='*60}")
        
        return {
            'profile': profile_info,
            'processes': procs,
            'network': net,
            'modules': mods,
            'indicators': indicators,
            'risk_level': risk_level
        }

def main():
    parser = argparse.ArgumentParser(description='Memory Forensics Analyzer')
    parser.add_argument('-f', '--file', required=True, help='Memory dump file')
    parser.add_argument('-p', '--profile', help='Memory profile (optional)')
    parser.add_argument('-o', '--output', help='Output report file')
    parser.add_argument('--volatility', default='vol', help='Path to volatility')
    
    args = parser.parse_args()
    
    analyzer = MemoryAnalyzer(args.volatility)
    
    if not analyzer.check_volatility():
        print("[!] Volatility not found. Please install volatility3 first.")
        print("    pip install volatility3")
        sys.exit(1)
    
    if not os.path.exists(args.file):
        print(f"[!] Memory dump not found: {args.file}")
        sys.exit(1)
    
    results = analyzer.generate_report(args.file)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[✓] Report saved to {args.output}")

if __name__ == "__main__":
    main()
