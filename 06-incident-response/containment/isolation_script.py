#!/usr/bin/env python3

import os
import sys
import time
import argparse
import subprocess
import platform
import psutil
import signal
import shutil
from datetime import datetime
from pathlib import Path
import json

class IncidentIsolation:
    """
    Immediate incident containment and isolation
    """
    
    def __init__(self, incident_id=None):
        """
        Initialize incident isolation
        
        Args:
            incident_id: Unique incident identifier
        """
        self.system = platform.system()
        self.incident_id = incident_id or f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.log_file = f"isolation_{self.incident_id}.log"
        self.actions_taken = []
        self.isolated_hosts = []
        self.terminated_processes = []
        
        # Create incident directory
        self.incident_dir = Path(f"incident_{self.incident_id}")
        self.incident_dir.mkdir(exist_ok=True)
        
        print(f"[*] Incident ID: {self.incident_id}")
        print(f"[*] Log file: {self.log_file}")
        print(f"[*] Incident directory: {self.incident_dir}")
    
    def log_action(self, action, status, details=None):
        """Log isolation action"""
        timestamp = datetime.now().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'action': action,
            'status': status,
            'details': details
        }
        
        # Print to console
        status_symbol = "✓" if status == 'success' else "✗"
        print(f"[{status_symbol}] {action}")
        if details:
            print(f"    {details}")
        
        # Save to log file
        self.actions_taken.append(log_entry)
        
        with open(self.log_file, 'a') as f:
            f.write(f"[{timestamp}] {action}: {status}\n")
            if details:
                f.write(f"    {details}\n")
    
    def isolate_network(self, interface=None, block_all=False):
        """
        Isolate system from network
        
        Args:
            interface: Specific interface to isolate
            block_all: Block all network traffic
        """
        print(f"\n{'='*60}")
        print("🔒 NETWORK ISOLATION")
        print(f"{'='*60}")
        
        if self.system == 'Windows':
            # Windows network isolation
            try:
                if block_all:
                    # Disable all network adapters
                    result = subprocess.run(
                        ['powershell', '-Command', 
                         'Get-NetAdapter | Disable-NetAdapter -Confirm:$false'],
                        capture_output=True, text=True
                    )
                    self.log_action('Disable all network adapters', 
                                  'success' if result.returncode == 0 else 'failed',
                                  result.stderr if result.stderr else None)
                elif interface:
                    # Disable specific interface
                    result = subprocess.run(
                        ['netsh', 'interface', 'set', 'interface', interface, 'admin=disable'],
                        capture_output=True, text=True
                    )
                    self.log_action(f'Disable interface {interface}', 
                                  'success' if result.returncode == 0 else 'failed',
                                  result.stderr if result.stderr else None)
                
                # Backup firewall rules
                subprocess.run(
                    ['netsh', 'advfirewall', 'export', f'{self.incident_dir}/firewall_backup.wfw'],
                    capture_output=True
                )
                
                # Block all inbound/outbound
                subprocess.run(
                    ['netsh', 'advfirewall', 'set', 'allprofiles', 'firewallpolicy', 'blockinbound,blockoutbound'],
                    capture_output=True
                )
                self.log_action('Set firewall to block all traffic', 'success')
                
            except Exception as e:
                self.log_action('Network isolation', 'failed', str(e))
        
        else:
            # Linux network isolation
            try:
                if block_all:
                    # Block all traffic with iptables
                    commands = [
                        ['iptables', '-P', 'INPUT', 'DROP'],
                        ['iptables', '-P', 'OUTPUT', 'DROP'],
                        ['iptables', '-P', 'FORWARD', 'DROP'],
                        ['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'],
                        ['iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT']
                    ]
                    
                    for cmd in commands:
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        if result.returncode != 0:
                            self.log_action(f'Failed: {" ".join(cmd)}', 'failed', result.stderr)
                    
                    self.log_action('Blocked all network traffic', 'success')
                    
                    # Save iptables rules
                    subprocess.run(
                        ['iptables-save'], 
                        stdout=open(f'{self.incident_dir}/iptables.rules', 'w')
                    )
                
                elif interface:
                    # Bring down specific interface
                    result = subprocess.run(
                        ['ip', 'link', 'set', interface, 'down'],
                        capture_output=True, text=True
                    )
                    self.log_action(f'Bring down interface {interface}', 
                                  'success' if result.returncode == 0 else 'failed',
                                  result.stderr if result.stderr else None)
                
            except Exception as e:
                self.log_action('Network isolation', 'failed', str(e))
    
    def terminate_suspicious_processes(self, process_names=None, pids=None, kill_all=False):
        """
        Terminate suspicious processes
        
        Args:
            process_names: List of process names to terminate
            pids: List of PIDs to terminate
            kill_all: Kill all non-system processes
        """
        print(f"\n{'='*60}")
        print("🔪 PROCESS TERMINATION")
        print(f"{'='*60}")
        
        system_processes = ['system', 'kernel', 'smss.exe', 'csrss.exe', 'wininit.exe',
                           'services.exe', 'lsass.exe', 'svchost.exe']
        
        terminated = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
            try:
                proc_info = proc.info
                should_terminate = False
                
                if kill_all and proc_info['name'].lower() not in system_processes:
                    should_terminate = True
                elif process_names and proc_info['name'].lower() in [p.lower() for p in process_names]:
                    should_terminate = True
                elif pids and proc_info['pid'] in pids:
                    should_terminate = True
                
                if should_terminate:
                    try:
                        proc.terminate()
                        time.sleep(1)
                        if proc.is_running():
                            proc.kill()
                        
                        terminated.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'exe': proc_info['exe']
                        })
                        
                        self.log_action(f'Terminated process {proc_info["name"]} (PID: {proc_info["pid"]})',
                                      'success')
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                        self.log_action(f'Failed to terminate {proc_info["name"]}', 'failed', str(e))
            
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        self.terminated_processes = terminated
        return terminated
    
    def disable_accounts(self, usernames=None, disable_all_non_admin=False):
        """
        Disable user accounts
        
        Args:
            usernames: List of usernames to disable
            disable_all_non_admin: Disable all non-administrator accounts
        """
        print(f"\n{'='*60}")
        print("👤 ACCOUNT DISABLEMENT")
        print(f"{'='*60}")
        
        if self.system == 'Windows':
            try:
                if usernames:
                    for username in usernames:
                        result = subprocess.run(
                            ['net', 'user', username, '/active:no'],
                            capture_output=True, text=True
                        )
                        self.log_action(f'Disable account {username}',
                                      'success' if result.returncode == 0 else 'failed',
                                      result.stderr if result.stderr else None)
                
                if disable_all_non_admin:
                    # Get all users
                    result = subprocess.run(
                        ['net', 'user'],
                        capture_output=True, text=True
                    )
                    
                    # Parse user list (simplified)
                    users = result.stdout.split('\n')[4:-2]
                    for user in users:
                        user = user.strip()
                        if user and user not in ['Administrator', 'Guest']:
                            subprocess.run(['net', 'user', user, '/active:no'])
                            self.log_action(f'Disable non-admin account {user}', 'success')
                            
            except Exception as e:
                self.log_action('Account disablement', 'failed', str(e))
        
        else:  # Linux
            try:
                if usernames:
                    for username in usernames:
                        result = subprocess.run(
                            ['passwd', '-l', username],
                            capture_output=True, text=True
                        )
                        self.log_action(f'Lock account {username}',
                                      'success' if result.returncode == 0 else 'failed',
                                      result.stderr if result.stderr else None)
                
                if disable_all_non_admin:
                    # Get all users with UID >= 1000
                    with open('/etc/passwd', 'r') as f:
                        for line in f:
                            parts = line.split(':')
                            if len(parts) >= 3:
                                uid = int(parts[2])
                                if uid >= 1000 and uid < 65534:
                                    username = parts[0]
                                    subprocess.run(['passwd', '-l', username])
                                    self.log_action(f'Lock non-admin account {username}', 'success')
                                    
            except Exception as e:
                self.log_action('Account disablement', 'failed', str(e))
    
    def lockdown_filesystem(self, paths=None, readonly=True):
        """
        Lockdown file system (mount as read-only)
        
        Args:
            paths: Specific paths to lockdown
            readonly: Mount as read-only
        """
        print(f"\n{'='*60}")
        print("📁 FILESYSTEM LOCKDOWN")
        print(f"{'='*60}")
        
        if self.system == 'Linux':
            try:
                if paths:
                    for path in paths:
                        if os.path.exists(path):
                            # Remount as read-only
                            result = subprocess.run(
                                ['mount', '-o', 'remount,ro', path],
                                capture_output=True, text=True
                            )
                            self.log_action(f'Remount {path} as read-only',
                                          'success' if result.returncode == 0 else 'failed',
                                          result.stderr if result.stderr else None)
                else:
                    # Remount all non-system partitions as read-only
                    with open('/proc/mounts', 'r') as f:
                        for line in f:
                            parts = line.split()
                            if len(parts) >= 2:
                                device, mountpoint = parts[0], parts[1]
                                if mountpoint not in ['/', '/boot', '/sys', '/proc', '/dev']:
                                    result = subprocess.run(
                                        ['mount', '-o', 'remount,ro', mountpoint],
                                        capture_output=True, text=True
                                    )
                                    self.log_action(f'Remount {mountpoint} as read-only',
                                                  'success' if result.returncode == 0 else 'failed',
                                                  result.stderr if result.stderr else None)
                                    
            except Exception as e:
                self.log_action('Filesystem lockdown', 'failed', str(e))
        
        elif self.system == 'Windows':
            # Windows doesn't have easy remount, so we set NTFS permissions
            try:
                if paths:
                    for path in paths:
                        if os.path.exists(path):
                            # Remove write permissions for all users
                            result = subprocess.run(
                                ['icacls', path, '/deny', '*S-1-1-0:(W)'],
                                capture_output=True, text=True
                            )
                            self.log_action(f'Remove write permissions from {path}',
                                          'success' if result.returncode == 0 else 'failed',
                                          result.stderr if result.stderr else None)
            except Exception as e:
                self.log_action('Filesystem lockdown', 'failed', str(e))
    
    def preserve_evidence(self, paths=None):
        """
        Preserve evidence by copying to secure location
        
        Args:
            paths: Specific paths to preserve
        """
        print(f"\n{'='*60}")
        print("🔍 EVIDENCE PRESERVATION")
        print(f"{'='*60}")
        
        evidence_dir = self.incident_dir / 'evidence'
        evidence_dir.mkdir(exist_ok=True)
        
        # Default evidence paths
        if not paths:
            if self.system == 'Windows':
                paths = [
                    'C:\\Windows\\System32\\winevt\\Logs',
                    'C:\\Windows\\Prefetch',
                    'C:\\Users',
                    'C:\\Windows\\Temp'
                ]
            else:
                paths = [
                    '/var/log',
                    '/home',
                    '/tmp',
                    '/etc'
                ]
        
        for path in paths:
            if os.path.exists(path):
                try:
                    dest = evidence_dir / Path(path).name
                    if os.path.isdir(path):
                        shutil.copytree(path, dest, ignore_dangling_symlinks=True)
                    else:
                        shutil.copy2(path, dest)
                    
                    self.log_action(f'Preserved evidence from {path}', 'success')
                except Exception as e:
                    self.log_action(f'Failed to preserve {path}', 'failed', str(e))
        
        # Save process list
        with open(evidence_dir / 'process_list.txt', 'w') as f:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'connections']):
                try:
                    f.write(f"{proc.info}\n")
                except:
                    pass
        
        # Save network connections
        with open(evidence_dir / 'network_connections.txt', 'w') as f:
            for conn in psutil.net_connections():
                f.write(f"{conn}\n")
        
        self.log_action('Saved system state', 'success')
    
    def create_snapshot(self):
        """Create system snapshot for later analysis"""
        print(f"\n{'='*60}")
        print("📸 SYSTEM SNAPSHOT")
        print(f"{'='*60}")
        
        snapshot_dir = self.incident_dir / 'snapshot'
        snapshot_dir.mkdir(exist_ok=True)
        
        # Save system information
        with open(snapshot_dir / 'system_info.txt', 'w') as f:
            f.write(f"Hostname: {platform.node()}\n")
            f.write(f"OS: {platform.system()} {platform.release()}\n")
            f.write(f"Time: {datetime.now().isoformat()}\n")
        
        # Save running processes
        with open(snapshot_dir / 'processes.txt', 'w') as f:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    f.write(f"{proc.info}\n")
                except:
                    pass
        
        # Save network connections
        with open(snapshot_dir / 'network.txt', 'w') as f:
            for conn in psutil.net_connections():
                f.write(f"{conn}\n")
        
        # Save listening ports
        with open(snapshot_dir / 'listening.txt', 'w') as f:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    f.write(f"{conn}\n")
        
        self.log_action('Created system snapshot', 'success')
    
    def generate_report(self):
        """Generate isolation report"""
        report = []
        report.append("="*80)
        report.append(f"INCIDENT ISOLATION REPORT")
        report.append("="*80)
        report.append(f"Incident ID: {self.incident_id}")
        report.append(f"Timestamp: {datetime.now().isoformat()}")
        report.append(f"System: {platform.system()} {platform.release()}")
        report.append(f"Hostname: {platform.node()}")
        report.append("="*80)
        
        report.append("\n📋 ISOLATION ACTIONS TAKEN")
        report.append("-"*40)
        for action in self.actions_taken:
            status_symbol = "✓" if action['status'] == 'success' else "✗"
            report.append(f"{status_symbol} {action['timestamp']} - {action['action']}")
            if action.get('details'):
                report.append(f"    {action['details']}")
        
        if self.terminated_processes:
            report.append("\n🔪 TERMINATED PROCESSES")
            report.append("-"*40)
            for proc in self.terminated_processes:
                report.append(f"  • {proc['name']} (PID: {proc['pid']})")
        
        if self.isolated_hosts:
            report.append("\n🔒 ISOLATED HOSTS")
            report.append("-"*40)
            for host in self.isolated_hosts:
                report.append(f"  • {host}")
        
        report.append("\n📁 EVIDENCE LOCATION")
        report.append("-"*40)
        report.append(f"  {self.incident_dir.absolute()}")
        
        report.append("\n" + "="*80)
        report.append("END OF REPORT")
        report.append("="*80)
        
        report_text = "\n".join(report)
        
        # Save report
        with open(self.incident_dir / 'isolation_report.txt', 'w') as f:
            f.write(report_text)
        
        print(report_text)
        return report_text

def main():
    parser = argparse.ArgumentParser(description='Incident Isolation Script')
    parser.add_argument('--id', help='Incident ID')
    parser.add_argument('--isolate-network', action='store_true', help='Isolate from network')
    parser.add_argument('--interface', help='Network interface to isolate')
    parser.add_argument('--block-all', action='store_true', help='Block all network traffic')
    parser.add_argument('--kill-processes', nargs='+', help='Process names to terminate')
    parser.add_argument('--kill-all', action='store_true', help='Kill all non-system processes')
    parser.add_argument('--disable-accounts', nargs='+', help='Usernames to disable')
    parser.add_argument('--disable-non-admin', action='store_true', help='Disable non-admin accounts')
    parser.add_argument('--lockdown-paths', nargs='+', help='Paths to lockdown')
    parser.add_argument('--preserve-evidence', action='store_true', help='Preserve evidence')
    parser.add_argument('--snapshot', action='store_true', help='Create system snapshot')
    parser.add_argument('--auto', action='store_true', help='Run all isolation measures')
    
    args = parser.parse_args()
    
    isolator = IncidentIsolation(args.id)
    
    print(f"""
    ╔═══════════════════════════════════════╗
    ║     Incident Isolation Script v1.0    ║
    ╚═══════════════════════════════════════╝
    """)
    
    # Confirm action
    print(f"{'='*60}")
    print("⚠️  WARNING: This script will modify system settings!")
    print("⚠️  Only run during confirmed security incidents.")
    print(f"{'='*60}")
    
    response = input("\n[?] Continue with isolation? (yes/no): ").lower()
    if response != 'yes':
        print("[!] Isolation aborted")
        sys.exit(0)
    
    # Create snapshot first
    if args.snapshot or args.auto:
        isolator.create_snapshot()
    
    # Preserve evidence
    if args.preserve_evidence or args.auto:
        isolator.preserve_evidence()
    
    # Network isolation
    if args.isolate_network or args.auto:
        isolator.isolate_network(args.interface, args.block_all or args.auto)
    
    # Process termination
    if args.kill_processes or args.kill_all or args.auto:
        isolator.terminate_suspicious_processes(
            args.kill_processes,
            kill_all=args.kill_all or args.auto
        )
    
    # Account disablement
    if args.disable_accounts or args.disable_non_admin or args.auto:
        isolator.disable_accounts(
            args.disable_accounts,
            args.disable_non_admin or args.auto
        )
    
    # Filesystem lockdown
    if args.lockdown_paths or args.auto:
        isolator.lockdown_filesystem(args.lockdown_paths)
    
    # Generate report
    isolator.generate_report()
    
    print(f"\n[✓] Isolation complete. Incident ID: {isolator.incident_id}")
    print(f"    Log file: {isolator.log_file}")
    print(f"    Evidence directory: {isolator.incident_dir}")

if __name__ == "__main__":
    main()
