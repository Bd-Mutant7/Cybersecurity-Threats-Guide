#!/usr/bin/env python3
"""
Disk Forensics Analyzer
Location: 06-incident-response/forensics/disk_forensics.py

This script analyzes disk images and file systems for forensic evidence including:
- Deleted file recovery
- File system timeline analysis
- Metadata extraction
- Suspicious file detection
- Hash analysis against known malware
"""

import os
import sys
import hashlib
import argparse
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import platform
import subprocess
import re
import shutil
from collections import defaultdict

class DiskForensics:
    """
    Disk and File System Forensics Analyzer
    """
    
    def __init__(self, image_path=None, mount_point=None):
        """
        Initialize disk forensics analyzer
        
        Args:
            image_path: Path to disk image (dd, e01, raw)
            mount_point: Mount point for analysis
        """
        self.image_path = image_path
        self.mount_point = mount_point
        self.system = platform.system()
        self.evidence = {
            'case_info': {
                'analyzer': 'Disk Forensics Tool',
                'timestamp': datetime.now().isoformat(),
                'image': image_path,
                'system': self.system
            },
            'file_system': {},
            'files': [],
            'deleted_files': [],
            'suspicious_files': [],
            'timeline': [],
            'artifacts': {}
        }
        
        # Known malware hashes (simplified - in production, use VirusTotal API)
        self.malware_hashes = {
            'eicar': '44d88612fea8a8f36de82e1278abb02f',  # EICAR test signature
            'test': 'd41d8cd98f00b204e9800998ecf8427e'
        }
        
        # Suspicious file extensions
        self.suspicious_extensions = [
            '.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.ps1',
            '.js', '.jar', '.docm', '.xlsm', '.pptm', '.hta'
        ]
        
    def get_file_system_info(self):
        """Get file system information"""
        print("[*] Analyzing file system...")
        
        if self.system == 'Windows':
            # Use fsutil on Windows
            try:
                result = subprocess.run(['fsutil', 'fsinfo', 'drives'],
                                       capture_output=True, text=True)
                drives = result.stdout
                self.evidence['file_system']['drives'] = drives
            except:
                pass
        
        # Get disk usage
        if self.image_path and os.path.exists(self.image_path):
            stat = os.stat(self.image_path)
            self.evidence['file_system']['image_size'] = stat.st_size
            self.evidence['file_system']['image_modified'] = datetime.fromtimestamp(
                stat.st_mtime).isoformat()
    
    def scan_files(self, path, recursive=True):
        """Scan files in directory"""
        print(f"[*] Scanning files in {path}...")
        
        files = []
        base_path = Path(path)
        
        if recursive:
            for root, dirs, filenames in os.walk(base_path):
                # Skip system directories
                dirs[:] = [d for d in dirs if not d.startswith('$')]
                
                for filename in filenames:
                    filepath = Path(root) / filename
                    file_info = self.analyze_file(filepath)
                    if file_info:
                        files.append(file_info)
        else:
            for item in base_path.iterdir():
                if item.is_file():
                    file_info = self.analyze_file(item)
                    if file_info:
                        files.append(file_info)
        
        self.evidence['files'] = files
        return files
    
    def analyze_file(self, filepath):
        """Analyze a single file"""
        try:
            stat = filepath.stat()
            
            # Calculate hashes
            md5_hash = self.calculate_hash(filepath, 'md5')
            sha1_hash = self.calculate_hash(filepath, 'sha1')
            sha256_hash = self.calculate_hash(filepath, 'sha256')
            
            file_info = {
                'path': str(filepath),
                'name': filepath.name,
                'extension': filepath.suffix.lower(),
                'size': stat.st_size,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash,
                'is_hidden': filepath.name.startswith('.') or self.is_hidden_windows(filepath),
                'permissions': oct(stat.st_mode)[-3:]
            }
            
            # Check if suspicious
            if self.is_suspicious_file(file_info):
                file_info['suspicious'] = True
                file_info['suspicious_reasons'] = self.get_suspicious_reasons(file_info)
                self.evidence['suspicious_files'].append(file_info)
            
            # Check against known malware
            if sha256_hash in self.malware_hashes or md5_hash in self.malware_hashes.values():
                file_info['malware_match'] = True
                self.evidence['suspicious_files'].append(file_info)
            
            return file_info
            
        except (PermissionError, OSError) as e:
            return None
    
    def calculate_hash(self, filepath, algorithm='sha256'):
        """Calculate file hash"""
        hash_func = getattr(hashlib, algorithm)()
        
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except:
            return None
    
    def is_hidden_windows(self, filepath):
        """Check if file is hidden on Windows"""
        if self.system == 'Windows':
            try:
                attrs = os.stat(filepath).st_file_attributes
                return attrs & 2  # FILE_ATTRIBUTE_HIDDEN
            except:
                pass
        return False
    
    def is_suspicious_file(self, file_info):
        """Determine if file is suspicious"""
        reasons = []
        
        # Check extension
        if file_info['extension'] in self.suspicious_extensions:
            reasons.append(f"Suspicious extension: {file_info['extension']}")
        
        # Check location
        path_lower = file_info['path'].lower()
        suspicious_paths = ['\\temp\\', '\\tmp\\', '\\appdata\\', '\\programdata\\']
        for sp in suspicious_paths:
            if sp in path_lower:
                reasons.append(f"Suspicious location: {sp}")
        
        # Check for double extensions
        if '.' in file_info['name'][:-4]:  # e.g., "document.pdf.exe"
            reasons.append("Double extension (possible masquerading)")
        
        # Check file size (very small executables)
        if file_info['extension'] in ['.exe', '.dll'] and file_info['size'] < 10240:
            reasons.append(f"Unusually small executable: {file_info['size']} bytes")
        
        return len(reasons) > 0
    
    def get_suspicious_reasons(self, file_info):
        """Get reasons why file is suspicious"""
        reasons = []
        
        if file_info['extension'] in self.suspicious_extensions:
            reasons.append(f"Extension: {file_info['extension']}")
        
        path_lower = file_info['path'].lower()
        if '\\temp\\' in path_lower:
            reasons.append("Located in Temp folder")
        if '\\appdata\\' in path_lower:
            reasons.append("Located in AppData")
        
        if '.' in file_info['name'][:-4]:
            reasons.append("Double extension detected")
        
        return reasons
    
    def find_deleted_files(self, image_path):
        """
        Attempt to recover deleted files
        Note: This is a simplified version - in production, use tools like testdisk
        """
        print("[*] Scanning for deleted files...")
        
        # This would normally parse MFT entries, inodes, etc.
        # For demonstration, we'll just note that this requires specialized tools
        
        self.evidence['deleted_files'].append({
            'note': 'Deep deleted file recovery requires specialized tools',
            'tools': ['testdisk', 'photorec', 'scalpel', 'foremost']
        })
        
        # Try to use photorec if available
        if shutil.which('photorec'):
            print("[!] PhotoRec detected. Run manually for deep recovery:")
            print(f"    sudo photorec {image_path}")
    
    def create_timeline(self, files):
        """Create timeline of file activity"""
        print("[*] Creating file activity timeline...")
        
        timeline = []
        
        for file_info in files:
            timeline.append({
                'timestamp': file_info['created'],
                'event': 'created',
                'file': file_info['path']
            })
            timeline.append({
                'timestamp': file_info['modified'],
                'event': 'modified',
                'file': file_info['path']
            })
            timeline.append({
                'timestamp': file_info['accessed'],
                'event': 'accessed',
                'file': file_info['path']
            })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x['timestamp'])
        
        self.evidence['timeline'] = timeline[:100]  # First 100 events
        return timeline
    
    def extract_artifacts(self, mount_point):
        """Extract common forensic artifacts"""
        print("[*] Extracting forensic artifacts...")
        
        artifacts = {}
        
        # Windows artifacts
        if self.system == 'Windows' or (mount_point and 'Windows' in str(mount_point)):
            # Prefetch files
            prefetch_path = Path(mount_point) / 'Windows' / 'Prefetch'
            if prefetch_path.exists():
                artifacts['prefetch'] = [str(p) for p in prefetch_path.glob('*.pf')]
            
            # Event logs
            eventlog_path = Path(mount_point) / 'Windows' / 'System32' / 'winevt' / 'Logs'
            if eventlog_path.exists():
                artifacts['event_logs'] = [str(p) for p in eventlog_path.glob('*.evtx')]
            
            # Registry hives
            system32_path = Path(mount_point) / 'Windows' / 'System32' / 'config'
            if system32_path.exists():
                artifacts['registry'] = [str(p) for p in system32_path.glob('*') 
                                       if p.suffix in ['', '.log']]
            
            # User profiles
            users_path = Path(mount_point) / 'Users'
            if users_path.exists():
                artifacts['users'] = [str(p) for p in users_path.iterdir() if p.is_dir()]
        
        # Linux artifacts
        else:
            # Bash history
            for user_dir in Path(mount_point).glob('home/*'):
                bash_history = user_dir / '.bash_history'
                if bash_history.exists():
                    artifacts[f'bash_history_{user_dir.name}'] = str(bash_history)
            
            # Auth logs
            var_log = Path(mount_point) / 'var' / 'log'
            if var_log.exists():
                artifacts['logs'] = [str(p) for p in var_log.glob('*') 
                                   if 'auth' in p.name or 'secure' in p.name]
            
            # Cron jobs
            etc = Path(mount_point) / 'etc'
            if etc.exists():
                artifacts['cron'] = [str(p) for p in etc.glob('cron*')]
        
        self.evidence['artifacts'] = artifacts
        return artifacts
    
    def analyze_browser_history(self, mount_point):
        """Analyze browser history artifacts"""
        print("[*] Analyzing browser history...")
        
        browser_data = []
        
        # Chrome/Chromium history
        chrome_patterns = [
            '**/AppData/Local/Google/Chrome/User Data/Default/History',
            '**/.config/google-chrome/Default/History',
            '**/.config/chromium/Default/History'
        ]
        
        for pattern in chrome_patterns:
            for history_file in Path(mount_point).glob(pattern):
                if history_file.exists():
                    try:
                        # Copy file to temp to avoid locking
                        temp_db = f"/tmp/chrome_history_{datetime.now().timestamp()}.db"
                        shutil.copy2(history_file, temp_db)
                        
                        conn = sqlite3.connect(temp_db)
                        cursor = conn.cursor()
                        
                        # Query URLs
                        cursor.execute("""
                            SELECT url, title, visit_count, last_visit_time 
                            FROM urls ORDER BY last_visit_time DESC LIMIT 50
                        """)
                        
                        for row in cursor.fetchall():
                            browser_data.append({
                                'browser': 'Chrome',
                                'url': row[0],
                                'title': row[1],
                                'visits': row[2],
                                'last_visit': row[3]
                            })
                        
                        conn.close()
                        os.remove(temp_db)
                        
                    except Exception as e:
                        print(f"[!] Error reading Chrome history: {e}")
        
        # Firefox history
        firefox_patterns = ['**/.mozilla/firefox/*.default/places.sqlite']
        
        for pattern in firefox_patterns:
            for history_file in Path(mount_point).glob(pattern):
                if history_file.exists():
                    try:
                        temp_db = f"/tmp/firefox_history_{datetime.now().timestamp()}.db"
                        shutil.copy2(history_file, temp_db)
                        
                        conn = sqlite3.connect(temp_db)
                        cursor = conn.cursor()
                        
                        # Query moz_places
                        cursor.execute("""
                            SELECT url, title, visit_count, last_visit_date 
                            FROM moz_places ORDER BY last_visit_date DESC LIMIT 50
                        """)
                        
                        for row in cursor.fetchall():
                            browser_data.append({
                                'browser': 'Firefox',
                                'url': row[0],
                                'title': row[1],
                                'visits': row[2],
                                'last_visit': row[3]
                            })
                        
                        conn.close()
                        os.remove(temp_db)
                        
                    except Exception as e:
                        print(f"[!] Error reading Firefox history: {e}")
        
        return browser_data
    
    def generate_report(self, output_file=None):
        """Generate forensic analysis report"""
        report = []
        report.append("="*80)
        report.append("DISK FORENSICS ANALYSIS REPORT")
        report.append("="*80)
        report.append(f"Case ID: {datetime.now().strftime('%Y%m%d_%H%M%S')}")
        report.append(f"Analyzer: Disk Forensics Tool v1.0")
        report.append(f"Timestamp: {self.evidence['case_info']['timestamp']}")
        report.append(f"Image: {self.image_path}")
        report.append("="*80)
        
        # File System Summary
        report.append("\n📁 FILE SYSTEM SUMMARY")
        report.append("-"*40)
        if self.evidence['file_system']:
            for key, value in self.evidence['file_system'].items():
                report.append(f"  {key}: {value}")
        
        # File Statistics
        report.append("\n📊 FILE STATISTICS")
        report.append("-"*40)
        total_files = len(self.evidence['files'])
        total_size = sum(f.get('size', 0) for f in self.evidence['files'])
        report.append(f"  Total Files Scanned: {total_files}")
        report.append(f"  Total Size: {self.format_size(total_size)}")
        report.append(f"  Suspicious Files: {len(self.evidence['suspicious_files'])}")
        
        # Suspicious Files
        if self.evidence['suspicious_files']:
            report.append("\n⚠️ SUSPICIOUS FILES")
            report.append("-"*40)
            for f in self.evidence['suspicious_files'][:20]:
                report.append(f"  • {f['name']} ({f['path']})")
                if 'suspicious_reasons' in f:
                    for reason in f['suspicious_reasons']:
                        report.append(f"      - {reason}")
        
        # Artifacts
        if self.evidence['artifacts']:
            report.append("\n🔍 FORENSIC ARTIFACTS")
            report.append("-"*40)
            for artifact_type, paths in self.evidence['artifacts'].items():
                report.append(f"  {artifact_type}:")
                for path in paths[:5]:
                    report.append(f"    • {path}")
        
        # Timeline (first 20 events)
        if self.evidence['timeline']:
            report.append("\n⏱️ TIMELINE (First 20 Events)")
            report.append("-"*40)
            for event in self.evidence['timeline'][:20]:
                report.append(f"  {event['timestamp']} - {event['event']} - {event['file']}")
        
        report.append("\n" + "="*80)
        report.append("END OF REPORT")
        report.append("="*80)
        
        report_text = "\n".join(report)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_text)
            print(f"[✓] Report saved to {output_file}")
        
        return report_text
    
    def format_size(self, size):
        """Format file size"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    
    def run_analysis(self):
        """Run complete disk forensics analysis"""
        print(f"""
        ╔═══════════════════════════════════════╗
        ║     Disk Forensics Analyzer v1.0      ║
        ╚═══════════════════════════════════════╝
        """)
        
        self.get_file_system_info()
        
        if self.image_path and os.path.exists(self.image_path):
            print(f"[*] Analyzing image: {self.image_path}")
            
            # For disk images, we'd need to mount them
            print("[!] For full analysis, mount the image first:")
            print(f"    sudo mount -o loop,ro {self.image_path} /mnt/forensics")
            
            if self.mount_point and os.path.exists(self.mount_point):
                files = self.scan_files(self.mount_point)
                self.create_timeline(files)
                self.extract_artifacts(self.mount_point)
                self.find_deleted_files(self.image_path)
        
        elif self.mount_point and os.path.exists(self.mount_point):
            print(f"[*] Analyzing mount point: {self.mount_point}")
            files = self.scan_files(self.mount_point)
            self.create_timeline(files)
            self.extract_artifacts(self.mount_point)
        
        else:
            print("[!] No valid image or mount point provided")
            return
        
        return self.evidence

def main():
    parser = argparse.ArgumentParser(description='Disk Forensics Analyzer')
    parser.add_argument('-i', '--image', help='Disk image file')
    parser.add_argument('-m', '--mount', help='Mount point for analysis')
    parser.add_argument('-o', '--output', help='Output report file')
    parser.add_argument('--quick', action='store_true', help='Quick scan (non-recursive)')
    
    args = parser.parse_args()
    
    if not args.image and not args.mount:
        print("[!] Either --image or --mount required")
        parser.print_help()
        sys.exit(1)
    
    analyzer = DiskForensics(args.image, args.mount)
    analyzer.run_analysis()
    
    report = analyzer.generate_report(args.output)
    print(report)

if __name__ == "__main__":
    main()
