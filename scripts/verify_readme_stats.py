#!/usr/bin/env python3
import re
from pathlib import Path
from datetime import datetime

def verify_readme():
    readme_path = Path('README.md')
    if not readme_path.exists():
        print("❌ README.md not found!")
        return False
    
    with open(readme_path, 'r') as f:
        content = f.read()
    
    # Check for statistics section
    stats_pattern = r'## 📊 Repository Statistics.*?(\|.*\|.*\|)+.*?\n\n'
    stats_match = re.search(stats_pattern, content, re.DOTALL)
    
    if not stats_match:
        print("❌ Statistics section not found!")
        return False
    
    print("✅ Statistics section found")
    
    # Extract the table
    table = stats_match.group(0)
    print("\n📊 Current Statistics:")
    print("-" * 40)
    print(table)
    
    # Check for last updated timestamp
    timestamp_pattern = r'\*Last updated: (.*?)\*'
    timestamp_match = re.search(timestamp_pattern, content)
    
    if timestamp_match:
        timestamp = timestamp_match.group(1)
        print(f"✅ Last updated: {timestamp}")
        
        # Check if it's recent
        if 'Auto-updated' in timestamp:
            print("✅ Auto-update working")
    else:
        print("❌ No timestamp found!")
    
    # Check for progress bar
    if 'progress-bar.dev' in content:
        print("✅ Progress bar found")
    else:
        print("❌ Progress bar missing")
    
    # Check for badges
    badges = ['[![Python]', '[![Shell]', '[![Docs]', '[![Sections]']
    for badge in badges:
        if badge in content:
            print(f"✅ {badge[4:10]} badge found")
    
    return True

if __name__ == "__main__":
    verify_readme()
