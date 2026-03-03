#!/usr/bin/env python3
"""
Run the Cybersecurity Toolkit Application
"""

import os
import sys
from app import app, socketio

if __name__ == '__main__':
    # Get port from environment or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Get debug mode from environment
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     Cybersecurity Toolkit Web Application                    ║
║     All-in-one security analysis platform                    ║
║                                                               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    print(f"[*] Starting server on port {port}")
    print(f"[*] Debug mode: {debug}")
    print("[*] Access the application at: http://localhost:5000")
    print("[*] Press Ctrl+C to stop\n")
    
    # Run the application
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=debug,
        allow_unsafe_werkzeug=True
    )
