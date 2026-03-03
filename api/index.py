from flask import Flask, request, jsonify
import uuid
import time
import random

app = Flask(__name__)

# In-memory storage (Vercel doesn't persist this between function calls)
# For production, use a database like Vercel Postgres or Upstash Redis
active_scans = {}

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'message': 'Cybersecurity Toolkit API is running',
        'version': '1.0.0'
    })

@app.route('/api/tools', methods=['GET'])
def list_tools():
    """List all available security tools"""
    tools = [
        {'id': 'ddos', 'name': 'DDoS Detector', 'category': 'network'},
        {'id': 'sqli', 'name': 'SQL Injection Scanner', 'category': 'webapp'},
        {'id': 'phishing', 'name': 'Phishing Detector', 'category': 'social'},
    ]
    return jsonify({'tools': tools})

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a scan (synchronous for Vercel)"""
    data = request.json
    tool_id = data.get('tool_id')
    parameters = data.get('parameters', {})
    
    scan_id = str(uuid.uuid4())
    
    # Simulate scan (keep it under 10 seconds!)
    if tool_id == 'ddos':
        result = {
            'scan_id': scan_id,
            'tool': tool_id,
            'status': 'completed',
            'threats_found': random.randint(0, 3),
            'results': {
                'packet_count': random.randint(1000, 5000),
                'findings': ['SYN flood detected'] if random.random() > 0.5 else []
            }
        }
    else:
        result = {
            'scan_id': scan_id,
            'tool': tool_id,
            'status': 'completed',
            'threats_found': random.randint(0, 2),
            'results': {'message': 'Scan completed'}
        }
    
    return jsonify(result)

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get scan results"""
    # In real app, fetch from database
    return jsonify({
        'scan_id': scan_id,
        'status': 'completed',
        'result': 'Sample result'
    })

# Vercel serverless handler
def handler(request):
    """Vercel serverless function handler"""
    with app.request_context(request.environ):
        return app.full_dispatch_request()

# For local development
if __name__ == '__main__':
    app.run(port=5000, debug=True)
