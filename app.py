import time
from flask import Flask, render_template, jsonify
import xml.etree.ElementTree as ET

app = Flask(__name__)

def run_audit():
    # This is the 'Logic' that scans the file
    filename = "sample_vm.vbox"
    ns = '{http://www.virtualbox.org/}'
    findings = []
    
    try:
        tree = ET.parse(filename)
        root = tree.getroot()
        
        # Risk 1: Clipboard
        for cb in root.iter(ns + 'Clipboard'):
            if cb.get('mode') == "Bidirectional":
                findings.append({
                    "level": "HIGH", 
                    "title": "Data Exfiltration Path",
                    "msg": "Bidirectional clipboard allows malware to move from Guest to Host.",
                    "fix": "Set Clipboard to 'HostToGuest' or 'Disabled'."
                })
        
        # Risk 2: Remote Display
        for rd in root.iter(ns + 'RemoteDisplay'):
            if rd.get('enabled') == "true" and rd.get('authType') == "Null":
                findings.append({
                    "level": "CRITICAL", 
                    "title": "Unauthorized Access Point",
                    "msg": "Remote Display is active with NO authentication.",
                    "fix": "Enable 'External' or 'Password' authentication."
                })

        if not findings:
            findings.append({"level": "SAFE", "title": "System Hardened", "msg": "No vulnerabilities found."})
            
    except Exception as e:
        findings.append({"level": "ERROR", "title": "Audit Failure", "msg": str(e)})
    
    return findings

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan():
    # Simulate a real system scan delay
    time.sleep(2) 
    results = run_audit()
    return jsonify(results)

if __name__ == '__main__':
    # host='0.0.0.0' allows other devices on your Wi-Fi to connect
    app.run(host='0.0.0.0', port=5000, debug=True)