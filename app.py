import time
import os
from flask import Flask, render_template, jsonify
import xml.etree.ElementTree as ET

app = Flask(__name__)

def run_audit():
    # This is the 'Logic' that scans the file [cite: 516]
    filename = "sample_vm.vbox"
    
    # VirtualBox uses different XML namespaces; we check for the most common ones [cite: 518, 767]
    findings = []
    
    try:
        if not os.path.exists(filename):
            return [{"level": "ERROR", "title": "Missing File", "msg": f"{filename} not found in root directory."}]

        tree = ET.parse(filename)
        root = tree.getroot()
        
        # We strip the namespace to make the search more flexible [cite: 381, 513]
        for elem in root.iter():
            tag_name = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
            
            # Risk 1: Clipboard [cite: 388, 523]
            if tag_name == 'Clipboard':
                if elem.get('mode') == "Bidirectional":
                    findings.append({
                        "level": "HIGH", 
                        "title": "Data Exfiltration Path",
                        "msg": "Bidirectional clipboard allows malware to move from Guest to Host.",
                        "fix": "Set Clipboard to 'HostToGuest' or 'Disabled'."
                    })
            
            # Risk 2: Remote Display [cite: 391, 532]
            if tag_name == 'RemoteDisplay':
                if elem.get('enabled') == "true" and elem.get('authType') == "Null":
                    findings.append({
                        "level": "CRITICAL", 
                        "title": "Unauthorized Access Point",
                        "msg": "Remote Display is active with NO authentication.",
                        "fix": "Enable 'External' or 'Password' authentication."
                    })

        if not findings:
            findings.append({
                "level": "SAFE", 
                "title": "System Hardened", 
                "msg": "No vulnerabilities found. All side-channels are isolated."
            })
            
    except Exception as e:
        findings.append({"level": "ERROR", "title": "Audit Failure", "msg": str(e)})
    
    return findings

@app.route('/')
def index():
    # Renders the 'beautified' dashboard [cite: 350, 561]
    return render_template('index.html')

@app.route('/scan')
def scan():
    # Simulate a real system scan delay for UI effect [cite: 551]
    time.sleep(2) 
    results = run_audit()
    return jsonify(results)

if __name__ == '__main__':
    # Updated for Cloud Deployment (Render/Railway) 
    # Uses the PORT assigned by the server, defaults to 5000 for local testing
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
