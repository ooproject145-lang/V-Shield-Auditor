import xml.etree.ElementTree as ET

# This is the file we are scanning
filename = "sample_vm.vbox"

print("====================================")
print("   MIU VIRTUALIZATION AUDIT TOOL    ")
print("====================================")

try:
    # Open the file and look for security risks
    tree = ET.parse(filename)
    root = tree.getroot()
    
    # This is the "Namespace" VirtualBox uses
    ns = '{http://www.virtualbox.org/}'
    
    found = False
    for clipboard in root.iter(ns + 'Clipboard'):
        found = True
        mode = clipboard.get('mode')
        
        if mode == "Bidirectional":
            print("[!] SECURITY ALERT: Shared Clipboard is set to Bidirectional!")
            print("[#] SOLUTION: Disable clipboard sharing to prevent data theft.")
        else:
            print("[+] SUCCESS: Clipboard setting is secure.")

    if not found:
        print("[-] No clipboard settings found in this file.")

except FileNotFoundError:
    print(f"[X] ERROR: Could not find {filename}. Make sure it is in the same folder!")
except Exception as e:
    print(f"[X] ERROR: {e}")

print("====================================")
input("SCAN FINISHED. Press ENTER to exit...")