import requests
import json
import subprocess
import time

# Configuration
SPIDERFOOT_CMD = "echo r00tr00t | sudo -S docker exec spiderfoot python3 sf.py -s example.com -m sfp_whois -o json"
NORMALIZER_URL = "http://10.0.1.15:5050/normalize"

def run_spiderfoot_pipeline():
    print("--- SPIDERFOOT -> AI PIPELINE TEST ---")
    
    # 1. Run Spiderfoot Scan
    print("[Step 1] Running Spiderfoot Scan on 'example.com' (Module: sfp_whois)...")
    # For this test, we mock the output to avoid re-running the Docker command in Python which is complex with sudo/ssh
    # usage. In prod, this would be an API call or queue.
    
    spiderfoot_raw_output = """
    {"generated": 1768203357, "type": "Internet Name", "data": "example.com", "module": "SpiderFoot UI", "source": "example.com"}
    {"generated": 1768203358, "type": "Domain Whois", "data": "Domain Name: EXAMPLE.COM\\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN\\nRegistrar WHOIS Server: whois.iana.org\\nUpdated Date: 2025-12-16T17:28:41Z\\nCreation Date: 1995-08-14T04:00:00Z\\nRegistry Expiry Date: 2026-08-13T04:00:00Z\\nRegistrar: RESERVED-Internet Assigned Numbers Authority\\nName Server: ELLIOTT.NS.CLOUDFLARE.COM\\nName Server: HERA.NS.CLOUDFLARE.COM", "module": "sfp_whois", "source": "example.com"}
    """
    
    # Extract the relevant raw text from the JSON stream
    relevant_text = []
    for line in spiderfoot_raw_output.strip().split('\n'):
        try:
            obj = json.loads(line)
            if obj.get("type") == "Domain Whois":
                relevant_text.append(obj.get("data"))
        except:
            continue
            
    full_text = "\n".join(relevant_text)
    print(f"Extracted {len(full_text)} bytes of WHOIS data.")

    # 2. Normalize with AI
    print("[Step 2] Sending to AI Normalizer...")
    
    # We construct the payload manually as if Unstructured had parsed it (Unstructured 'NarrativeText')
    payload = {
        "source_url": "spiderfoot:example.com",
        "elements": [
            {
                "type": "NarrativeText",
                "text": full_text
            }
        ]
    }
    
    try:
        r = requests.post(NORMALIZER_URL, json=payload, timeout=60)
        if r.status_code == 200:
            print("\n[SUCCESS] AI Normalizer Result:")
            print(json.dumps(r.json(), indent=2))
        else:
            print(f"[ERROR] Normalizer failed: {r.text}")
    except Exception as e:
        print(f"[ERROR] Connection failed: {e}")

if __name__ == "__main__":
    run_spiderfoot_pipeline()
