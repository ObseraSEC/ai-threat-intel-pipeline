import requests
import json
import time

UNSTRUCTURED_URL = "http://10.0.1.14:8000/general/v0/general"
NORMALIZER_URL = "http://10.0.1.15:5050/normalize"

THREAT_SCENARIOS = [
    {
        "source": "CISA-ALERT-2026-044",
        "text": """
        Alert (AA26-044A): BlackCat Ransomware Affiliates Targeting Critical Infrastructure
        The FBI and CISA have observed BlackCat (ALPHV) affiliates targeting the energy sector.
        Indicators of Compromise:
        - IP: 149.102.10.11 (C2 Server)
        - IP: 198.51.100.2 (Exfiltration Node)
        - Domain: alphv-pay-site.onion
        - Hash: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
        Techniques:
        - T1190 - Exploit Public-Facing Application
        - T1059 - Command and Scripting Interpreter: PowerShell
        """
    },
    {
        "source": "INTERNAL-SOC-TICKET-992",
        "text": """
        Incident: Insider Data Exfiltration [DETECTED]
        User: sarah.jones@corp-example.internal
        Date: 2026-01-12 14:00 UTC
        Details:
        User attempted to upload 450MB of manufacturing schematics to 'dropbox-personal-upload.com'.
        DLP Blocked the transaction.
        IP Address: 10.20.1.55 (Internal Workstation)
        Action Taken: Account suspended, device isolated.
        """
    },
    {
        "source": "DARKWEB-MONITOR-BOT-02",
        "text": """
        [SALE] 50,000 Credit Cards - Chase / BofA
        Seller: CardMaster99
        Price: 0.05 BTC
        Sample Data:
        - 4147 2022 3030 1010 | Exp 09/27 | CVV 992
        - Name: Michael Smith | Zip: 90210
        Contact me on Jabber: cardmaster@jabber.calyxinstitute.org
        Forum: BreachForums v3
        """
    },
    {
        "source": "PHISHING-REPORT-FINANCE",
        "text": """
        Subject: URGENT: Q4 Invoice Overdue - Action Required
        From: billing@vendor-support-portal.net (Spoofing internal domain)
        Target: finance-dept@obserasec.com
        Analysis:
        Email contained a PDF with embedded javascript dropper.
        Malicious URL: http://vendor-support-portal.net/login.php?ref=invoice
        Payload: Dridex Banking Trojan
        """
    },
    {
        "source": "APT-INTEL-GROUP-8",
        "text": """
        Campaign: Operation "Silent Dragon"
        Actor: APT41
        Targets: Healthcare providers in SE Asia
        Modus Operandi: Supply chain attack via compromised software update mechanism of 'HealthCure ERP'.
        C2 Infrastructure:
        - update-healthcure.com
        - 45.33.22.11
        - 103.11.22.33
        Status: Active infection observed.
        """
    }
]

def ingest_scenarios():
    print("--- INGESTING REAL THREAT SCENARIOS ---")
    
    for i, scenario in enumerate(THREAT_SCENARIOS):
        print(f"\nProcessing Scenario {i+1}: {scenario['source']}...")
        
        # 1. Unstructured Parsing (Simulating file upload by sending text as file)
        # We need to save to a temp file first because Unstructured API expects a file
        temp_filename = f"temp_scenario_{i}.txt"
        with open(temp_filename, "w") as f:
            f.write(scenario["text"])
            
        with open(temp_filename, "rb") as f:
            files = {'files': (temp_filename, f)}
            try:
                r1 = requests.post(UNSTRUCTURED_URL, files=files, timeout=30)
                r1.raise_for_status()
                clean_json = r1.json()
            except Exception as e:
                print(f"xx Unstructured Failed: {e}")
                continue

        # 2. Normalization & Indexing
        payload = {
            "source_url": scenario["source"],
            "elements": clean_json
        }
        
        try:
            r2 = requests.post(NORMALIZER_URL, json=payload, timeout=60)
            if r2.status_code == 200:
                data = r2.json()
                print(f"vv Indexed Success! DB_ID: {data.get('db_id')}")
                print(f"   Summary: {data['structured_intel'].get('summary')}")
                print(f"   Category: {data['structured_intel'].get('threat_category')}")
            else:
                print(f"xx Normalizer Failed: {r2.text}")
        except Exception as e:
            print(f"xx Normalizer Connection Failed: {e}")
            
        time.sleep(1) # Be nice to the API

    print("\n--- INGESTION COMPLETE ---")

if __name__ == "__main__":
    ingest_scenarios()
