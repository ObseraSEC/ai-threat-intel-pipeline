import requests
import json
import time
import random

UNSTRUCTURED_URL = "http://10.0.1.14:8000/general/v0/general"
NORMALIZER_URL = "http://10.0.1.15:5050/normalize"

# Extended varied threat scenarios
THREAT_SCENARIOS = [
    {
        "source": "CISA-ALERT-2026-044",
        "category": "Ransomware",
        "text": """
        Alert (AA26-044A): BlackCat Ransomware Affiliates Targeting Energy Sector.
        Indicators:
        - IP: 149.102.10.11
        - Domain: alphv-pay-site.onion
        Techniques: PowerShell, T1190.
        """
    },
    {
        "source": "INTERNAL-DLP-LOG-992",
        "category": "Leak",
        "text": """
        Incident: Insider Data Exfiltration [BLOCK].
        User: sarah.jones@corp.internal attempted upload to dropbox-personal-upload.com.
        IP: 10.20.1.55.
        """
    },
    {
        "source": "DARKWEB-Z-MARKET",
        "category": "Leak",
        "text": """
        [SALE] 50,000 Credit Cards - Chase / BofA.
        Seller: CardMaster99.
        Sample: 4147 2022 3030 1010 | Exp 09/27.
        Contact: cardmaster@jabber.calyxinstitute.org.
        """
    },
    {
        "source": "EMAIL-GATEWAY-BLOCK",
        "category": "Phishing",
        "text": """
        Subject: URGENT: Invoice Overdue.
        From: billing@vendor-support-portal.net.
        Malicious URL: http://vendor-support-portal.net/login.php?ref=invoice.
        Payload: Dridex.
        """
    },
    {
        "source": "FW-LOG-2026-01-12",
        "category": "Botnet",
        "text": """
        [CRITICAL] Outbound connection detected to known C2.
        Src: 192.168.100.15 (HR-Desktop).
        Dst: 85.11.22.33 (Mirai-C2).
        Port: 6667 (IRC).
        Action: Blocked.
        """
    },
    {
        "source": "AWS-GUARDDUTY-ALERT",
        "category": "CryptoMining",
        "text": """
        Finding: EC2 instance i-0123456789abcdef0 querying crypto mining pool.
        Domain: xmr.pool.minergate.com.
        IP: 18.22.33.44.
        """
    },
    {
        "source": "SOC-ALERT-SQLI",
        "category": "Web Attack",
        "text": """
        Attack detected on public web server.
        Payload: ' OR 1=1; DROP TABLE users; --
        Src IP: 203.0.113.55.
        User-Agent: sqlmap/1.4.
        """
    },
    {
        "source": "SSH-AUTH-LOG",
        "category": "Brute Force",
        "text": """
        Failed password for root from 116.31.116.16 port 22.
        Failed password for root from 116.31.116.16 port 22.
        Failed password for root from 116.31.116.16 port 22.
        REPEATED 500 TIMES.
        """
    },
     {
        "source": "CROWDSTRIKE-INTEL",
        "category": "APT",
        "text": """
        Actor: FANCY BEAR (APT28).
        Target: Government Agency.
        Implant: XAgent.
        C2 IP: 89.44.33.22.
        Domain: nato-defense-portal.com.
        """
    }
]

def ingest_scenarios():
    print(f"--- INGESTING {len(THREAT_SCENARIOS)} REAL THREAT SCENARIOS ---")
    
    for i, scenario in enumerate(THREAT_SCENARIOS):
        source = scenario["source"]
        print(f"\n[{i+1}/{len(THREAT_SCENARIOS)}] Processing {source} ({scenario['category']})...")
        
        # 1. Unstructured Parsing
        temp_filename = f"temp_scenario_{i}.txt"
        with open(temp_filename, "w") as f:
            f.write(scenario["text"])
            
        with open(temp_filename, "rb") as f:
            files = {'files': (temp_filename, f)}
            try:
                r1 = requests.post(UNSTRUCTURED_URL, files=files, timeout=30)
                if r1.status_code != 200:
                    print(f"xx Unstructured error: {r1.text}")
                    continue
                clean_json = r1.json()
            except Exception as e:
                print(f"xx Unstructured Failed: {e}")
                continue

        # 2. Normalization & Indexing
        payload = {
            "source_url": source,
            "elements": clean_json
        }
        
        try:
            r2 = requests.post(NORMALIZER_URL, json=payload, timeout=60)
            if r2.status_code == 200:
                data = r2.json()
                print(f"vv Indexed! ID: {data.get('db_id')} | Conf: {data.get('structured_intel', {}).get('confidence_score')}")
            else:
                print(f"xx Normalizer Failed: {r2.text}")
        except Exception as e:
            print(f"xx Normalizer Connection Failed: {e}")
            
        time.sleep(0.5) 

    print("\n--- INGESTION COMPLETE ---")

if __name__ == "__main__":
    ingest_scenarios()
