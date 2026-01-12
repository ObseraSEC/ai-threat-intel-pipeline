import requests
import json

UNSTRUCTURED_URL = "http://10.0.1.14:8000/general/v0/general"
PRESIDIO_URL = "http://10.0.1.17:3000/analyze" # Internal IP of Presidio container

def run_test():
    print("--- PIPELINE TEST: UNSTRUCTURED -> PRESIDIO ---")
    
    # 1. Unstructured Parsing
    print("\n[Step 1] Parsing HTML with Unstructured...")
    with open("scan_result_real.html", "rb") as f:
        r1 = requests.post(UNSTRUCTURED_URL, files={"files": ("scan_result_real.html", f)})
    
    if r1.status_code != 200:
        print(f"Unstructured Error: {r1.text}")
        return
        
    elements = r1.json()
    print(f"Extracted {len(elements)} elements.")
    
    # 2. Presidio Analysis
    print("\n[Step 2] Analyzing Text for PII with Presidio...")
    
    # We combine text to reduce API calls, or analyze line-by-line if needed.
    # For this test, let's analyze the first few 'NarrativeText' or 'Table' elements which likely contain real data.
    
    results_summary = []
    
    for el in elements:
        text = el.get("text", "")
        # Filter for meaningful text length to avoid analyzing "Name" or headers endlessly
        if len(text) > 15: 
            payload = {
                "text": text,
                "language": "en",
                "score_threshold": 0.4
            }
            
            try:
                r2 = requests.post(PRESIDIO_URL, json=payload, timeout=5)
                if r2.status_code == 200:
                    analysis = r2.json()
                    if analysis:
                        # Found something!
                        results_summary.append({
                            "original_text": text[:100] + "..." if len(text) > 100 else text,
                            "pii_detected": analysis
                        })
            except Exception as e:
                print(f"Presidio request failed: {e}")

    # 3. Report
    print(f"\n[Result] Found PII in {len(results_summary)} text segments.\n")
    print(json.dumps(results_summary, indent=2))

if __name__ == "__main__":
    run_test()
