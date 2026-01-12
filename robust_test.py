import requests
import json
import time

UNSTRUCTURED_URL = "http://10.0.1.14:8000/general/v0/general"
NORMALIZER_URL = "http://10.0.1.15:5050/normalize"

def run_test():
    print("--- STARTING ROBUST MASSIVE TEST ---")
    
    # 1. CLEANUP
    print("Step 1: Sending massive_intel.txt to Unstructured...")
    with open("massive_intel.txt", "rb") as f:
        r1 = requests.post(UNSTRUCTURED_URL, files={"files": f})
    
    if r1.status_code != 200:
        print(f"Error in Cleanup: {r1.text}")
        return
    
    clean_elements = r1.json()
    print(f"Cleanup successful. Extracted {len(clean_elements)} elements.")

    # 2. NORMALIZATION
    print("Step 2: Sending cleaned data to AI Normalizer (Llama 3.1 8B)...")
    payload = {
        "source_url": "massive-darkweb-dump",
        "elements": clean_elements[:100] # Start with 100 elements to avoid context clutter, can increase later
    }
    
    start_time = time.time()
    r2 = requests.post(NORMALIZER_URL, json=payload, timeout=120)
    end_time = time.time()

    if r2.status_code != 200:
        print(f"Error in Normalization: {r2.text}")
        return

    print(f"Normalization successful in {end_time - start_time:.2f} seconds.")
    print("\n--- FINAL STRUCTURED INTELLIGENCE (PREVIEW) ---")
    print(json.dumps(r2.json(), indent=2))

if __name__ == "__main__":
    run_test()
