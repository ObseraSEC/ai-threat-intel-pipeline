import requests
import json
import time

# -- CONFIGURATION --
# This assumes OpenSearch Dashboards is running on port 5601
# In a real environment, this might need internal network access or localhost port forward
KIBANA_URL = "http://10.0.1.15:5601" # This won't work from the Normalizer container, accessing via internal IP or host
# The user's prompt implies we are running these scripts on the host or inside the pipeline network.
# Let's assume we run this FROM the normalizer container or host targeting the Dashboards container IP.
# We'll use the IP we found earlier for Dashboards or rely on 'opensearch-dashboards' hostname if in Docker network.

# Since we are running via ssh on host, we need to know where Dashboards is listening.
# Based on previous `docker ps`, Dashboards is on `opensearch-dashboards-q0wwcsc8kwowsowk4ksck4wo`.
# We need its internal IP.

OPENSEARCH_DASHBOARDS_URL = "http://10.0.15.3:5601" # We will verify this IP in the run_command step
INDEX_PATTERN_TITLE = "threat_intel_v1"
TIME_FIELD = "timestamp"

HEADERS = {
    "kbn-xsrf": "true",
    "Content-Type": "application/json",
    "osd-xsrf": "true" 
}

def setup_dashboards():
    print("--- AUTO-CONFIGURING OPENSEARCH DASHBOARDS ---")
    
    # 1. Check/Create Index Pattern (Data View)
    print("\n[1] Creating Index Pattern...")
    url = f"{OPENSEARCH_DASHBOARDS_URL}/api/saved_objects/index-pattern/{INDEX_PATTERN_TITLE}"
    payload = {
        "attributes": {
            "title": INDEX_PATTERN_TITLE,
            "timeFieldName": TIME_FIELD
        }
    }
    
    try:
        r = requests.post(url, headers=HEADERS, json=payload)
        if r.status_code == 200:
            print("vv Index Pattern Created!")
        elif r.status_code == 409:
            print("vv Index Pattern already exists.")
        else:
            print(f"xx Failed to create index pattern: {r.status_code} - {r.text}")
    except Exception as e:
        print(f"xx Connection failed: {e}")
        return

    # 2. Create Visualization: Threat Category Pie Chart
    print("\n[2] Creating Visualization: Threat Categories...")
    viz_payload = {
        "attributes": {
            "title": "Threat Categories Distribution",
            "visState": json.dumps({
                "title": "Threat Categories",
                "type": "pie",
                "params": {"addTooltip": True, "addLegend": True, "isDonut": True},
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                    {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {"field": "threat_category", "size": 5, "order": "desc", "orderBy": "1"}}
                ]
            }),
            "uiStateJSON": "{}",
            "description": "Breakdown of threats by category",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"index": INDEX_PATTERN_TITLE, "query": {"query": "", "language": "kuery"}, "filter": []})}
        }
    }
    
    r = requests.post(f"{OPENSEARCH_DASHBOARDS_URL}/api/saved_objects/visualization/viz_threat_categories", headers=HEADERS, json=viz_payload)
    if r.status_code in [200, 409]: print("vv Visualization 'viz_threat_categories' ready.")
    else: print(f"xx Vis creation failed: {r.text}")

    # 3. Create Dashboard
    print("\n[3] Creating Dashboard: 'AI Threat Intel Overview'...")
    dash_payload = {
        "attributes": {
            "title": "AI Threat Intel Overview",
            "description": "Auto-generated dashboard for AI Pipeline",
            "panelsJSON": json.dumps([
                {
                    "version": "1",
                    "type": "visualization",
                    "id": "viz_threat_categories",
                    "panelIndex": "1",
                    "gridData": {"x": 0, "y": 0, "w": 24, "h": 15, "i": "1"}
                }
            ]),
            "optionsJSON": json.dumps({"useMargins": True}),
            "version": 1,
            "timeRestore": False,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})}
        }
    }
    
    r = requests.post(f"{OPENSEARCH_DASHBOARDS_URL}/api/saved_objects/dashboard/dash_ai_threat_intel", headers=HEADERS, json=dash_payload)
    if r.status_code == 200: 
        print("vv DASHBOARD CREATED SUCCESSFULLY!")
        print(">> Access it at: /app/dashboards#/view/dash_ai_threat_intel")
    elif r.status_code == 409:
        print("vv Dashboard already exists.")
    else: 
        print(f"xx Dashboard creation failed: {r.text}")

if __name__ == "__main__":
    setup_dashboards()
