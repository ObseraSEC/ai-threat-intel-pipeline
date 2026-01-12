import os
import json
import time
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Any
import httpx
from opensearchpy import OpenSearch, helpers

app = FastAPI(title="AI Threat Intel Normalizer (Ollama + OpenSearch)")

# --- CONFIGURATION ---
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://100.119.58.75:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "opensearch-q0wwcsc8kwowsowk4ksck4wo")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", 9200))
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER", "admin")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD", "admin")

# --- OPENSEARCH CLIENT ---
def get_opensearch_client():
    return OpenSearch(
        hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
        http_compress=True,
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
        use_ssl=False,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False
    )

INDEX_NAME = "threat_intel_v1"

def init_opensearch():
    client = get_opensearch_client()
    if not client.indices.exists(index=INDEX_NAME):
        # Define strict mapping for analytics
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "source_url": {"type": "keyword"},
                    "summary": {"type": "text"},
                    "threat_category": {"type": "keyword"},
                    "confidence_score": {"type": "float"},
                    "indicators": {
                        "properties": {
                            "ips": {"type": "ip"},
                            "emails": {"type": "keyword"},
                            "domains": {"type": "keyword"}
                        }
                    },
                    "pii_found": {"type": "boolean"},
                    "raw_text": {"type": "text", "index": False}
                }
            }
        }
        client.indices.create(index=INDEX_NAME, body=mapping)
        print(f"INFO: Created OpenSearch index '{INDEX_NAME}'")
    else:
        print(f"INFO: Index '{INDEX_NAME}' already exists.")

# Initialize on startup (lazy approach or explicit)
try:
    init_opensearch()
except Exception as e:
    print(f"WARNING: Could not connect to OpenSearch on startup: {e}")


# --- MODELS ---
class UnstructuredElement(BaseModel):
    type: str
    text: str
    metadata: Optional[dict] = None

class NormalizationRequest(BaseModel):
    elements: List[UnstructuredElement]
    source_url: Optional[str] = "unknown"

# --- CORE LOGIC ---
@app.post("/normalize")
async def normalize_data(request: NormalizationRequest):
    start_time = time.time()
    
    # 1. Consolidate text from Unstructured elements
    full_text = "\n".join([el.text for el in request.elements if hasattr(el, 'text')])
    
    if len(full_text) < 5:
        return {"status": "error", "message": "Insufficient text extracted"}

    print(f"DEBUG: Processing {len(request.elements)} elements. Total text length: {len(full_text)}")

    # 2. Build Prompt
    system_prompt = """You are a strictly accurate Threat Intelligence Extraction AI. 
    Review the provided text and extract security indicators and summaries.
    Return ONLY a JSON object."""

    user_prompt = f"""
    SOURCE: {request.source_url}
    TEXT TO ANALYZE:
    {full_text[:12000]}

    EXTRACT THE FOLLOWING INTO JSON:
    1. 'indicators': {{ 'ips': [], 'domains': [], 'emails': [] }}
    2. 'pii_found': true/false
    3. 'threat_category': string (e.g. Phishing, Ransomware, Leak, Botnet)
    4. 'summary': string (concise executive summary)
    5. 'confidence_score': 0.0 to 1.0 (float)
    
    Important:
    - If no IPs or domains are found, return empty lists.
    - Do not invent data.
    - Return ONLY the JSON.
    """

    try:
        # 3. Call Ollama
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": OLLAMA_MODEL,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "stream": False,
                    "format": "json"
                }
            )
            response.raise_for_status()
            ollama_result = response.json()
            raw_ai_response = ollama_result["message"]["content"].strip()
            
            try:
                ai_data = json.loads(raw_ai_response)
            except json.JSONDecodeError:
                # Fallback extraction
                start = raw_ai_response.find('{')
                end = raw_ai_response.rfind('}') + 1
                ai_data = json.loads(raw_ai_response[start:end])
            
            # 4. Ingest into OpenSearch
            doc = {
                "timestamp": int(time.time() * 1000), # Epoch millis
                "source_url": request.source_url,
                "summary": ai_data.get("summary", ""),
                "threat_category": ai_data.get("threat_category", "Unknown"),
                "confidence_score": ai_data.get("confidence_score", 0.0),
                "indicators": ai_data.get("indicators", {}),
                "pii_found": ai_data.get("pii_found", False),
                "raw_text": full_text[:4000] # truncate for storage efficiency
            }
            
            os_client = get_opensearch_client()
            res = os_client.index(index=INDEX_NAME, body=doc)
            doc_id = res['_id']
            print(f"INFO: Indexed document {doc_id} to OpenSearch.")

        return {
            "status": "success",
            "db_id": doc_id,
            "structured_intel": ai_data,
            "model_used": OLLAMA_MODEL,
            "processing_time": time.time() - start_time
        }
    except Exception as e:
        print(f"ERROR: {str(e)}")
        # We still return the AI data if possible, but mark DB as failed? 
        # For now, just raise 500
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health():
    return {"status": "alive", "opensearch_connected": True}
