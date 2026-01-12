import os
import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import httpx

app = FastAPI(title="AI Threat Intel Normalizer (Ollama)")

# Configuration
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://100.119.58.75:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

class UnstructuredElement(BaseModel):
    type: str
    text: str
    metadata: Optional[dict] = None

class NormalizationRequest(BaseModel):
    elements: List[UnstructuredElement]
    source_url: Optional[str] = "unknown"

@app.post("/normalize")
async def normalize_data(request: NormalizationRequest):
    # 1. Consolidate text from Unstructured elements
    full_text = "\n".join([el.text for el in request.elements if hasattr(el, 'text')])
    
    if len(full_text) < 10:
        return {"status": "error", "message": "Insufficient text extracted"}

    # 2. Build the AI Prompt
    prompt = f"""
    You are a Threat Intelligence AI. 
    Analyze the following raw data extracted from {request.source_url}.
    
    TASK:
    1. Extract all Indicators of Compromise (IPs, Domains, File Hash, Emails).
    2. Identify any PII (Personally Identifiable Information).
    3. Categorize the threat (e.g., Phishing, Malware, Leak, Darkweb Post).
    4. Provide a 2-sentence summary.
    5. Detect the 'Target' if mentioned.
    
    FORMAT: Return ONLY a valid JSON object with these keys: 
    'indicators', 'pii_found', 'threat_category', 'summary', 'target_entity', 'confidence_score'.
    Do not include any other text in your response.

    RAW DATA:
    {full_text[:4000]} 
    """

    try:
        # 3. Call Ollama for Normalization
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json"
                }
            )
            response.raise_for_status()
            ollama_result = response.json()
            
            ai_data = json.loads(ollama_result["response"].strip())
            
        return {
            "source": request.source_url,
            "structured_intel": ai_data,
            "raw_text_preview": full_text[:200],
            "total_elements_processed": len(request.elements),
            "model_used": OLLAMA_MODEL
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health():
    return {"status": "alive"}
