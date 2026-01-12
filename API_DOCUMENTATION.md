# AI Threat Intel Pipeline - API & Usage Documentation

## Overview
This pipeline ingests raw, unstructured threat intelligence (Text, HTML, PDF) and converts it into structured, searchable data using Generative AI.

**Flow:**
`Raw Input` ⮕ `Unstructured.io (Cleaning)` ⮕ `AI Normalizer (Ollama/Llama3)` ⮕ `OpenSearch (Storage)`

---

## 1. AI Normalizer API

**Base URL:** `http://<server-ip>:5050`
**Swagger UI:** `http://<server-ip>:5050/docs`

### **Endpoint: Normalize & Ingest**
`POST /normalize`

**Description:**
Takes cleaned text segments (from Unstructured.io), extracts intelligence, and automatically indexes the result into OpenSearch.

**Request Body:**
```json
{
  "source_url": "report-id-or-url",
  "elements": [
    {
      "type": "NarrativeText",
      "text": "The raw text content to analyze..."
    }
  ]
}
```

**Response:**
```json
{
  "status": "success",
  "db_id": "open-search-document-id",
  "structured_intel": {
    "indicators": {
      "ips": ["1.2.3.4"],
      "domains": ["malicious.com"],
      "emails": []
    },
    "threat_category": "Phishing",
    "summary": "Executive summary of the threat...",
    "confidence_score": 0.95
  }
}
```

---

## 2. Unstructured.io API

**Base URL:** `http://<server-ip>:8000`

### **Endpoint: Partition File**
`POST /general/v0/general`

**Description:**
Upload any file (PDF, HTML, Docx, Text) to strip formatting and get clean text elements.

**Curl Example:**
```bash
curl -X POST http://localhost:8000/general/v0/general \
  -F 'files=@my_threat_report.pdf'
```

---

## 3. Querying OpenSearch

**Base URL:** `http://<server-ip>:9200`
**Index:** `threat_intel_v1`
**Credentials:** `admin` / `<your-password>`

### **Sample Query: Find all "Ransomware" threats**
```bash
curl -X GET "http://localhost:9200/threat_intel_v1/_search?pretty" \
  -u admin:password \
  -H 'Content-Type: application/json' \
  -d'
{
  "query": {
    "match": {
      "threat_category": "Ransomware"
    }
  }
}'
```

### **Sample Query: Find threats involving a specific IP**
```bash
curl -X GET "http://localhost:9200/threat_intel_v1/_search?pretty" \
  -u admin:password \
  -H 'Content-Type: application/json' \
  -d'
{
  "query": {
    "term": {
      "indicators.ips": "149.102.10.11"
    }
  }
}'
```

---

## 4. Visualization (OpenSearch Dashboards)

OpenSearch Dashboards does **not** generate dashboards automatically, but you can create a powerful "Threat Map" in minutes using the data we are now ingesting.

### **Quick Setup Guide:**
1.  **Login** to Dashboards (Port 5601).
2.  **Create Index Pattern**:
    *   Go to **Stack Management** > **Index Patterns**.
    *   Create pattern: `threat_intel_v1`.
    *   Time field: `timestamp`.
3.  **Discover**:
    *   Go to **Discover** tab. You will see all your ingested threat reports immediately.
4.  **Visualize**:
    *   Go to **Visualize** > **Create new visualization**.
    *   **Tag Cloud**: Use `threat_category` field to see top threats (Ransomware, Leak, etc.).
    *   **Metric**: Count unique `indicators.ips` to see total IOCs found.
    *   **Data Table**: Show `summary` and `confidence_score` for high-confidence alerts.
