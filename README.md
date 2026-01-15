# Capstone-Project : Advanced Data Transfer Chatbot
An AI-assisted data transfer chatbot with a web UI and Python backend that validates Avro schemas and automates Airflow DAG creation, triggering, and deletion across cloud and database systems.

# Advanced Data Processing Chatbot (Airflow + Avro + Web UI)

A full-stack data processing chatbot that generates **Avro-validated JSON payloads** and supports orchestration of **Apache Airflow DAG** operations for data pipeline workflows (create/trigger/delete) and connection management (database/cloud).

## Key Features
- **Web UI** for interacting with the chatbot
- **Python backend** for message handling and payload generation
- **Avro schema validation** to ensure payload correctness
- Supports payload models for:
  - Database Connection
  - Cloud Connection
  - Create DAG
  - Trigger DAG
  - Delete Connection
  - Delete DAG

---

## Repository Structure

- `src/` — Python application source
  - `app.py` — App entry point
  - `backend.py` — Backend logic / endpoints
  - `utils.py` — Helper utilities
  - `constants.py` — Shared constants

- `ui/` — Frontend user interface
  - `trial.html` — Web UI for the chatbot

- `schemas/` — Avro schemas used for validation
  - `database_connection_schema.avsc`
  - `cloud_connection_schema.avsc`
  - `create_dag_schema.avsc`
  - `trigger_dag_schema.avsc`
  - `delete_connection_schema.avsc`
  - `delete_dag_schema.avsc`


## How to Run (Local)

### 1) Start the backend
From the repo root:

# 1) create a venv (optional but recommended)
python -m venv .venv && source .venv/bin/activate

# 2) install runtime deps (plus anything your bot needs: avro, openai, etc.)
pip install fastapi uvicorn "avro-python3>=1.10" openai
python -m pip install python-multipart

# 3) keys & dirs
export OPENAI_API_KEY="**Requires a OPENAI API Key**"
export JSON_OUT_DIR="./json_data"
export UPLOAD_DIR="./uploads"
export SAVE_DIR="./json_data”
SUPPRESS_JSON_IN_UI=1

# 4) start API on port 5000 (so trial.html works as-is)
uvicorn backend:app --reload --port 5000

# 5) open the UI
open ./trial.html   # or just double-click the file
