# SIOPV

Sistema Inteligente de Orquestación y Priorización de Vulnerabilidades.

## Quick Start

```bash
# Install dependencies
uv sync

# Copy and configure environment
cp .env.example .env
# Edit .env with your API keys

# Run CLI
uv run siopv --help
uv run siopv process-report trivy-report.json

# Run tests
uv run pytest
```

## Architecture

Hexagonal architecture with 8-phase pipeline:

1. **Ingestion** - Parse Trivy JSON reports
2. **Enrichment** - Dynamic RAG (NVD, GitHub, EPSS)
3. **Classification** - XGBoost ML model with XAI
4. **Orchestration** - LangGraph state machine
5. **Authorization** - OpenFGA (ReBAC)
6. **Privacy** - DLP with Presidio
7. **Human-in-the-Loop** - Streamlit dashboard
8. **Output** - Jira tickets + PDF audit

## License

MIT
