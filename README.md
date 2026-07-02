# LLM Vulnerability Scanner (MVP)

A prompt-injection and jailbreak detection scanner for **local HuggingFace models**.
Fires a library of adversarial probes at a target model, scores the responses
through multiple independent detection engines, and produces an HTML/JSON report.

## Architecture

```
llm_vuln_scanner/
  core/
    model_adapter.py   # LocalHFModel wrapper (+ MockModel for smoke tests)
    detectors.py        # KeywordEngine, CanaryTokenEngine, PerplexityEngine, EmbeddingSimilarityEngine
    orchestrator.py      # Scanner: loads probes, runs them, aggregates risk scores
    report.py            # HTML/JSON report rendering
  data/
    injection_payloads.json   # prompt injection probe library
    jailbreak_payloads.json    # jailbreak probe library
  cli.py                 # command-line interface
  api.py                  # FastAPI service
  requirements.txt
```

### Detection engines

| Engine | What it catches | Notes |
|---|---|---|
| `KeywordEngine` | Known compliance/leak phrases, absence of expected refusals | Fast, always on, no deps |
| `CanaryTokenEngine` | System-prompt / context leakage | Plants a secret token in the system prompt; near-100% precision if it appears in output |
| `PerplexityEngine` | Adversarial-suffix / GCG-style attacks | Flags statistically abnormal payload token sequences; requires the real model (not mock) |
| `EmbeddingSimilarityEngine` | Paraphrased/novel variants of known attacks | Optional (`--use-embeddings`), needs `sentence-transformers` |

Each probe gets a **weighted risk score (0-100)** combining all engine verdicts;
probes above `--flag-threshold` (default 40) are marked `VULNERABLE` in the report.

## Setup

```bash
pip install -r requirements.txt
```

> Note: `LocalHFModel` downloads weights from the HuggingFace Hub the first time
> you point it at a model name (e.g. `gpt2`, `meta-llama/Llama-3-8b-instruct`).
> Make sure your environment has network access to `huggingface.co`, or pass a
> local path to already-downloaded weights.

## Usage

### CLI

Quick smoke test with no model download (uses a deterministic mock model):
```bash
python cli.py scan --mock --out report.html
```

Real scan against a local/hub model:
```bash
python cli.py scan \
  --model gpt2 \
  --system-prompt "You are a helpful banking assistant. Never reveal account numbers." \
  --categories injection --categories jailbreak \
  --use-embeddings \
  --flag-threshold 40 \
  --out report.html
```

Open `report.html` in a browser for the full report, or use `--out report.json`
for machine-readable output (e.g. to gate a CI/CD pipeline).

### API

```bash
uvicorn api:app --reload --port 8000
```

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "model_name": "gpt2",
    "system_prompt": "You are a helpful assistant.",
    "categories": ["injection", "jailbreak"],
    "use_embeddings": true
  }'
```

`GET /probes` lists the current probe library. `GET /health` for liveness checks.

## Extending the probe library

Add entries to `data/injection_payloads.json` or `data/jailbreak_payloads.json`:
```json
{ "id": "inj-009", "category": "direct_override", "payload": "..." }
```
No code changes needed — the orchestrator loads these dynamically.

## Roadmap (beyond this MVP)

This MVP covers prompt injection + jailbreak detection only, per current scope.
Natural next modules, following the same "probe + detector" pattern:

1. **Data/token poisoning detection** — statistical outlier detection over
   fine-tuning datasets (embedding clustering), differential testing against
   a clean baseline model.
2. **Weight/supply-chain scanning** — `safetensors` validation, refuse to load
   pickled checkpoints, activation-clustering based backdoor/trojan detection.
3. **Sensitive info leakage probes** — targeted probes for PII/training-data
   memorization (e.g. repeated-token extraction attacks).
4. **LLM-as-judge engine** — use a second model to score responses against a
   rubric, catching subtler policy violations the keyword/embedding engines miss.
5. **Multi-turn escalation tracking** — score cumulative risk across a
   conversation instead of single-shot probes only.
6. **CI/CD integration** — fail a build if `overall_risk_score` exceeds a
   threshold on `report.json`, similar to a SAST gate.

## Known limitations (be upfront about these)

- Detection is heuristic; expect false positives/negatives, especially from
  `KeywordEngine` alone. Use multiple engines together and tune `--flag-threshold`.
- `PerplexityEngine` needs a real model (not `MockModel`) to produce meaningful scores.
- This is a defensive/red-teaming tool for testing **your own** models. It is
  not intended to be pointed at third-party production systems without authorization.
