# ShieldOS: Real-Time Fraud & Event Decisioning Gateway

A low-latency, first-principles transaction monitoring pipeline designed to isolate and mitigate account takeovers (ATO), identity fraud, SIM-swap network vectors, and high-velocity transaction fraud around a **<45 ms decision budget** before ledger settlement.

The primary review artifact is the executed notebook: **[ShieldOS Fraud Decisioning Gateway](notebooks/ShieldOS_Fraud_Decisioning_Gateway.ipynb)**.

## What the prototype proves

- A typed transaction contract and replay-safe decision response.
- Deterministic hard stops for compromised payment tokens, sensitive SIM swaps, and high-confidence ATO.
- Four bounded deterministic signal evaluators covering device identity, velocity, network reputation, and transaction context in parallel.
- An explainable ensemble risk score with explicit reason codes and versioned routing policy.
- Three-way action orchestration: STATUS_APPROVED, STATUS_TRIGGER_MFA, and STATUS_HARD_BLOCK.
- A replay-stable decision envelope and integrity digest that exclude raw customer identifiers and IP addresses.
- A warmed 1,000-request concurrency benchmark with P50, P95, P99, throughput, and an automatically evaluated SLA result.
- An off-path investigation workflow where generative AI may summarize allowlisted evidence but cannot change settlement.

## Evidence boundary

| Demonstrated with public observed data | Demonstrated as operational simulation |
|---|---|
| Fraud classification, extreme imbalance, temporal evaluation, threshold trade-offs, value capture, and drift | IMSI change, device trust, IP reputation, impossible travel, idempotency, service timeouts, and case routing |

The committed extract contains authentic anonymized transaction rows from [OpenML dataset 1597](https://www.openml.org/search?id=1597&type=data), originally published by the ULB Machine Learning Group. OpenML does not contain customer, device, IP, IMSI, IMEI, or carrier-event fields. Those operational signals are explicitly labelled scenario fixtures.

## 1. System Architecture & Topology

### Synchronous authorization path

~~~text
┌──────────────────────────┐
│ Incoming HTTPS request   │
│ transaction_id + payload │
└─────────────┬────────────┘
              │
              v
┌──────────────────────────┐
│ API Gateway              │
│ mTLS · schema · rate cap │
│ idempotency admission    │
└─────────────┬────────────┘
              │
              v
┌──────────────────────────┐
│ Header / signal extract  │
│ IMSI · IP · DeviceID     │
│ token · event timestamp  │
└─────────────┬────────────┘
              │
              v
┌──────────────────────────┐        critical rule hit
│ Deterministic rules      ├─────────────────────────────┐
│ hard-stop precedence     │                             │
└─────────────┬────────────┘                             │
              │ pass                                    │
              v                                         │
┌──────────────────────────┐                             │
│ Hydrated feature store   │                             │
│ Redis / Feast online     │                             │
│ point-in-time snapshot   │                             │
└─────────────┬────────────┘                             │
              │                                         │
              v                                         │
┌───────────────────────────────────────────────┐        │
│ Bounded deterministic signal fan-out         │        │
│                                               │        │
│ Identity/Device  Velocity  Network  Context   │        │
└─────────────┬─────────────────────────────────┘        │
              │ typed signals                            │
              v                                         │
┌──────────────────────────┐                             │
│ ML inference layer       │                             │
│ Production target:       │                             │
│ XGBoost → ONNX Runtime   │                             │
│ calibrated probability  │                             │
└─────────────┬────────────┘                             │
              │                                         │
              v                                         v
┌──────────────────────────────────────────────────────────────┐
│ Versioned action router                                      │
│ <40 APPROVE │ 40–75 MFA STEP-UP │ >75 / hard stop BLOCK     │
└──────────┬───────────────┬────────────────────┬──────────────┘
           │               │                    │
           v               v                    v
  Core Banking Ledger   MFA Service     Fraud Operations Queue
           │               │                    │
           └───────────────┴──────────┬─────────┘
                                      v
                         Kafka decision + audit event
~~~

### Asynchronous agentic investigation path

~~~text
Decision event
     |
     v
Evidence allowlist + PII minimizer
     |
     +--> Timeline Agent -----------+
     +--> Entity/Device Graph Agent +--> Case Synthesis Agent
     +--> Policy Evidence Agent ----+          |
                                                v
                                      Human investigator
                                                |
                                                v
                                  disposition + delayed label
                                                |
                             rule analysis / model retraining
~~~

The authorization path is bounded, deterministic, versioned, and replayable. Generative agents operate after the decision and have no permission to release funds, block an account, alter thresholds, or write the authoritative audit event.

## 2. Real-Time Network Vector Identification

### Coordinated SIM swap

The extraction layer does not trust a boolean from the client. A production adapter resolves the current IMSI/IMEI binding through a carrier-risk provider, records the carrier-event timestamp, and compares it with the transaction and authentication timeline. A recent IMSI change becomes a hard stop only when paired with a sensitive transaction, elevated velocity, or material amount. A low-value transaction with an isolated SIM change is stepped up to MFA rather than silently approved.

Required evidence:

- account reference and tokenized device identifier;
- old and current IMSI/IMEI binding hashes;
- carrier change timestamp and freshness;
- authentication age and transaction amount;
- rule version, provider response code, and correlation ID.

### Account takeover

ATO detection joins identity, device, network, and behavioural evidence:

- impossible travel: London activity 12 minutes after a Mumbai authentication;
- new or low-trust device combined with elevated hourly velocity;
- poor IP or ASN reputation;
- rapid credential, beneficiary, or payment-token changes;
- amount and payee novelty relative to the account baseline.

No single weak signal blocks a customer. The gateway reserves deterministic blocking for high-confidence combinations and routes ambiguous cases through step-up authentication.

## 3. High-Concurrency Latency Performance Budget

| Execution Stage | Latency Budget (P99) | Dependency |
|---|---:|---|
| Payload Ingestion & SSL Termination | 6ms | API Gateway |
| Feature Store Hydration & Lookup | 14ms | Redis Cluster |
| Deterministic Rules Evaluation | 4ms | In-Memory Engine |
| XGBoost Model Inference Scoring | 11ms | ONNX Runtime Engine |
| Action Routing & Enqueueing | 3ms | Apache Kafka Producer |
| **Total Decision Window SLA** | **38ms** | **Passed budget design** |

The remaining 7 ms of the 45 ms service objective is an error budget for scheduling, serialization, cross-zone jitter, and telemetry. Run **python main.py** to calculate the local in-process P99. The local benchmark deliberately excludes TLS, Redis, Kafka acknowledgement, and core-ledger network latency.

## 4. Business Impact & False-Positive Mitigation Metrics

The following are **case-study product targets** used to size thresholds and operational capacity:

- Fraud Loss Reduction: 54% decrease in unauthorized account leakage.
- False Positive Optimization Ratio: 3.1:1 improvement using dynamic risk-score thresholds over legacy static rules.
- Operational Queue Optimization: 42% decrease in manual investigator backlogs through automated step-up MFA routing.

The notebook computes model evidence separately: PR-AUC, fraud recall, value-weighted capture, approval rate, MFA rate, block precision, drift, and review-queue volume. It does not present the case-study targets as observed bank outcomes.

## 5. Decision Contract

Every decision returns:

~~~json
{
  "transaction_id": "txn_...",
  "trace_id": "trc_...",
  "user_reference": "usr_pseudonymous",
  "aggregate_risk_score": 43.23,
  "action": "STATUS_TRIGGER_MFA",
  "http_status": 202,
  "fraud_vector": "VELOCITY_BURST",
  "reason_codes": ["VELOCITY_ELEVATED", "DEVICE_TRUST_LOW"],
  "hard_stop": false,
  "degraded": false,
  "model_version": "fraud-ensemble-surrogate-2026.10",
  "policy_version": "routing-policy-1.0",
  "downstream_route": "identity.step-up-mfa.v1",
  "processing_time_ms": 0.81,
  "sla_met": true
}
~~~

The response excludes raw user IDs, device IDs, and network addresses. The audit hash covers the decision, score, reasons, and model/policy versions so a case can be reproduced without copying PII into downstream logs.
Customer references use a keyed HMAC rather than a reversible or dictionary-attackable plain hash. The sandbox creates an ephemeral process key; a deployed service must inject a stable key from its secret manager. The SHA-256 audit field is an integrity checksum for replay in this sandbox, not a digital signature; production mapping requires a signed append-only envelope.

## 6. Agent Contracts and Failure Policy

| Agent | Inputs | Output | Timeout / fallback |
|---|---|---|---|
| Identity & Device | trust score, SIM-change state | identity risk and reason codes | 12 ms; force MFA |
| Velocity | hourly event count | saturation-based velocity risk | 12 ms; force MFA |
| Network | hydrated IP reputation | network risk | 12 ms; force MFA |
| Transaction Context | amount, geo velocity, auth age | contextual risk | 12 ms; force MFA |
| Evidence Case Agent | allowlisted decision event | investigator brief | asynchronous; human review |

Agent failures never disappear into a default score. A timeout emits a typed degraded signal and the policy enforces at least MFA. Critical deterministic rules retain precedence if model inference is unavailable.

## 7. Notebook Demonstration

The notebook is ordered as an executable architecture review:

1. Verify source provenance and class imbalance.
2. Run a chronological train/calibration/test split.
3. Compare a balanced logistic baseline with XGBoost.
4. Calibrate the model and inspect reliability.
5. Explore policy thresholds against fraud capture, customer friction, and queue capacity.
6. Replay clean, model-led anomaly, and SIM-swap scenarios through the gateway.
7. Visualize the specialist-agent trace and decision evidence.
8. Execute a 1,000-request P99 benchmark.
9. Review production controls, drift, delayed labels, and rollout strategy.

## 8. Repository Layout

~~~text
ShieldOS-Fraud-Decisioning/
├── README.md
├── main.py
├── notebooks/
│   └── ShieldOS_Fraud_Decisioning_Gateway.ipynb
├── data/
│   ├── creditcard_openml_1597_extract.csv.gz
│   └── creditcard_openml_1597_manifest.json
├── scripts/
│   └── build_data_extract.py
├── tests/
│   └── test_main.py
├── requirements.txt
└── pyproject.toml
~~~

## 9. Run

Prerequisite: Python 3.11 or newer.

On macOS, install the OpenMP runtime with `brew install libomp` if XGBoost reports that `libomp.dylib` is missing.

~~~bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python main.py
pytest -q
jupyter notebook notebooks/ShieldOS_Fraud_Decisioning_Gateway.ipynb
~~~

Each benchmark invocation uses a new transaction-ID namespace so repeated runs exercise the decision pipeline rather than the in-memory idempotency cache. Reported latency covers the local in-process engine only.

Rebuild the checked-in data extract:

~~~bash
python scripts/build_data_extract.py
~~~

## 10. Production Mapping

| Sandbox component | Production component |
|---|---|
| Pydantic request model | FastAPI or gRPC edge contract |
| In-memory feature values | Redis-backed Feast online store |
| Python hard-stop rules | versioned in-memory policy engine |
| deterministic ensemble surrogate | calibrated XGBoost exported to ONNX |
| thread-based fan-out | async service calls with bulkheads and deadlines |
| route string | transactional Kafka producer + outbox |
| response cache | distributed idempotency store |
| audit SHA-256 | signed append-only decision envelope |
| notebook drift check | scheduled feature, score, label, and queue monitors |

Release controls: champion/challenger shadowing, model and policy pinning, canary rollout, feature freshness checks, timeout budgets, circuit breakers, transactional outbox, delayed-label monitoring, and manual override audit.

## References

- [Shuru Product Manager (Fintech) role](https://in.linkedin.com/jobs/view/product-manager-fintech-at-shuru-4478396990)
- [OpenML credit-card fraud dataset 1597](https://www.openml.org/search?id=1597&type=data)
- [ULB fraud-detection research](https://di.ulb.ac.be/map/adalpozz/pdf/FraudDetectionPaper_8.pdf)
- [Feast online feature store](https://docs.feast.dev/getting-started/components/online-store)
- [ONNX Runtime performance guidance](https://onnxruntime.ai/docs/performance/)
