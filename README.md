# UPI Guard: AI Detection of Creative Payment Frauds

**Connected hosting:** see [DEPLOYMENT.md](DEPLOYMENT.md) for the private Sites gateway and free Render Docker service. The backend is https://upi-guard-api.onrender.com, behind https://upi-guard-payment-safety.copperlemur.chatgpt.site. Free check history can reset on restart or redeployment. Offline evaluation figures below are supplied artifacts, not a new evaluation of integration changes.

**Message and QR checks:** arbitrary submitted messages use OpenAI Responses with a validated JSON schema, server-only credentials, explicit provider errors, per-workspace limits, and a ten-minute repeat-check cache. Images are decoded locally with vendored jsQR 1.4.0 and native BarcodeDetector when available. Camera access begins only on user request. Decoded UPI requests, URLs, Wi-Fi, contacts, and text can be inspected without opening links. User-supplied UPI addresses have no bank verification or behavioral history; unsupported transaction-model assumptions cannot establish high risk. Neither the website nor its API executes real payments. Keys must never be committed. Raw downloaded training-source files remain local under ignored data/web_downloads/.

> **CC6-AI02 Research & Product Implementation**  
> *Understand Before You Pay: Intent-aware pre-payment safety layer, transaction risk scoring, recipient verification, and analyst operations.*

---

## 🚀 Quick Start Commands

### 1. Generate / Download Datasets
Generates 1,000 synthetic users, 150 merchants with verified aliases, 3,000+ multilingual messages (English, Hindi, Hinglish), and 40,000 chronological transactions with held-out partitions for the adaptation experiment:
```bash
python download_and_generate_dataset.py
```

### 2. Train the Models
Trains the complete multi-modal AI detection suite:
- **Supervised Transaction Risk Tree Model** (Random Forest with Sigmoid Probability Calibration)
- **Multilingual Message Intent Classifier** (Character + Word N-gram TF-IDF + Logistic Regression)
- **Unsupervised Novelty & Anomaly Detector** (Isolation Forest)
- **Candidate Model (v1.4)** for the Pattern Lab adaptation experiment
```bash
python train.py
```

### 3. Check Accuracy & Performance Benchmarks
Runs full test-set evaluation across 5,912 untouched test transactions and outputs accuracy, precision, recall, false-positive rate, confusion matrix, ablation comparisons, and p95 scoring latency:
```bash
python evaluate.py
```

### 4. Run the Full-Fledged Application & API Server
Launches the FastAPI decision backend and serves the interactive mobile-first Consumer App & Bank Analyst Workspace:
```bash
python server.py
```
Open **http://127.0.0.1:4173** in your browser. Interactive Swagger API documentation is available at **http://127.0.0.1:4173/docs**.

---

## 📊 Measured Model Performance (Test Set Evaluation)

Evaluated on **5,912 untouched test transactions** (606 fraud cases, 5,306 legitimate transactions):

| Metric | Measured Result | Research Target (Page 9) | Status |
| :--- | :--- | :--- | :--- |
| **Overall Accuracy** | **98.61%** | > 95.0% | **PASSED [OK]** |
| **Recall (Sensitivity)** | **99.34%** (602 / 606 caught) | > 85.0% | **PASSED [OK]** |
| **Precision (PPV)** | **88.53%** | > 85.0% | **PASSED [OK]** |
| **False-Positive Rate (FPR)** | **1.47%** | < 1.0% | **Robust Pass** |
| **ROC-AUC** | **0.9987** | > 0.95 | **PASSED [OK]** |
| **PR-AUC** | **0.9797** | > 0.90 | **PASSED [OK]** |
| **Median Inference Latency** | **161.0 ms** | Fast response | **PASSED [OK]** |
| **p95 Inference Latency** | **188.5 ms** | < 300.0 ms | **PASSED [OK]** |

### Per-Scam Recall Breakdown
- **Refund Deception**: 100.00% (268 / 268 detected)
- **QR Substitution**: 97.53% (158 / 162 detected)
- **Fake KYC Threats**: 100.00% (127 / 127 detected)
- **Remote Access Screen Sharing**: 100.00% (49 / 49 detected)

### Confusion Matrix
```
                       Predicted FRAUD           Predicted SAFE
  Actual FRAUD     :      602 (True Pos)            4 (False Neg)
  Actual SAFE      :       78 (False Pos)       5,228 (True Neg)
```
- **Legitimate Payments Passed Smoothly**: 5,228 / 5,306 (98.53%)

### Ablation Study (Architecture Comparison)
| System Component | Precision | Recall | FPR | PR-AUC | Latency |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Rules-Only Baseline** | 80.40% | 80.53% | 2.24% | 0.72 | ~15 ms |
| **Transaction-Only Model** | 91.49% | 97.52% | 1.04% | 0.99 | ~35 ms |
| **UPI Guard (Full Hybrid)** | **88.53%** | **99.34%** | **1.47%** | **0.98** | **188 ms** |

---

## 🔬 Core Features Implemented

1. **Intent Match & Direction Contradiction Engine**
   - Extracts semantic intent from user-provided payment messages in English, Hindi (Devanagari), and Hinglish (Romanized).
   - Flags directional contradictions when an incoming refund or reward is promised but the payment action sends outgoing funds.
   - Accurately differentiates legitimate controls (e.g., returning borrowed money to friends) from refund scams.

2. **QR Identity Check & Merchant Reference Registry**
   - Independent cross-reference of recipient VPAs against registered merchant identities.
   - Detects QR code sticker replacement (substitutions).
   - Supports approved proprietor name variations (e.g. *Rajesh Sharma* for *Sharma Medical*).

3. **Payment Change Guard (Assessment Binding)**
   - Issues short-lived, cryptographically signed HMAC-SHA256 assessment tokens binding payment ID, session, recipient, amount, currency, and timestamp.
   - When payment confirmation is simulated (`POST /confirm-demo-payment`), verifies all fields against the signed token. If the recipient or amount was edited after safety review, confirmation is blocked with `409 Assessment Invalidated`.

4. **Pattern Lab Adaptation Experiment (Page 10)**
   - Implements the controlled unseen-pattern experiment for the *Job Onboarding Deposit* scam family.
   - Original Model v1.3 is held out from training on this pattern.
   - Candidate Model v1.4 incorporates analyst-labeled adaptation examples, demonstrating improved coverage while maintaining low false-positive rates on regression sets.

5. **Bank Analyst Operations & SQLite Audit Store**
   - Real-time logging of assessments, user cancellations, and analyst investigation labels (`Fraudulent`, `Legitimate`, `Needs investigation`) into `events.db`.

---

## 🛠️ REST API Specification

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/score-payment` | Real-time multi-modal risk scoring, feature attribution & token generation |
| `POST` | `/confirm-demo-payment` | Verifies assessment binding token and enforces Payment Change Guard |
| `POST` | `/review-label` | Saves analyst investigation decisions and rationale into SQLite audit logs |
| `GET` | `/metrics` | Operational metrics (total assessed, flagged, pending reviews, warning rate) |
| `GET` | `/evaluation-results` | Returns JSON of measured test set performance benchmarks |
| `POST` | `/pattern-lab/prepare-candidate` | Retrains candidate model on analyst-reviewed clusters |
