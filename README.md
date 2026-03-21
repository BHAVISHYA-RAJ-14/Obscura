# 🛡️ Obscura — AI-Powered Insider Threat Detection

> *"Obscura doesn't just detect insider threats — it writes the investigation report for you."*

---

## 📌 Problem Statement

Insider threats represent one of the most complex cybersecurity challenges faced by modern organizations. Unlike external attacks, insider threats originate from individuals within the organization — employees, contractors, or partners — who may intentionally or unintentionally expose sensitive information.

Obscura addresses **PS3: AI-Powered Insider Threat Detection System** by building an end-to-end behavioral analytics platform that monitors 4,000+ employees, scores them on a 0–100 risk scale, and auto-generates investigation briefs — all from raw organizational activity logs.

---

## 🎯 What Makes Obscura Different

Every other team will build a risk score + dashboard. Obscura adds one feature no one else has:

**The Case File Engine** — when a user is flagged, Obscura automatically generates a complete, investigation-ready security brief using statistical behavioral analysis. Security analysts can act immediately without manual investigation.

---

## 🏗️ System Architecture

```
Raw CSV Files (logon, device, file, psychometric, users)
            │
            ▼
┌─────────────────────────┐
│   DATA CLEANING         │  Python engine, bad row skipping,
│   obscura_cleaning.py   │  schema normalization, content removal
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   SAFE BROWSING SCAN    │  Google Safe Browsing API v4
│   safe_browsing.py      │  Pre-flags malicious URLs from http.csv
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   FEATURE ENGINEERING   │  47 behavioral features per user
│   data_pipeline.py      │  Ratios, entropy, multi-source fusion
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   DETECTION ENGINE      │  Isolation Forest (300 trees)
│   detection_engine.py   │  Risk score 0–100 per employee
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   CASE FILE ENGINE  ⭐   │  Rule-based investigation briefs
│   case_file_engine.py   │  Z-score analysis + scenario classification
└───────────┬─────────────┘
            │
            ▼
┌─────────────────────────┐
│   STREAMLIT DASHBOARD   │  5-page live interface
│   dashboard.py          │  Radar charts, heatmaps, leaderboard
└─────────────────────────┘
```

---

## 📊 Results

| Metric | Value |
|--------|-------|
| Total users monitored | 4,000 |
| Flagged as anomalous | 200 (5.0%) |
| Critical threats | 25 (0.6%) |
| High risk | 79 (2.0%) |
| Medium risk | 410 (10.2%) |
| Normal users | 3,486 (87.2%) |
| Top threat score | 100.0 / 100 |
| Case files generated | 15 |

### Feature Separation (Flagged vs Normal)

| Feature | Normal Avg | Flagged Avg | Separation |
|---------|-----------|-------------|------------|
| USB After-Hours Ratio | 0.1% | 13.8% | +21,622% |
| Suspicious File Types | 0.5 | 10.6 | +1,827% |
| USB Total Events | 33 | 471 | +1,298% |
| Unique Workstations | 5.8 | 53.7 | +815% |
| After-Hours Logins | 6.3% | 39.1% | +525% |
| File Copy Ratio | 5.7% | 31.8% | +457% |

---

## 📁 Project Structure

```
obscura/
  ├── main.py                 # Master orchestrator — run this first
  ├── config.py               # All paths + API keys — edit only this
  ├── data_pipeline.py        # Loads all CSVs + engineers 47 features
  ├── safe_browsing.py        # Google Safe Browsing API integration
  ├── detection_engine.py     # Isolation Forest training + scoring
  ├── case_file_engine.py     # Rule-based investigation brief generator
  ├── visualizations.py       # 9 Plotly behavioral charts
  ├── dashboard.py            # 5-page Streamlit dashboard
  ├── requirements.txt        # Python dependencies
  └── output/
        ├── results.csv       # All users with risk scores (generated)
        └── case_files.json   # Investigation briefs (generated)
```

---

## 🗂️ Dataset

**CMU CERT Insider Threat Dataset** (Kaggle mirror)
Source: `https://www.kaggle.com/datasets/mrajaxnp/cert-insider-threat-detection-research`

| File | Description | Rows |
|------|-------------|------|
| `logon.csv` | Authentication events (Logon/Logoff) | 597,453 |
| `device.csv` | USB connect/disconnect events | 443,277 |
| `file.csv` | File system operations | 59,718 |
| `psychometric.csv` | Big Five personality scores | 4,000 |
| `users.csv` | Employee directory + roles | 4,000 |

---

## ⚙️ ML Pipeline Details

### Data Cleaning
- `engine="python"` with `on_bad_lines="skip"` — handles corrupted rows
- Removes `content` column from file.csv (massive text, not needed)
- Normalizes Big Five scores from 0–100 to 0.0–1.0
- SHA-256 anonymization of all user IDs

### Feature Engineering (47 Features)
- **Ratio features** — anomalous_count / total_count (normalizes for activity volume)
- **Shannon Entropy** — measures login time irregularity
- **Multi-source fusion** — combines logon + device + file + psychometric signals
- **After-hours detection** — flags activity outside 7AM–7PM business hours
- **Boolean flags** — `to_removable_media`, `from_removable_media` from file.csv

### Detection Model
- **Algorithm:** Isolation Forest (unsupervised — no labels needed)
- **Trees:** 300 estimators
- **Contamination:** 5% (matches known CMU dataset insider rate)
- **Scaling:** StandardScaler before training
- **Scoring:** Decision function normalized to 0–100 risk score

### Risk Levels
| Level | Score Range | Count |
|-------|-------------|-------|
| Critical | 85–100 | 25 |
| High | 65–84 | 79 |
| Medium | 40–64 | 410 |
| Low | 0–39 | 3,486 |

### Case File Engine
- Computes population mean + std for all 47 features
- Calculates Z-scores per user per feature
- Classifies threat scenario from signal combinations:
  - USB + file copies + after-hours → Data Exfiltration via Removable Media
  - External emails + attachments → Data Exfiltration via Email
  - Malicious URLs + file ops → Malware / External Coordination
  - File deletions + after-hours → Sabotage / Evidence Destruction
- Interprets Big Five psychometric risk factors
- Recommends tiered security action (Critical → CISO escalation)

---

## 🔒 Privacy & Security

| Measure | Implementation |
|---------|---------------|
| User ID Anonymization | SHA-256 hash — `USR-XXXXXXXX` format |
| Content Data | Dropped from file.csv — never processed |
| No raw IDs in output | results.csv only contains hashed IDs |
| API Key handling | Environment variables via `os.getenv()` |

---

## 🚀 Setup & Running

### Prerequisites
```bash
pip install -r requirements.txt
```

### Configuration
Edit `config.py`:
```python
DATA_DIR              = "./data"               # folder with your CSVs
OUTPUT_DIR            = "./output"             # where results are saved
SAFE_BROWSING_API_KEY = "YOUR_KEY_HERE"        # Google Cloud Console
```

### Training (recommended on Google Colab for large files)
```bash
python main.py
```

### Dashboard (run locally)
```bash
streamlit run dashboard.py
# Opens at http://localhost:8501
```

---

## 📺 Dashboard Pages

| Page | What You See |
|------|-------------|
| 📊 Overview | KPI cards, risk distribution, scatter plots |
| 🚨 Threat Leaderboard | Top 25 riskiest employees ranked by score |
| 🔍 Employee Profile | Radar chart vs population + behavior breakdown |
| 📋 Case Files | Full investigation brief per flagged employee |
| 📈 Analytics | Feature correlation matrix + department heatmap |

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Data Processing | Pandas, NumPy |
| ML Model | scikit-learn (Isolation Forest) |
| Visualization | Plotly, Streamlit |
| URL Scanning | Google Safe Browsing API v4 |
| Privacy | hashlib SHA-256 |
| Deployment | Streamlit (local / cloud) |

---

## 📈 Evaluation Criteria Coverage

| PS Criteria | How Obscura Addresses It |
|-------------|--------------------------|
| Model Performance | 21,000%+ feature separation, exact 5% contamination calibration |
| Dashboard Quality | 5-page interactive Streamlit with 9 chart types |
| Data Engineering | Multi-CSV pipeline, 47 engineered features, full cleaning |
| System Scalability | Processes 1M+ events across 4,000 users |
| Privacy & Security | SHA-256 anonymization, content data never stored |

---

## 👥 Team

**Team NeoTech** — NPCI Hackathon 2025
- Bhavishya Raj
- @shivam1211
- @aaryan9106

---

## 📝 License

Built for NPCI Hackathon PS3. For educational and research purposes only.
Dataset: CMU CERT Insider Threat Test Dataset (synthetic data).
