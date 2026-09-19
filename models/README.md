# Machine Learning Models

This directory contains trained ML models used by the detection engine.

## Models

### DGA Detection (`dga/`)
- `combined_dga_model.pkl`: XGBoost classifier for Domain Generation Algorithm detection
- `ngram_vectorizer.pkl`: Character n-gram feature vectorizer
- Trained on: DGA domain dataset (benign + malicious domains)
- Features: n-grams + 9 handcrafted features (entropy, length, digit ratio, vowel ratio, etc.)

### DNS Tunnel Detection (`dns_tunnel/`)
- `dns_tunnel_model.pkl`: XGBoost classifier for DNS tunneling detection
- Features: query length, entropy, subdomain count, numerical ratio, byte ratios

## Training

Training scripts are located in `research/dga/` and `research/dns_tunnel/`.
See the research directory for model retraining and feature engineering.

## Usage

Models are loaded automatically by the corresponding detectors in `src/detection/detectors/`:
- `dga.py` loads models from `models/dga/`
- `dns_tunnel.py` loads models from `models/dns_tunnel/`
