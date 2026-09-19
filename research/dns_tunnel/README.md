# DNS Tunnel Detector

## Purpose

The DNS Tunnel Detector identifies DNS traffic exhibiting characteristics
associated with DNS-based data exfiltration/tunnelling.

This detector is separate from the DGA Detector.

## Current Approach

The detector uses a lightweight XGBoost machine-learning model combined
with behavioral analysis.

### ML Features

The trained model uses:

- DNS query length
- DNS query entropy
- DNS subdomain count
- DNS numerical ratio
- Source-to-destination bytes
- Destination-to-source bytes
- Request/response byte ratio
- Log-transformed source-to-destination bytes
- Log-transformed destination-to-source bytes
- Log-transformed request/response ratio

### Behavioral Layer

The detector is designed to additionally consider:

- Query rate to the same domain
- Time-window activity
- TXT/NULL query types
- Repeated DNS activity

Redis is used for maintaining temporal state when deployed in the
full pipeline.

## Model

Model:

`dns_tunnel_model.pkl`

Algorithm:

`XGBoost binary classifier`

Labels:

- `0` → Benign
- `1` → DNS tunnelling / DNS-based exfiltration

## Current Testing

The trained baseline was evaluated using a stratified train/test split.

Initial results:

- Precision: ~1.00
- Recall: ~1.00
- F1-score: ~1.00
- ROC-AUC: 1.0000
- PR-AUC: 1.0000

These results are considered baseline results and require further
generalization/leakage validation before being treated as real-world
performance.

## Output

The detector returns:

- Prediction
- Tunnel score
- Suspicion level
- Feature evidence
- Behavioral evidence

Example:

```text
Prediction: DNS_Tunnelling
Tunnel Score: 0.9965
Suspicion Level: High