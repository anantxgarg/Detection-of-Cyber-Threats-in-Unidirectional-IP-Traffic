# DGA Detector

A machine-learning-based Domain Generation Algorithm (DGA) detector designed to classify domain names as **Legitimate** or **DGA-generated**.

## Features

The detector uses:

* Character n-gram features
* Domain length
* Number of labels
* Longest label length
* Shannon entropy
* Digit ratio
* Vowel ratio
* Hyphen ratio
* Unique character ratio
* Maximum consecutive consonants

These features are processed using a trained Logistic Regression model.

## Project Structure

```text
DGA_Detector/
│
├── dga_detector.py
├── inspect_data.py
├── combined_dga_model.pkl
├── ngram_vectorizer.pkl
├── requirements.txt
└── README.md
```

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Running the Detector

Run:

```bash
python dga_detector.py
```

## Using the Detector in Another Module

The detector can be imported and used as follows:

```python
from dga_detector import detect_dga

result = detect_dga("google.com")

print(result)
```

The detector can also accept optional context metadata:

```python
result = detect_dga(
    "example-domain.com",
    context={
        "timestamp": "2026-08-31T16:30:00",
        "source_ip": "192.168.1.10",
        "query_type": "A"
    }
)
```

## Output Format

The detector returns a structured dictionary:

```json
{
    "detector_name": "DGA_Detector",
    "entity": {
        "type": "domain",
        "value": "example-domain.com"
    },
    "result": {
        "prediction": "DGA",
        "dga_score": 0.998,
        "suspicion_level": "High"
    },
    "evidence": {
        "features": {
            "domain_length": 18,
            "entropy": 3.2
        }
    },
    "context": {}
}
```

## Output Fields

* `prediction`: Classification result — `DGA` or `Legit`
* `dga_score`: Model probability for the DGA class
* `suspicion_level`: Human-readable interpretation of the score
* `evidence`: Extracted domain features used as supporting information
* `context`: Optional metadata associated with the DNS event

## Integration with Correlation Engine

The Correlation Engine can use the detector output as an input signal.

The primary machine-readable detection signal is:

```python
result["result"]["dga_score"]
```

The prediction and supporting evidence can also be used:

```python
result["result"]["prediction"]
result["result"]["suspicion_level"]
result["evidence"]["features"]
result["context"]
```

The DGA detector is designed to analyze domains extracted from passively observed DNS queries and return a standardized detection event for downstream correlation.
