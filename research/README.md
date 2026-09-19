# Research and Training Artifacts

This directory contains model training scripts, data analysis tools, and standalone detector prototypes used during development.

## Directory Structure

### `dga/`
- `train_model.py`: Full DGA model training pipeline
- `standalone_detector.py`: Standalone detector (not integrated with engine)
- `data/`: Training datasets
- `README.md`: DGA detector documentation

### `dns_tunnel/`
- `train_dns_model.py`: DNS tunnel model training
- `inspect_data.py`: Dataset analysis
- `check_labels.py`: Label verification
- `feature_analysis.py`: Feature engineering analysis
- `dns_features.py`: Feature extraction utilities
- `standalone_detector.py`: Standalone detector
- `data/`: Training datasets
- `README.md`: DNS tunnel detector documentation

## Usage

These scripts are not part of the production detection pipeline. They are preserved for:
- Model retraining with updated datasets
- Feature engineering experimentation
- Understanding detector logic and design decisions
- Standalone testing without full pipeline

## Production Code

The production-integrated detectors are in `src/detection/detectors/`:
- `dga.py`: Production DGA detector
- `dns_tunnel.py`: Production DNS tunnel detector

Trained models are in `models/` directory.
