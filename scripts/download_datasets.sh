#!/bin/bash
set -e

# Change to the directory where the script is located
cd "$(dirname "$0")"
DEST_DIR="../pcaps"
mkdir -p "$DEST_DIR"

echo "Dataset Acquisition Script"
echo "--------------------------"

# Configurable URLs for datasets
# CICIDS2017 (Often requires session cookie/agreement from UNB website)
CICIDS_URL=""

# CTU-13 Sample
CTU_13_SAMPLE_URL="https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-42/botnet-capture-20110810-neris.pcap"

echo "Downloading CTU-13 sample to $DEST_DIR..."
# Uncomment to enable actual download (commented out by default to save bandwidth during dev)
# curl -L -o "$DEST_DIR/ctu13_sample.pcap" "$CTU_13_SAMPLE_URL"

echo "Download script complete. Configure CICIDS_URL or other sources as needed."
