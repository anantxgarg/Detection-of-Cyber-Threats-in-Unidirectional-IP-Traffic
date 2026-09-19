#!/bin/bash
set -e

echo "Setting up Python virtual environment..."
python3 -m venv .venv

echo "Activating virtual environment..."
source .venv/bin/activate

echo "Upgrading pip..."
pip install --upgrade pip

echo "Installing requirements..."
pip install -r requirements.txt

echo "Setup complete. To activate the virtual environment, run:"
echo "source .venv/bin/activate"
