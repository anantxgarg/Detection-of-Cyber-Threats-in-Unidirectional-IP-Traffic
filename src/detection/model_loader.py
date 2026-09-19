"""Centralized model loading utility for detection models."""
from pathlib import Path
from typing import Any
import joblib


def get_project_root() -> Path:
    """Get project root directory (3 levels up from this file)."""
    return Path(__file__).resolve().parents[2]


def load_model(model_name: str, subdir: str = "") -> Any:
    """
    Load a model from the canonical models directory.
    
    Args:
        model_name: Name of the model file (e.g., "combined_dga_model.pkl")
        subdir: Subdirectory under models/ (e.g., "dga", "dns_tunnel")
    
    Returns:
        Loaded model object
    
    Raises:
        FileNotFoundError: If model file doesn't exist
    """
    model_dir = get_project_root() / "models"
    if subdir:
        model_dir = model_dir / subdir
    
    model_path = model_dir / model_name
    
    if not model_path.exists():
        raise FileNotFoundError(
            f"Model not found: {model_path}\n"
            f"Ensure model files are in the models/ directory."
        )
    
    return joblib.load(model_path)
