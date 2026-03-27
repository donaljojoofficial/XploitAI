"""
Configuration Manager for XploitAI.
Handles persistence of API keys and system settings.
"""
import json
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dotenv is declared in requirements
    load_dotenv = None

# Define base directory
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = BASE_DIR / 'ai_config.json'

if load_dotenv:
    load_dotenv(BASE_DIR / '.env')

def get_config(key: str, default: str = None) -> str:
    """
    Retrieve a configuration value.
    Priority: Environment Variable > Config File > Default
    """
    # 1. Check Environment
    val = os.getenv(key)
    if val:
        return val
    
    # 2. Check Config File
    if not CONFIG_FILE.exists():
        return default
        
    try:
        with open(CONFIG_FILE, 'r') as f:
            data = json.load(f)
            return data.get(key, default)
    except Exception:
        return default

def set_config(key: str, value: str) -> None:
    """
    Save a configuration value to the JSON store.
    """
    data = {}
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                data = json.load(f)
        except Exception:
            pass
            
    data[key] = value
    
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f, indent=4)
