#!/usr/bin/env python3
"""
Script to ensure the required Ollama model is pulled and available.
Usage: python scripts/ensure_ollama_model.py
"""
import os
import sys
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ollama_setup")

try:
    import ollama
except ImportError:
    logger.error("Ollama SDK not installed. Run: pip install ollama")
    sys.exit(1)

try:
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

def ensure_model():
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "llama3.2:1b-instruct")
    
    client = ollama.Client(host=host)
    
    try:
        logger.info(f"Connecting to Ollama at {host}...")
        list_response = client.list()
        
        existing_models = []
        if hasattr(list_response, 'models'):
            existing_models = [m.model for m in list_response.models]
        else:
            existing_models = [m.get('name') or m.get('model') for m in list_response.get('models', [])]
            
        if model not in existing_models and f"{model}:latest" not in existing_models:
            logger.info(f"Model '{model}' missing. Pulling... (this may take a while)")
            
            if HAS_RICH:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    TimeRemainingColumn(),
                ) as progress:
                    task = progress.add_task(f"Pulling {model}", total=None)
                    for response in client.pull(model, stream=True):
                        if response.get('total'):
                            progress.update(task, total=response['total'], completed=response.get('completed', 0), description=f"Pulling {model}: {response.get('status', '')}")
                        else:
                            progress.update(task, description=f"Pulling {model}: {response.get('status', '')}")
            else:
                for progress in client.pull(model, stream=True):
                    pass
            logger.info(f"Model '{model}' pulled successfully.")
        else:
            logger.info(f"Model '{model}' is already available.")
            
    except Exception as e:
        logger.error(f"Error checking/pulling model: {e}")
        sys.exit(1)

if __name__ == "__main__":
    ensure_model()