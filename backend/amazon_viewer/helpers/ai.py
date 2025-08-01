# backend/amazon_viewer/helpers/ai.py
import os
import requests
import logging

def summarize_title(title):
    """
    Calls a local Ollama WebUI server to summarize the item title.
    """
    if not isinstance(title, str) or not title.strip():
        return ""
    
    ollama_url = os.environ.get("OLLAMA_URL")
    api_key = os.environ.get("OLLAMA_API_KEY")
    model_name = os.environ.get("OLLAMA_MODEL")

    if not all([ollama_url, api_key, model_name]):
        logging.error("Ollama configuration is missing from environment variables.")
        return title

    prompt = f"Summarize the following product title in 3 to 5 words: '{title}'. Do not provide any additional text other than the summarized product title."
    payload = { "model": model_name, "messages": [{"role": "user", "content": prompt}] }
    headers = { "Authorization": f"Bearer {api_key}", "Content-Type": "application/json" }
    
    try:
        response = requests.post(ollama_url, json=payload, headers=headers)
        response.raise_for_status() 
        response_data = response.json()
        summary = ""
        if response_data.get("choices") and len(response_data["choices"]) > 0:
            summary = response_data["choices"][0].get("message", {}).get("content", "").strip()
        return summary if summary else title
    except Exception:
        logging.exception("An error occurred during title summarization.")
        return title
