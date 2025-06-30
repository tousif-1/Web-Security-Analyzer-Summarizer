# Web-Security-Analyzer-Summarizer

1. A self‑contained Streamlit application that:
2. Crawls a target web application (HTML + linked JS/CSS) and captures live XHR/Fetch traffic via selenium‑wire.
3. Safely stores each artifact to disk, percent‑encoding any non‑ASCII URL chars to avoid encoding errors (e.g., U+2011 in itsecgames.com).
4. Uses a local **Ollama** LLM (e.g., `llama3:8b`) to generate a short security summary for every text asset and, on demand, a deeper OWASP‑aligned analysis with recommended tests.
5. Lets users upload their own files (JS/CSS/HTML/JSON…) for the same treatment.
6. Presents everything in a clean Streamlit UI: expandable artifacts list, deep‑dive buttons, and per‑file download links.

##  Quick start
`python -m venv venv && source venv/bin/activate`
(Windows: venv\Scripts\activate)
`pip install streamlit selenium-wire beautifulsoup4 requests ollama-python`
*Ensure Chrome + matching chromedriver are on PATH, or set CHROMEDRIVER env var.*
`ollama serve & `         # make sure the local Ollama server is running
`ollama run llama3:8b`    # pull the model once (adjust name/version as needed)
`streamlit run web_security_analyzer_app.py`

## High-level Analysis of the application
![image](https://github.com/user-attachments/assets/e08f7923-2155-4250-b09f-a0f34f74b3a7)

## Deep Dive Analysis
![image](https://github.com/user-attachments/assets/d90c5701-752d-45c7-8289-cb2044675fe4)
