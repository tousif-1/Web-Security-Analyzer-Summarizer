# Web Security Analyzer & Summarizer
# ----------------------------------
# A self‑contained Streamlit application that:
#   • Crawls a target web application (HTML + linked JS/CSS) and captures live XHR/Fetch
#     traffic via selenium‑wire.
#   • Safely stores each artifact to disk, percent‑encoding any non‑ASCII URL chars to
#     avoid encoding errors (e.g., U+2011 in itsecgames.com).
#   • Uses a local **Ollama** LLM (e.g., `gemma3:4b`) to generate a short security
#     summary for every text asset and, on demand, a deeper OWASP‑aligned analysis with
#     recommended tests.
#   • Lets users upload their own files (JS/CSS/HTML/JSON…) for the same treatment.
#   • Presents everything in a clean Streamlit UI: expandable artifacts list, deep‑dive
#     buttons, and per‑file download links.
#
# ────────────────────────────────────────────────────────────────────────────────
#  Quick start
# ────────────────────────────────────────────────────────────────────────────────
#   python -m venv venv && source venv/bin/activate  # (Windows: venv\Scripts\activate)
#   pip install streamlit selenium-wire beautifulsoup4 requests ollama-python
#   # Ensure Chrome + matching chromedriver are on PATH, or set CHROMEDRIVER env var.
#   ollama serve &          # make sure the local Ollama server is running
#   ollama run gemma3:4b    # pull the model once (adjust name/version as needed)
#   streamlit run web_security_analyzer_app.py
#
# ────────────────────────────────────────────────────────────────────────────────

from __future__ import annotations

import textwrap
import tempfile
import pathlib
import mimetypes
import hashlib
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup, SoupStrainer
import streamlit as st
from seleniumwire import webdriver
from selenium.webdriver.chrome.options import Options
import ollama  # local LLM client (pip install ollama-python)

###############################################################################
# Data model
###############################################################################

@dataclass
class FileArtifact:
    path: pathlib.Path          # where the file was saved locally
    type: str                   # html | js | css | api_request | api_response | other
    url: str | None             # original source URL (None for uploads)
    content: str | bytes | None # raw data
    summary: Optional[str] = None   # short security summary
    details: Optional[str] = None   # deep OWASP analysis

    def hash(self) -> str:
        return hashlib.sha1(self.path.read_bytes()).hexdigest()[:10]

###############################################################################
# Helper functions
###############################################################################

def _safe_write(path: pathlib.Path, text: str):
    path.write_text(text, encoding="utf-8", errors="replace")


def _requote(url: str) -> str:
    return requests.utils.requote_uri(url)


def fetch_static(base: str, sess: requests.Session, tmp: pathlib.Path) -> List[FileArtifact]:
    arts: List[FileArtifact] = []

    root_r = sess.get(_requote(base), timeout=25, allow_redirects=True)
    root_r.raise_for_status()
    html = root_r.text
    idx = tmp / "index.html"; _safe_write(idx, html)
    arts.append(FileArtifact(idx, "html", base, html))

    soup = BeautifulSoup(html, "html.parser", parse_only=SoupStrainer(["script", "link"]))
    for tag in soup:
        src = None; ftype = None
        if tag.name == "script" and tag.get("src"):
            src, ftype = tag["src"], "js"
        elif tag.name == "link" and tag.get("rel") and "stylesheet" in tag["rel"] and tag.get("href"):
            src, ftype = tag["href"], "css"
        if not src:
            continue
        full = _requote(urljoin(base, src))
        try:
            r = sess.get(full, timeout=20); r.raise_for_status()
            fp = tmp / (hashlib.sha1(full.encode()).hexdigest()[:10] + ("." + ftype))
            if ftype in {"js", "css", "html"}:
                _safe_write(fp, r.text); arts.append(FileArtifact(fp, ftype, full, r.text))
            else:
                fp.write_bytes(r.content); arts.append(FileArtifact(fp, ftype, full, r.content))
        except Exception as e:
            st.warning(f"Failed {full}: {e}")
    return arts


def capture_api(base: str, tmp: pathlib.Path) -> List[FileArtifact]:
    opts = Options(); opts.add_argument("--headless=new"); opts.add_argument("--disable-gpu"); opts.add_argument("--no-sandbox")
    drv = webdriver.Chrome(options=opts); drv.scopes = [r".*"]; drv.set_page_load_timeout(40)
    out: List[FileArtifact] = []
    try:
        drv.get(_requote(base)); drv.implicitly_wait(8)
        for rq in drv.requests:
            if rq.response is None: continue
            ct = rq.response.headers.get("Content-Type", "")
            if not any(x in ct for x in ("application/json", "text/plain", "application/xml")):
                continue
            try: body = rq.response.body.decode("utf-8", errors="replace")
            except: body = "<binary payload>"
            req_p = tmp / f"api_req_{hashlib.sha1(rq.url.encode()).hexdigest()[:8]}.txt"
            _safe_write(req_p, f"{rq.method} {rq.url}\n\n{rq.headers}\n\n{rq.body or ''}")
            out.append(FileArtifact(req_p, "api_request", rq.url, req_p.read_text()))
            res_p = tmp / f"api_res_{hashlib.sha1(rq.url.encode()).hexdigest()[:8]}.txt"
            _safe_write(res_p, body)
            out.append(FileArtifact(res_p, "api_response", rq.url, body))
    finally:
        drv.quit()
    return out


def short_summary(text: str, role: str) -> str:
    prompt = (
        "You are a senior application security tester. Provide a ≤120‑word, "
        f"bullet‑friendly security summary of the following {role}, highlighting potential vulnerabilities."
    )
    try:
        return ollama.generate(model="gemma3:4b", prompt=prompt+"\n\n"+text[:12000], stream=False,
                               options={"temperature":0.2,"max_tokens":300})["response"].strip()
    except Exception as e:
        return f"[LLM error: {e}]"


def deep_dive(text: str, ftype: str) -> str:
    prompt = textwrap.dedent(f"""
        You are an expert pentester using the OWASP Web Security Testing Guide.
        Analyse the following {ftype} file and produce:
          • Purpose overview
          • Critical code walkthrough
          • Potential vulnerabilities/misconfigurations (with OWASP refs)
          • Manual or automated tests to confirm each finding
        Limit to 500 words and quote only relevant lines.
        --- BEGIN ---
        {text[:12000]}
        --- END ---
    """)
    try:
        return ollama.generate(model="gemma3:4b", prompt=prompt, stream=False,
                               options={"temperature":0.1,"max_tokens":700})["response"].strip()
    except Exception as e:
        return f"[LLM error: {e}]"

###############################################################################
# Streamlit UI
###############################################################################

def main():
    st.set_page_config(page_title="Web Security Analyzer", layout="wide")
    st.title("🔍 Web Security Analyzer & Summarizer")

    with st.sidebar:
        st.header("Crawl Target")
        url = st.text_input("URL of web application:")
        crawl_btn = st.button("Fetch & Analyze", disabled=not url)
        st.markdown("---")
        uploads = st.file_uploader("Or upload files for analysis", accept_multiple_files=True)

    if "arts" not in st.session_state:
        st.session_state.arts: List[FileArtifact] = []

    # Handle uploads
    if uploads:
        up_dir = pathlib.Path(tempfile.mkdtemp(prefix="sec_up_"))
        for uf in uploads:
            p = up_dir / uf.name; p.write_bytes(uf.read())
            mime = mimetypes.guess_type(uf.name)[0] or ""
            if "javascript" in mime or p.suffix.lower()==".js": t="js"
            elif "css" in mime or p.suffix.lower()==".css": t="css"
            elif "html" in mime or p.suffix.lower() in {".html",".htm"}: t="html"
            else: t="other"
            c = p.read_text(errors="replace") if t!="other" else p.read_bytes()
            st.session_state.arts.append(FileArtifact(p,t,None,c))
        uploads.clear()

    # Crawl
    if crawl_btn and url:
        with st.spinner("Crawling & capturing …"):
            tmp = pathlib.Path(tempfile.mkdtemp(prefix="sec_crawl_"))
            sess = requests.Session(); sess.headers["User-Agent"] = "Mozilla/5.0 (sec-analyzer)"
            try:
                st.session_state.arts.extend(fetch_static(url, sess, tmp))
                st.session_state.arts.extend(capture_api(url, tmp))
            except Exception as e:
                st.error(f"Crawl failed: {e}")

    # Summaries
    for a in st.session_state.arts:
        if a.summary is None and isinstance(a.content, str):
            a.summary = short_summary(a.content, a.type)

    # ──────────────────────────────────────────
    # Report UI
    # ──────────────────────────────────────────
    if not st.session_state.arts:
        st.info("Provide a URL or upload files to start.")
        return

    st.subheader("📄 Collected Artifacts")
    for i, a in enumerate(st.session_state.arts):
        with st.expander(f"{i+1}. [{a.type.upper()}] {a.path.name} ({a.hash()})"):
            st.markdown("**Short Summary:**")
            st.markdown(a.summary or "*Binary content – no summary*")
            if isinstance(a.content, str):
                if st.button(f"🔬 Deep‑Dive {i+1}", key=f"dd{i}"):
                    if a.details is None:
                        with st.spinner("Generating deep dive …"):
                            a.details = deep_dive(a.content, a.type)
                    st.markdown(a.details)
            st.download_button("⬇ Download", data=a.path.read_bytes(), file_name=a.path.name)

if __name__ == "__main__":
    main()
