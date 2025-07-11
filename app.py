#!/usr/bin/env python3
"""
Ruby – PubMed Reference Verifier (Fixed version)
"""
import re, time, unicodedata
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests, uvicorn
from Bio import Entrez
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from jinja2 import TemplateNotFound
from rapidfuzz import fuzz

# ───────────────────────── SETTINGS ──────────────────────────
Entrez.email      = "rperlis@gmail.com"
RATE_LIMIT_SEC    = 0.34          # polite delay
SEARCH_RETMAX     = 50            # fetch up to 50 ids
STRICT_THRESHOLD  = 88
LOOSE_THRESHOLD   = 75

# ───────────────────────── DATA ──────────────────────────────
@dataclass
class Reference:
    raw: str
    title: str
    first_author: str
    year: str
    pmid: Optional[str] = None
    status: str = "UNMATCHED"      # MATCHED / AMBIGUOUS / UNMATCHED
    pubmed_title: str = ""
    pubmed_first_author: str = ""
    pubmed_year: str = ""

# ───────────────────────── UTILITIES ─────────────────────────
def normalize(txt: str) -> str:
    txt = unicodedata.normalize("NFD", txt)
    txt = "".join(c for c in txt if unicodedata.category(c) != "Mn")
    txt = re.sub(r"[^\w\s]", " ", txt.lower())
    return re.sub(r"\s+", " ", txt).strip()

def clean_title_for_query(title: str) -> str:
    # Replace problematic Unicode characters first
    title = title.replace(""", '"').replace(""", '"')
    title = title.replace("'", "'").replace("'", "'")
    title = title.replace("–", "-").replace("—", "-")
    
    # Normalize spacing
    title = re.sub(r"\s+", " ", title).strip()
    
    # Remove ALL types of quotes and other characters that can interfere with PubMed search
    # Using character escapes to avoid quote conflicts
    quote_pattern = r'["\u201C\u201D\u2018\u2019\u0060\u2033\u201F\u201E\u201A\u2032\u201B]'
    title = re.sub(quote_pattern, '', title)
    
    # Also remove other problematic punctuation that can break searches
    title = re.sub(r'[()<>[\]{}]', ' ', title)
    
    # Clean up multiple spaces
    title = re.sub(r"\s+", " ", title).strip()
    
    print(f"    Cleaned title: '{title}'")  # Debug output
    return title

def best_similarity(a: str, b: str) -> int:
    return max(fuzz.token_set_ratio(a, b),
               fuzz.partial_ratio(a, b),
               fuzz.QRatio(a, b))

# ───────────────────────── IMPROVED PARSER ────────────────────────────
def parse_reference_line(line: str) -> Reference:
    original = line.strip()
    if not original:
        return Reference(raw="", title="", first_author="", year="",
                         status="AMBIGUOUS")

    # Remove leading number and period
    line_clean = re.sub(r"^\s*\d+\.\s*", "", original)
    
    # Extract year first (helps with parsing)
    year_match = re.search(r"\b(19|20)\d{2}\b", line_clean)
    year = year_match.group(0) if year_match else ""
    
    # Check if this looks like a web article/non-journal reference
    if re.search(r"(Accessed|Available|Retrieved|https?://|www\.)", line_clean):
        # For web articles, try to extract title and author differently
        parts = [p.strip() for p in line_clean.split(".") if p.strip()]
        if len(parts) >= 1:
            first_part = parts[0]
            # Check if first part has author pattern (LastName InitialInitial)
            author_match = re.search(r"^([A-Z][a-z]+(?:\s+[A-Z]+)*)", first_part)
            if author_match and re.search(r"[A-Z][a-z]+\s+[A-Z]", first_part):
                first_author = author_match.group(1)
                title = parts[1] if len(parts) > 1 else ""
            else:
                # Assume first part is title for web articles
                title = first_part
                first_author = ""
        else:
            title = line_clean
            first_author = ""
        
        # Web articles should be marked as ambiguous since they're not journal articles
        return Reference(raw=original, title=title, first_author=first_author, year=year, status="AMBIGUOUS")
    
    # For journal articles, split by periods
    parts = [p.strip() for p in line_clean.split(".") if p.strip()]
    
    if len(parts) < 2:
        return Reference(raw=original, title=line_clean, first_author="", year=year,
                         status="AMBIGUOUS")
    
    # Improved author extraction logic
    first_part = parts[0]
    title = ""
    first_author = ""
    
    print(f"  Analyzing first part: '{first_part}'")  # Debug
    
    # Pattern matching for different author formats
    # Look for various author patterns more comprehensively
    
    # Pattern 1: Standard format with initials - "Smith J" or "Smith JA" or "Smith J, Jones K"
    author_pattern1 = re.search(r"^([A-Z][a-z]+(?:-[A-Z][a-z]+)?)\s+([A-Z]{1,3})(?:[,\s]|$)", first_part)
    
    # Pattern 2: Multiple authors with et al - "Smith J et al" or "Smith JA, Jones KB et al"
    author_pattern2 = re.search(r"^([A-Z][a-z]+(?:-[A-Z][a-z]+)?)\s+[A-Z]{1,3}.*?\bet\s+al", first_part, re.IGNORECASE)
    
    # Pattern 3: Full name format - "Smith John" or "Smith John A"
    author_pattern3 = re.search(r"^([A-Z][a-z]+(?:-[A-Z][a-z]+)?)\s+([A-Z][a-z]+(?:\s+[A-Z])?)", first_part)
    
    # Pattern 4: Lastname, Firstname format - "Smith, John" or "Smith, J"
    author_pattern4 = re.search(r"^([A-Z][a-z]+(?:-[A-Z][a-z]+)?),\s*([A-Z](?:[a-z]+|\.))", first_part)
    
    # Pattern 5: Organization/Group author
    org_pattern = re.search(r"(Committee|Association|Organization|Society|Group|Team|Collaboration|Consortium|Study Group)", first_part, re.IGNORECASE)
    
    if author_pattern1:
        first_author = author_pattern1.group(1)
        title = parts[1] if len(parts) > 1 else ""
        print(f"    Pattern 1 match - Author: '{first_author}'")
    elif author_pattern2:
        first_author = author_pattern2.group(1)
        title = parts[1] if len(parts) > 1 else ""
        print(f"    Pattern 2 match (et al) - Author: '{first_author}'")
    elif author_pattern4:
        first_author = author_pattern4.group(1)
        title = parts[1] if len(parts) > 1 else ""
        print(f"    Pattern 4 match (Lastname, First) - Author: '{first_author}'")
    elif author_pattern3 and not re.search(r"^(The|A|An)\s", first_part):  # Avoid titles starting with articles
        first_author = author_pattern3.group(1)
        title = parts[1] if len(parts) > 1 else ""
        print(f"    Pattern 3 match (full name) - Author: '{first_author}'")
    elif org_pattern:
        # Organization author - use first few words as "author"
        org_match = re.search(r"^([^.]+)", first_part)
        first_author = org_match.group(1)[:50] if org_match else ""  # Limit length
        title = parts[1] if len(parts) > 1 else ""
        print(f"    Organization author - Author: '{first_author}'")
    else:
        # No clear author pattern found - assume first part is title
        title = first_part
        first_author = ""
        print(f"    No author pattern found - treating as title")
        
        # Try to find author in subsequent parts
        for i, part in enumerate(parts[1:], 1):
            # Look for author patterns in later parts
            later_author = re.search(r"^([A-Z][a-z]+(?:-[A-Z][a-z]+)?)\s+[A-Z]{1,3}", part)
            if later_author:
                first_author = later_author.group(1)
                print(f"    Found author in part {i+1}: '{first_author}'")
                break
    
    print(f"  Final parsing - Title: '{title[:50]}...', Author: '{first_author}', Year: '{year}'")
    return Reference(raw=original, title=title, first_author=first_author, year=year)

# ───────────────────────── PUBMED HELPERS ────────────────────
def esearch(term: str) -> List[str]:
    url = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi"
    params = {"db": "pubmed", "retmode": "json",
              "retmax": SEARCH_RETMAX, "term": term}
    try:
        response = requests.get(url, params=params, timeout=15)
        response.raise_for_status()
        return response.json().get("esearchresult", {}).get("idlist", [])
    except Exception as e:
        print(f"Search error for term '{term}': {e}")
        return []

def esummary(pmids: List[str]) -> Dict[str, Dict]:
    if not pmids:
        return {}
    url = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi"
    params = {"db": "pubmed", "retmode": "json", "id": ",".join(pmids)}
    try:
        data = requests.get(url, params=params, timeout=15).json()
    except Exception as e:
        print(f"Summary error for PMIDs {pmids}: {e}")
        return {}
    res = data.get("result", {})
    return {pid: res[pid] for pid in pmids if pid in res and isinstance(res[pid], dict)}

def _commit(ref: Reference, summ: Dict, status: str, pmid: str) -> Reference:
    ref.status = status
    ref.pmid   = pmid
    ref.pubmed_title        = summ.get("title", "")
    ref.pubmed_first_author = summ.get("authors", [{}])[0].get("name", "") if summ.get("authors") else ""
    ref.pubmed_year         = summ.get("pubdate", "")[:4] if summ.get("pubdate") else ""
    return ref

def match_against_pubmed(ref: Reference) -> Reference:
    if ref.status == "AMBIGUOUS" or not ref.title.strip():
        print(f"    Skipping PubMed search - status: {ref.status}, title empty: {not ref.title.strip()}")
        return ref

    title_q = clean_title_for_query(ref.title)
    print(f"Processing: {ref.title[:50]}... (Author: {ref.first_author}, Year: {ref.year})")

    # Strategy 1: Multi-author search (for common surnames like Li, Wang, etc.)
    if ref.first_author and ref.year and len(ref.first_author) <= 4:  # Common surnames are usually short
        # Extract key words from title and combine with author + year
        title_words = re.findall(r'\b[A-Za-z]{4,}\b', title_q.lower())
        stop_words = {'with', 'from', 'this', 'that', 'they', 'have', 'were', 'been', 'their', 'said', 'each', 'which', 'what', 'there', 'will', 'would', 'only', 'other', 'when', 'time', 'very', 'also', 'your', 'work', 'life', 'should', 'after', 'being', 'made', 'before', 'here', 'through', 'than', 'where', 'among', 'most'}
        key_words = [w for w in title_words if w not in stop_words][:3]
        
        if key_words:
            search1 = f'{" ".join(key_words)} AND {ref.first_author}[AUTH] AND {ref.year}[DP]'
            print(f"  Keyword+author+year search: {search1}")
            ids = esearch(search1)
            if ids:
                summ = esummary(ids)
                if summ:
                    best_id = max(summ, key=lambda pid:
                                  best_similarity(ref.title.lower(),
                                                  summ[pid].get("title", "").lower()))
                    score = best_similarity(ref.title.lower(),
                                             summ[best_id].get("title", "").lower())
                    print(f"    Best match score: {score}")
                    if score >= STRICT_THRESHOLD:
                        return _commit(ref, summ[best_id], "MATCHED", best_id)
                    elif score >= LOOSE_THRESHOLD:
                        return _commit(ref, summ[best_id], "AMBIGUOUS", best_id)

    # Strategy 2: Author + year (if available) - for less common names
    if ref.first_author and ref.year:
        search2 = f'{ref.first_author}[AUTH] AND {ref.year}[DP]'
        print(f"  Author+year search: {search2}")
        ids = esearch(search2)
        if ids:
            summ = esummary(ids)
            if summ:
                best_id = max(summ, key=lambda pid:
                              best_similarity(ref.title.lower(),
                                              summ[pid].get("title", "").lower()))
                score = best_similarity(ref.title.lower(),
                                         summ[best_id].get("title", "").lower())
                print(f"    Best match score: {score}")
                if score >= STRICT_THRESHOLD:
                    return _commit(ref, summ[best_id], "MATCHED", best_id)
                elif score >= LOOSE_THRESHOLD:
                    return _commit(ref, summ[best_id], "AMBIGUOUS", best_id)

    # Strategy 3: Title keywords + author (no year restriction)
    if ref.first_author:
        title_words = re.findall(r'\b[A-Za-z]{4,}\b', title_q.lower())
        stop_words = {'with', 'from', 'this', 'that', 'they', 'have', 'were', 'been', 'their', 'said', 'each', 'which', 'what', 'there', 'will', 'would', 'only', 'other', 'when', 'time', 'very', 'also', 'your', 'work', 'life', 'should', 'after', 'being', 'made', 'before', 'here', 'through', 'than', 'where', 'among', 'most'}
        key_words = [w for w in title_words if w not in stop_words][:3]
        
        if key_words:
            search3 = f'{" ".join(key_words)} AND {ref.first_author}[AUTH]'
            print(f"  Keywords+author search: {search3}")
            ids = esearch(search3)
            if ids:
                summ = esummary(ids)
                if summ:
                    best_id = max(summ, key=lambda pid:
                                  best_similarity(ref.title.lower(),
                                                  summ[pid].get("title", "").lower()))
                    score = best_similarity(ref.title.lower(),
                                             summ[best_id].get("title", "").lower())
                    print(f"    Best match score: {score}")
                    if score >= STRICT_THRESHOLD:
                        return _commit(ref, summ[best_id], "MATCHED", best_id)
                    elif score >= LOOSE_THRESHOLD:
                        return _commit(ref, summ[best_id], "AMBIGUOUS", best_id)

    # Strategy 4: Broad natural language search (no field tags)
    if ref.first_author and ref.year:
        title_words = re.findall(r'\b[A-Za-z]{4,}\b', title_q.lower())
        stop_words = {'with', 'from', 'this', 'that', 'they', 'have', 'were', 'been', 'their', 'said', 'each', 'which', 'what', 'there', 'will', 'would', 'only', 'other', 'when', 'time', 'very', 'also', 'your', 'work', 'life', 'should', 'after', 'being', 'made', 'before', 'here', 'through', 'than', 'where', 'among', 'most'}
        key_words = [w for w in title_words if w not in stop_words][:3]
        
        if key_words:
            search4 = f'{ref.first_author} {ref.year} {" ".join(key_words)}'
            print(f"  Natural language search: {search4}")
            ids = esearch(search4)
            if ids:
                summ = esummary(ids)
                if summ:
                    best_id = max(summ, key=lambda pid:
                                  best_similarity(ref.title.lower(),
                                                  summ[pid].get("title", "").lower()))
                    score = best_similarity(ref.title.lower(),
                                             summ[best_id].get("title", "").lower())
                    print(f"    Best match score: {score}")
                    if score >= STRICT_THRESHOLD:
                        return _commit(ref, summ[best_id], "MATCHED", best_id)
                    elif score >= LOOSE_THRESHOLD:
                        return _commit(ref, summ[best_id], "AMBIGUOUS", best_id)

    # Strategy 5: Title keywords only (for papers without clear authors)
    title_words = re.findall(r'\b[A-Za-z]{4,}\b', title_q.lower())
    stop_words = {'with', 'from', 'this', 'that', 'they', 'have', 'were', 'been', 'their', 'said', 'each', 'which', 'what', 'there', 'will', 'would', 'only', 'other', 'when', 'time', 'very', 'also', 'your', 'work', 'life', 'should', 'after', 'being', 'made', 'before', 'here', 'through', 'than', 'where', 'among', 'most'}
    key_words = [w for w in title_words if w not in stop_words][:4]
    
    if key_words:
        search5 = ' '.join(key_words)  # Natural language, no AND operators
        print(f"  Keywords natural language search: {search5}")
        ids = esearch(search5)
        if ids:
            summ = esummary(ids)
            if summ:
                best_id = max(summ, key=lambda pid:
                              best_similarity(ref.title.lower(),
                                              summ[pid].get("title", "").lower()))
                score = best_similarity(ref.title.lower(),
                                         summ[best_id].get("title", "").lower())
                print(f"    Best match score: {score}")
                if score >= STRICT_THRESHOLD:
                    return _commit(ref, summ[best_id], "MATCHED", best_id)
                elif score >= LOOSE_THRESHOLD:
                    return _commit(ref, summ[best_id], "AMBIGUOUS", best_id)

    ref.status = "UNMATCHED"
    print(f"    No suitable match found - setting status to UNMATCHED")
    return ref

# ───────────────────────── MAIN PIPELINE ─────────────────────
def process_block(text: str) -> List[Reference]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    print(f"\nProcessing {len(lines)} non-empty lines")
    
    refs = []
    for i, line in enumerate(lines):
        print(f"\n--- Parsing line {i+1}/{len(lines)} ---")
        print(f"Input: {line}")
        ref = parse_reference_line(line)
        print(f"Parsed: Title='{ref.title[:50]}...', Author='{ref.first_author}', Year='{ref.year}', Status='{ref.status}'")
        refs.append(ref)
    
    # Filter out empty references
    valid_refs = [r for r in refs if r.raw]
    print(f"\nFound {len(valid_refs)} valid references to process")
    
    # Process each reference against PubMed
    for i, r in enumerate(valid_refs):
        print(f"\n--- Processing reference {i+1}/{len(valid_refs)} against PubMed ---")
        original_status = r.status
        processed_ref = match_against_pubmed(r)
        print(f"Status changed from '{original_status}' to '{processed_ref.status}'")
        valid_refs[i] = processed_ref
        time.sleep(RATE_LIMIT_SEC)
    
    # Debug: Print final status counts
    final_counts = {}
    for ref in valid_refs:
        final_counts[ref.status] = final_counts.get(ref.status, 0) + 1
    print(f"\nFinal status counts: {final_counts}")
    
    return valid_refs

# ───────────────────────── FASTAPI / HTML ────────────────────
app       = FastAPI()
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "matched_count": 0,
        "ambiguous_count": 0,
        "unmatched_count": 0
    })

@app.post("/process", response_class=HTMLResponse)
async def process_endpoint(request: Request, reference_text: str = Form(...)):
    try:
        print(f"\n{'='*60}")
        print(f"Processing new request with {len(reference_text.splitlines())} lines")
        print(f"{'='*60}")
        
        refs = process_block(reference_text)
        
        # Calculate counts with explicit validation
        matched = 0
        ambiguous = 0
        unmatched = 0
        
        for ref in refs:
            if ref.status == "MATCHED":
                matched += 1
            elif ref.status == "AMBIGUOUS":
                ambiguous += 1
            elif ref.status == "UNMATCHED":
                unmatched += 1
            else:
                print(f"WARNING: Unexpected status '{ref.status}' for reference: {ref.title[:50]}...")
                unmatched += 1  # Default unexpected statuses to unmatched
        
        total_processed = matched + ambiguous + unmatched
        print(f"\nFINAL COUNTS:")
        print(f"  Matched: {matched}")
        print(f"  Ambiguous: {ambiguous}")
        print(f"  Unmatched: {unmatched}")
        print(f"  Total: {total_processed}")
        print(f"  References processed: {len(refs)}")

        blocks = []
        for i, r in enumerate(refs, 1):
            cls = ("unmatched-ref-text" if r.status == "UNMATCHED"
                   else "ambiguous-ref-text" if r.status == "AMBIGUOUS"
                   else "")
            sym = "✓" if r.status == "MATCHED" else \
                  "?" if r.status == "AMBIGUOUS" else "✗"
            
            # Clean title for display (remove any remaining numbering artifacts)
            display_title = re.sub(r'^\d+\.\s*', '', r.title)
            
            blocks.append(
                f"<div class='reference-item'>"
                f"<span class='{cls}'>{i}. {sym} {display_title}</span><br>"
                f"<span class='{cls}'>   First author: {r.first_author or 'N/A'}</span><br>"
                f"<span class='{cls}'>   Year: {r.year or 'N/A'}</span><br>"
                f"<span class='{cls}'>   {'PMID: ' + r.pmid if r.pmid else 'No PMID'}</span>"
                f"</div>"
            )

        return templates.TemplateResponse("index.html", {
            "request": request,
            "reference_text": reference_text,
            "output": "".join(blocks),
            "matched_count": matched,
            "ambiguous_count": ambiguous,
            "unmatched_count": unmatched,
        })
    except TemplateNotFound:
        return HTMLResponse("Template not found", status_code=500)
    except Exception as exc:
        print(f"Error in processing: {exc}")
        import traceback
        traceback.print_exc()
        return HTMLResponse(f"Error: {exc}", status_code=500)

# ─────────────────────── EMBED TEMPLATE ───────────────
if __name__ == "__main__":
    import os, pathlib
    
    # Always recreate the templates directory and file
    if os.path.exists("templates"):
        import shutil
        shutil.rmtree("templates")
    
    os.makedirs("templates", exist_ok=True)
    tpl = pathlib.Path("templates/index.html")
    
    # Force write the new template
    tpl.write_text("""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ruby - PubMed Reference Verifier</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #4f46e5;
            --primary-light: #6366f1;
            --primary-dark: #3730a3;
            --secondary: #06b6d4;
            --success: #10b981;
            --warning: #f59e0b;
            --error: #ef4444;
            --gray-50: #f8fafc;
            --gray-100: #f1f5f9;
            --gray-200: #e2e8f0;
            --gray-300: #cbd5e1;
            --gray-400: #94a3b8;
            --gray-500: #64748b;
            --gray-600: #475569;
            --gray-700: #334155;
            --gray-800: #1e293b;
            --gray-900: #0f172a;
            --gradient-bg: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --gradient-card: linear-gradient(145deg, #ffffff 0%, #f8fafc 100%);
            --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
            --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
            --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--gradient-bg);
            min-height: 100vh;
            padding: 20px;
            overflow-x: hidden;
        }
        
        .container {
            max-width: 1600px;
            margin: 0 auto;
            background: var(--gradient-card);
            border-radius: 24px;
            box-shadow: var(--shadow-xl);
            overflow: hidden;
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            min-height: calc(100vh - 40px);
            display: flex;
            flex-direction: column;
        }
        
        .header {
            background: linear-gradient(135deg, var(--primary-dark) 0%, var(--primary) 50%, var(--primary-light) 100%);
            color: white;
            padding: 25px 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }
        
        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 8px;
            text-shadow: 0 4px 8px rgba(0,0,0,0.3);
        }
        
        .header .subtitle {
            font-size: 1.1rem;
            opacity: 0.9;
            font-weight: 400;
            letter-spacing: 0.5px;
        }

        .help-button {
            position: absolute;
            top: 15px;
            right: 20px;
            background: rgba(255, 255, 255, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 50%;
            width: 40px;
            height: 40px;
            font-size: 1.2rem;
            color: white;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            backdrop-filter: blur(10px);
            z-index: 2;
        }

        .help-button:hover {
            background: rgba(255, 255, 255, 0.25);
            transform: scale(1.1);
        }
        
        .content {
            padding: 30px;
            flex-grow: 1;
            display: flex;
            flex-direction: column;
            gap: 25px;
        }
        
        .top-section {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 25px;
            margin-bottom: 15px;
        }
        
        .instructions {
            background: white;
            padding: 20px;
            border-radius: 16px;
            border: 1px solid var(--primary-light);
            position: relative;
            overflow: hidden;
        }
        
        .instructions::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--primary);
            border-radius: 2px;
        }
        
        .instructions h3 {
            color: var(--primary-dark);
            font-size: 1.2rem;
            margin-bottom: 12px;
            font-weight: 600;
        }
        
        .instructions p {
            color: var(--primary-dark);
            line-height: 1.5;
            font-size: 0.9rem;
        }
        
        .summary {
            background: var(--gradient-card);
            border: 1px solid var(--gray-200);
            border-radius: 16px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
        }
        
        .summary.all-matched {
            background: linear-gradient(135deg, #d1fae5 0%, #a7f3d0 100%);
            border-color: var(--success);
        }

        .summary.has-unmatched {
            background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
            border-color: var(--error);
        }
        
        .summary h3 {
            color: var(--gray-800);
            font-size: 1.1rem;
            margin-bottom: 12px;
            font-weight: 600;
        }
        
        .summary-stats {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
            font-size: 1rem;
        }
        
        .matched-count { 
            color: var(--success);
            font-weight: 700;
        }
        
        .ambiguous-count { 
            color: var(--secondary);
            font-weight: 700;
        }
        
        .unmatched-count {
            color: var(--error);
            font-weight: 700;
        }
        
        .main-workspace {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            align-items: stretch;
            flex-grow: 1;
            min-height: 500px;
        }
        
        .input-section, .output-section {
            display: flex;
            flex-direction: column;
            background: white;
            border-radius: 20px;
            border: 1px solid var(--gray-200);
            overflow: hidden;
            box-shadow: var(--shadow-md);
            transition: all 0.3s ease;
        }
        
        .input-section:hover, .output-section:hover {
            box-shadow: var(--shadow-lg);
            transform: translateY(-2px);
        }
        
        .section-header {
            background: var(--gray-50);
            padding: 15px 25px;
            border-bottom: 1px solid var(--gray-200);
            font-weight: 600;
            color: var(--gray-700);
            font-size: 0.95rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            min-height: 70px;  /* ADD THIS LINE */
        }
        
        .section-header .label {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .section-header .label::before {
            content: '📝';
        }
        
        .output-section .section-header .label::before {
            content: '📊';
        }
        
        .process-btn {
            background: linear-gradient(135deg, var(--success) 0%, #059669 100%);
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 25px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 6px 20px rgba(16, 185, 129, 0.3);
            position: relative;
            overflow: hidden;
            min-width: 100px;
        }
        
        .process-btn:hover {
            transform: translateY(-2px) scale(1.02);
            box-shadow: 0 8px 25px rgba(16, 185, 129, 0.4);
        }
        
        .process-btn:disabled {
            background: var(--gray-400);
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        .textarea-container, .output-container {
            flex-grow: 1;
            padding: 25px;
            display: flex;
            flex-direction: column;
        }
        
        textarea {
            width: 100%;
            min-height: 400px;
            border: 2px solid var(--gray-200);
            border-radius: 16px;
            padding: 20px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            line-height: 1.6;
            resize: vertical;
            background: var(--gray-50);
            transition: all 0.3s ease;
            outline: none;
            flex-grow: 1;
        }
        
        textarea:focus {
            border-color: var(--primary);
            background: white;
            box-shadow: 0 0 0 4px rgba(79, 70, 229, 0.1);
        }
        
        textarea::placeholder {
            color: var(--gray-400);
            font-style: italic;
        }
        
        .output-area {
            background: var(--gray-50);
            border: 2px solid var(--gray-200);
            border-radius: 16px;
            padding: 20px;
            min-height: 400px;
            overflow-y: auto;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            line-height: 1.6;
            color: var(--gray-700);
            flex-grow: 1;
            position: relative;
        }
        
        .output-area:empty::before {
            content: "Results will appear here after processing...";
            color: var(--gray-400);
            font-style: italic;
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }
        
        .reference-item {
            background: white;
            border: 1px solid var(--gray-200);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 12px;
            transition: all 0.2s ease;
            border-left: 4px solid var(--gray-300);
        }
        
        .reference-item:hover {
            box-shadow: var(--shadow-md);
            transform: translateX(4px);
        }
        
        .reference-item.matched {
            border-left-color: var(--success);
            background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
        }
        
        .reference-item.ambiguous {
            border-left-color: var(--secondary);
            background: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 100%);
        }
        
        .reference-item.unmatched {
            border-left-color: var(--error);
            background: linear-gradient(135deg, #fef2f2 0%, #fee2e2 100%);
        }
        
        .unmatched-ref-text { 
            color: var(--error);
        }
        
        .ambiguous-ref-text { 
            color: var(--secondary);
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #4f46e5;  /* CHANGE THIS from rgba(255, 255, 255, 0.8) */
            font-size: 0.85rem;
            background: linear-gradient(135deg, rgba(220, 38, 38, 0.1) 0%, rgba(124, 45, 18, 0.1) 100%);
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 2000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(8px);
            justify-content: center;
            align-items: center;
        }

        .modal.show {
            display: flex;
        }

        .modal-content {
            background: white;
            border-radius: 24px;
            padding: 40px;
            max-width: 500px;
            width: 90%;
            box-shadow: var(--shadow-xl);
            position: relative;
        }

        .modal-content h3 {
            color: var(--gray-800);
            font-size: 2rem;
            margin-bottom: 20px;
            text-align: center;
        }

        .modal-content p {
            color: var(--gray-600);
            font-size: 1.1rem;
            line-height: 1.6;
            margin-bottom: 20px;
            text-align: center;
        }

        .close-button {
            position: absolute;
            top: 16px;
            right: 20px;
            background: none;
            border: none;
            font-size: 24px;
            color: var(--gray-400);
            cursor: pointer;
            width: 32px;
            height: 32px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
        }

        .close-button:hover {
            background: var(--gray-100);
            color: var(--gray-600);
        }

        .process-indicator {
            display: flex;
            align-items: center;
            gap: 12px;
            color: var(--primary);
            font-weight: 500;
            opacity: 0;
            transform: translateY(10px);
            transition: all 0.3s ease;
            font-size: 12px;
            margin-top: 8px;
        }
        
        .process-indicator.show {
            opacity: 1;
            transform: translateY(0);
        }
        
        .spinner {
            width: 16px;
            height: 16px;
            border: 2px solid var(--gray-200);
            border-top: 2px solid var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        @media (max-width: 1200px) {
            .main-workspace {
                grid-template-columns: 1fr;
                gap: 25px;
            }
            
            .top-section {
                grid-template-columns: 1fr;
            }
        }
        
        @media (max-width: 768px) {
            body {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .content {
                padding: 20px;
            }
            
            .help-button {
                width: 36px;
                height: 36px;
                top: 12px;
                right: 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Ruby</h1>
            <p class="subtitle">PubMed Reference Verifier</p>
            <button class="help-button" id="helpButton">?</button>
        </div>
        
        <div class="content">
            <div class="top-section">
                <div class="instructions">
                    <h3>How to Use Ruby</h3>
                    <p>
                        Paste references → Click Process → Review results: ✓ matched, ? ambiguous, ✗ unmatched<br>
                        <small><em>Note: Non-journal references may not be in PubMed</em></small>
                    </p>
                </div>
                
                <div class="summary" id="summaryBox">
                    <h3>Summary</h3>
                    <div class="summary-stats">
                        <span class="matched-count" id="matchedCount">{{ matched_count or 0 }}</span> matched,
                        <span class="ambiguous-count" id="ambiguousCount">{{ ambiguous_count or 0 }}</span> ambiguous,
                        <span class="unmatched-count" id="unmatchedCount">{{ unmatched_count or 0 }}</span> unmatched
                    </div>
                </div>
            </div>
            
            <form method="post" action="/process" id="processForm">
                <div class="main-workspace">
                    <div class="input-section">
                        <div class="section-header">
                            <div class="label">Input References</div>
                            <button type="submit" class="process-btn" id="processBtn">
                                Process →
                            </button>
                        </div>
                        <div class="textarea-container">
                            <textarea 
                                name="reference_text" 
                                id="referenceTextarea" 
                                placeholder="Paste your manuscript references here..."
                            >{{ reference_text or '' }}</textarea>
                            <div class="process-indicator" id="processingStatus">
                                <div class="spinner"></div>
                                <span>Processing references...</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="output-section">
                        <div class="section-header">
                            <div class="label">Results</div>
                        </div>
                        <div class="output-container">
                            <div class="output-area" id="outputArea">{{ output | safe }}</div>
                        </div>
                    </div>
                </div>
            </form>
        </div>
        
        <div class="footer">
            &copy; 2025 MGB Center for Quantitative Health • The robots will get us in the end but not today
        </div>
    </div>

    <div id="helpModal" class="modal">
        <div class="modal-content">
            <button class="close-button" id="closeModal">&times;</button>
            <h3>💎 Ruby</h3>
            <p>A tool to ensure references actually exist.</p>
            <p>Because AI lies. It will get us in the end, but not today.</p>
            <p><strong>&copy; 2025 MGB Center for Quantitative Health</strong></p>
        </div>
    </div>

    <script>
        class RubyUI {
            constructor() {
                this.initializeElements();
                this.bindEvents();
                this.updateDisplay(0, 0, 0);
            }
            
            initializeElements() {
                this.form = document.getElementById('processForm');
                this.processBtn = document.getElementById('processBtn');
                this.processingStatus = document.getElementById('processingStatus');
                this.outputArea = document.getElementById('outputArea');
                this.summaryBox = document.getElementById('summaryBox');
                this.matchedCount = document.getElementById('matchedCount');
                this.ambiguousCount = document.getElementById('ambiguousCount');
                this.unmatchedCount = document.getElementById('unmatchedCount');
                this.helpButton = document.getElementById('helpButton');
                this.helpModal = document.getElementById('helpModal');
                this.closeModal = document.getElementById('closeModal');
            }
            
            bindEvents() {
                this.form.addEventListener('submit', (e) => this.handleSubmit(e));
                this.helpButton.addEventListener('click', () => this.showModal());
                this.closeModal.addEventListener('click', () => this.hideModal());
                this.helpModal.addEventListener('click', (e) => {
                    if (e.target === this.helpModal) this.hideModal();
                });
                
                document.addEventListener('keydown', (e) => {
                    if (e.key === 'Escape') this.hideModal();
                    if (e.key === 'F1') {
                        e.preventDefault();
                        this.showModal();
                    }
                });
            }
            
            handleSubmit(e) {
                this.processBtn.disabled = true;
                this.processBtn.textContent = 'Processing...';
                this.processBtn.style.background = 'var(--gray-400)';
                this.processingStatus.classList.add('show');
                this.outputArea.innerHTML = '<div style="text-align: center; padding: 40px; color: var(--primary);">💎 Analyzing references...</div>';
                this.updateDisplay(0, 0, 0);
            }
            
            updateDisplay(matched, ambiguous, unmatched) {
                this.matchedCount.textContent = matched;
                this.ambiguousCount.textContent = ambiguous;
                this.unmatchedCount.textContent = unmatched;
                
                this.summaryBox.classList.remove('all-matched', 'has-unmatched');
                
                if (matched > 0 && unmatched === 0 && ambiguous === 0) {
                    this.summaryBox.classList.add('all-matched');
                } else if (unmatched > 0) {
                    this.summaryBox.classList.add('has-unmatched');
                }
            }
            
            showModal() {
                this.helpModal.classList.add('show');
                document.body.style.overflow = 'hidden';
            }
            
            hideModal() {
                this.helpModal.classList.remove('show');
                document.body.style.overflow = 'auto';
            }
        }
        
        document.addEventListener('DOMContentLoaded', () => {
            const ruby = new RubyUI();
            
            const initialMatched = parseInt("{{ matched_count or 0 }}");
            const initialAmbiguous = parseInt("{{ ambiguous_count or 0 }}");
            const initialUnmatched = parseInt("{{ unmatched_count or 0 }}");
            
            ruby.updateDisplay(initialMatched, initialAmbiguous, initialUnmatched);
            
            document.querySelectorAll('.reference-item').forEach(item => {
                const text = item.textContent;
                if (text.includes('✓')) {
                    item.classList.add('matched');
                } else if (text.includes('?')) {
                    item.classList.add('ambiguous');
                } else if (text.includes('✗')) {
                    item.classList.add('unmatched');
                }
            });
        });
    </script>
</body>
</html>""")
    
    print("→ open http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)

# Test function for debugging individual references
def test_single_reference(ref_text: str):
    """Test a single reference for debugging"""
    print(f"\n=== TESTING REFERENCE ===")
    print(f"Input: {ref_text}")
    ref = parse_reference_line(ref_text)
    print(f"Parsed - Title: '{ref.title}', Author: '{ref.first_author}', Year: '{ref.year}', Status: '{ref.status}'")
    
    if ref.status != "AMBIGUOUS":
        result = match_against_pubmed(ref)
        print(f"Final Result: {result.status}, PMID: {result.pmid}")
        if result.pmid:
            print(f"PubMed Title: {result.pubmed_title}")
    else:
        print("Skipped PubMed search (marked as ambiguous)")
        result = ref
    
    return result

# Uncomment to test specific references:
# test_single_reference("Fox CW, Albert AYK, Vines TH. Recruitment of reviewers is becoming harder at some journals: a test of the influence of reviewer fatigue at six journals in ecology and evolution. Res Integr Peer Rev. 2017;2(1):3. doi:10.1186/s41073-017-0027-x")
# test_single_reference("Li ZQ, Xu HL, Cao HJ, Liu ZL, Fei YT, Liu JP. Use of Artificial Intelligence in Peer Review Among Top 100 Medical Journals. JAMA Netw Open. 2024;7(12):e2448609. doi:10.1001/jamanetworkopen.2024.48609")
# test_single_reference("Rennie D, Flanagin A. Three Decades of Peer Review Congresses. JAMA. 2018;319(4):350-353. doi:10.1001/jama.2017.20606")