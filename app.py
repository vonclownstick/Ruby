#!/usr/bin/env python3
"""
Ruby – PubMed Reference Verifier (Async Version - Pre-Batching)
Enhanced with enterprise-level security features
"""
import re, time, unicodedata, asyncio, hashlib, secrets, logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta

import aiohttp, uvicorn
from Bio import Entrez
from fastapi import FastAPI, Form, Request, HTTPException, Depends, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jinja2 import TemplateNotFound
from rapidfuzz import fuzz
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

# ───────────────────────── SECURITY CONFIGURATION ──────────────────────────
import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Security Settings
ACCESS_PASSWORD = os.environ.get("ACCESS_PASSWORD", "Cassowary")
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_urlsafe(32))
SESSION_DURATION = 7 * 24 * 60 * 60  # 7 days in seconds
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_DURATION = 5 * 60  # 5 minutes in seconds
CLEANUP_INTERVAL = 60 * 60  # 1 hour in seconds

# Security Storage (In production, use Redis or database)
AUTHENTICATED_SESSIONS: Set[str] = set()
SESSION_DATA: Dict[str, Dict] = {}  # session_token -> {ip, created_at, last_access}
LOGIN_ATTEMPTS: Dict[str, Dict] = {}  # ip -> {count, last_attempt, locked_until}

# Security Headers
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval' fonts.googleapis.com fonts.gstatic.com"
}

# ───────────────────────── LOGGING SETUP ──────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ───────────────────────── ORIGINAL SETTINGS ──────────────────────────
Entrez.email = os.environ.get("NCBI_EMAIL", "research@example.com")
Entrez.api_key = os.environ.get("NCBI_API_KEY")

# Conservative rate limiting to avoid 429 errors
RATE_LIMIT_SEC = 0.2 if os.environ.get("NCBI_API_KEY") else 0.5
SEARCH_RETMAX = 200  # Increased retrieval
STRICT_THRESHOLD = 88
LOOSE_THRESHOLD = 75
MAX_CONCURRENT = 3  # Conservative concurrent processing

# ───────────────────────── SECURITY UTILITIES ─────────────────────────
def get_client_ip(request: Request) -> str:
    """Get client IP address with proxy support"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.client.host

def create_session_token(ip: str) -> str:
    """Create a cryptographically secure session token"""
    timestamp = str(int(time.time()))
    random_data = secrets.token_urlsafe(32)
    data = f"{ip}:{timestamp}:{random_data}:{SESSION_SECRET}"
    return hashlib.sha256(data.encode()).hexdigest()

def is_session_valid(token: str, ip: str) -> bool:
    """Validate session token and IP"""
    if not token or token not in AUTHENTICATED_SESSIONS:
        return False
    
    session_info = SESSION_DATA.get(token)
    if not session_info:
        return False
    
    # Check IP match
    if session_info["ip"] != ip:
        logger.warning(f"Session IP mismatch: expected {session_info['ip']}, got {ip}")
        cleanup_session(token)
        return False
    
    # Check expiration
    if time.time() - session_info["created_at"] > SESSION_DURATION:
        logger.info(f"Session expired for IP {ip}")
        cleanup_session(token)
        return False
    
    # Update last access
    session_info["last_access"] = time.time()
    return True

def cleanup_session(token: str):
    """Clean up a specific session"""
    AUTHENTICATED_SESSIONS.discard(token)
    SESSION_DATA.pop(token, None)

def cleanup_expired_sessions():
    """Clean up expired sessions and login attempts"""
    current_time = time.time()
    expired_tokens = []
    
    for token, info in SESSION_DATA.items():
        if current_time - info["created_at"] > SESSION_DURATION:
            expired_tokens.append(token)
    
    for token in expired_tokens:
        cleanup_session(token)
    
    # Clean up old login attempts
    expired_ips = []
    for ip, attempt_info in LOGIN_ATTEMPTS.items():
        if current_time - attempt_info["last_attempt"] > LOGIN_LOCKOUT_DURATION:
            expired_ips.append(ip)
    
    for ip in expired_ips:
        LOGIN_ATTEMPTS.pop(ip, None)
    
    if expired_tokens or expired_ips:
        logger.info(f"Cleaned up {len(expired_tokens)} expired sessions and {len(expired_ips)} old login attempts")

def is_ip_locked(ip: str) -> bool:
    """Check if IP is locked due to too many failed attempts"""
    if ip not in LOGIN_ATTEMPTS:
        return False
    
    attempt_info = LOGIN_ATTEMPTS[ip]
    if attempt_info["count"] >= MAX_LOGIN_ATTEMPTS:
        if time.time() < attempt_info.get("locked_until", 0):
            return True
        else:
            # Lock expired, reset attempts
            LOGIN_ATTEMPTS[ip] = {"count": 0, "last_attempt": time.time(), "locked_until": 0}
    
    return False

def record_login_attempt(ip: str, success: bool):
    """Record login attempt and handle rate limiting"""
    current_time = time.time()
    
    if ip not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip] = {"count": 0, "last_attempt": current_time, "locked_until": 0}
    
    if success:
        # Reset on successful login
        LOGIN_ATTEMPTS[ip] = {"count": 0, "last_attempt": current_time, "locked_until": 0}
        logger.info(f"Successful login from IP {ip}")
    else:
        # Increment failed attempts
        LOGIN_ATTEMPTS[ip]["count"] += 1
        LOGIN_ATTEMPTS[ip]["last_attempt"] = current_time
        
        if LOGIN_ATTEMPTS[ip]["count"] >= MAX_LOGIN_ATTEMPTS:
            LOGIN_ATTEMPTS[ip]["locked_until"] = current_time + LOGIN_LOCKOUT_DURATION
            logger.warning(f"IP {ip} locked for {LOGIN_LOCKOUT_DURATION/60} minutes after {MAX_LOGIN_ATTEMPTS} failed attempts")
        else:
            logger.warning(f"Failed login attempt from IP {ip} (attempt {LOGIN_ATTEMPTS[ip]['count']}/{MAX_LOGIN_ATTEMPTS})")

# ───────────────────────── SECURITY MIDDLEWARE ─────────────────────────
class SecurityMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Add security headers
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        
        return response

def get_session_token(request: Request) -> Optional[str]:
    """Extract session token from cookies"""
    return request.cookies.get("session_token")

def require_auth(request: Request) -> str:
    """Dependency to require authentication"""
    token = get_session_token(request)
    ip = get_client_ip(request)
    
    if not token or not is_session_valid(token, ip):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    return token

# ───────────────────────── ORIGINAL DATA STRUCTURES ──────────────────────────
@dataclass
class Reference:
    raw: str
    title: str
    first_author: str
    year: str
    pmid: Optional[str] = None
    status: str = "UNMATCHED"
    pubmed_title: str = ""
    pubmed_first_author: str = ""
    pubmed_year: str = ""

# ───────────────────────── ORIGINAL UTILITIES ─────────────────────────
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
    quote_pattern = r'["\u201C\u201D\u2018\u2019\u0060\u2033\u201F\u201E\u201A\u2032\u201B]'
    title = re.sub(quote_pattern, '', title)
    
    # Also remove other problematic punctuation that can break searches
    title = re.sub(r'[()<>[\]{}]', ' ', title)
    
    # Clean up multiple spaces
    title = re.sub(r"\s+", " ", title).strip()
    
    return title

def best_similarity(a: str, b: str) -> int:
    return max(fuzz.token_set_ratio(a, b),
               fuzz.partial_ratio(a, b),
               fuzz.QRatio(a, b))

def extract_key_words(title: str, max_words: int = 3) -> List[str]:
    """Extract key words from title, removing stop words"""
    title_words = re.findall(r'\b[A-Za-z]{4,}\b', title.lower())
    stop_words = {'with', 'from', 'this', 'that', 'they', 'have', 'were', 'been', 
                  'their', 'said', 'each', 'which', 'what', 'there', 'will', 'would', 
                  'only', 'other', 'when', 'time', 'very', 'also', 'your', 'work', 
                  'life', 'should', 'after', 'being', 'made', 'before', 'here', 
                  'through', 'than', 'where', 'among', 'most', 'study', 'analysis',
                  'using', 'based', 'data', 'results', 'effects', 'patients'}
    key_words = [w for w in title_words if w not in stop_words][:max_words]
    return key_words

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
        parts = [p.strip() for p in line_clean.split(".") if p.strip()]
        if len(parts) >= 1:
            first_part = parts[0]
            author_match = re.search(r"^([A-Z][a-z]+(?:\s+[A-Z]+)*)", first_part)
            if author_match and re.search(r"[A-Z][a-z]+\s+[A-Z]", first_part):
                first_author = author_match.group(1)
                title = parts[1] if len(parts) > 1 else ""
            else:
                title = first_part
                first_author = ""
        else:
            title = line_clean
            first_author = ""
        
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
    
    # Pattern matching for different author formats
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
    elif author_pattern2:
        first_author = author_pattern2.group(1)
        title = parts[1] if len(parts) > 1 else ""
    elif author_pattern4:
        first_author = author_pattern4.group(1)
        title = parts[1] if len(parts) > 1 else ""
    elif author_pattern3 and not re.search(r"^(The|A|An)\s", first_part):
        first_author = author_pattern3.group(1)
        title = parts[1] if len(parts) > 1 else ""
    elif org_pattern:
        org_match = re.search(r"^([^.]+)", first_part)
        first_author = org_match.group(1)[:50] if org_match else ""
        title = parts[1] if len(parts) > 1 else ""
    else:
        title = first_part
        first_author = ""
        
        # Try to find author in subsequent parts
        for i, part in enumerate(parts[1:], 1):
            later_author = re.search(r"^([A-Z][a-z]+(?:-[A-Z][a-z]+)?)\s+[A-Z]{1,3}", part)
            if later_author:
                first_author = later_author.group(1)
                break
    
    return Reference(raw=original, title=title, first_author=first_author, year=year)

# ───────────────────────── ASYNC PUBMED HELPERS ─────────────────────
async def esearch_async(session: aiohttp.ClientSession, term: str, retries: int = 3) -> List[str]:
    """Async version of PubMed search with retry logic"""
    url = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi"
    params = {
        "db": "pubmed", 
        "retmode": "json",
        "retmax": SEARCH_RETMAX, 
        "term": term
    }
    
    if Entrez.api_key:
        params["api_key"] = Entrez.api_key
    
    for attempt in range(retries):
        try:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 429:  # Too Many Requests
                    wait_time = (2 ** attempt) * 1.0  # Exponential backoff: 1s, 2s, 4s
                    print(f"Rate limited, waiting {wait_time}s before retry {attempt + 1}/{retries}")
                    await asyncio.sleep(wait_time)
                    continue
                
                response.raise_for_status()
                data = await response.json()
                return data.get("esearchresult", {}).get("idlist", [])
                
        except aiohttp.ClientError as e:
            if attempt == retries - 1:  # Last attempt
                print(f"Search error for term '{term}': {e}")
                return []
            else:
                wait_time = (2 ** attempt) * 0.5
                await asyncio.sleep(wait_time)
        except Exception as e:
            print(f"Search error for term '{term}': {e}")
            return []
    
    return []

async def esummary_async(session: aiohttp.ClientSession, pmids: List[str], retries: int = 3) -> Dict[str, Dict]:
    """Async version of PubMed summary with retry logic"""
    if not pmids:
        return {}
    
    url = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi"
    params = {
        "db": "pubmed", 
        "retmode": "json", 
        "id": ",".join(pmids)
    }
    
    if Entrez.api_key:
        params["api_key"] = Entrez.api_key
    
    for attempt in range(retries):
        try:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 429:  # Too Many Requests
                    wait_time = (2 ** attempt) * 1.0  # Exponential backoff
                    print(f"Rate limited on summary, waiting {wait_time}s before retry {attempt + 1}/{retries}")
                    await asyncio.sleep(wait_time)
                    continue
                
                response.raise_for_status()
                data = await response.json()
                res = data.get("result", {})
                return {pid: res[pid] for pid in pmids if pid in res and isinstance(res[pid], dict)}
                
        except aiohttp.ClientError as e:
            if attempt == retries - 1:  # Last attempt
                print(f"Summary error for PMIDs {pmids}: {e}")
                return {}
            else:
                wait_time = (2 ** attempt) * 0.5
                await asyncio.sleep(wait_time)
        except Exception as e:
            print(f"Summary error for PMIDs {pmids}: {e}")
            return {}
    
    return {}

def _commit(ref: Reference, summ: Dict, status: str, pmid: str) -> Reference:
    ref.status = status
    ref.pmid = pmid
    ref.pubmed_title = summ.get("title", "")
    ref.pubmed_first_author = summ.get("authors", [{}])[0].get("name", "") if summ.get("authors") else ""
    ref.pubmed_year = summ.get("pubdate", "")[:4] if summ.get("pubdate") else ""
    return ref

async def try_search_strategy(session: aiohttp.ClientSession, ref: Reference, search_term: str, strategy_name: str) -> Optional[Reference]:
    """Try a single search strategy and return result if successful"""
    print(f"  {strategy_name}: {search_term}")
    
    ids = await esearch_async(session, search_term)
    if not ids:
        return None
    
    # Small delay between search and summary
    await asyncio.sleep(RATE_LIMIT_SEC)
    
    summ = await esummary_async(session, ids)
    if not summ:
        return None
    
    best_id = max(summ, key=lambda pid: best_similarity(ref.title.lower(), summ[pid].get("title", "").lower()))
    score = best_similarity(ref.title.lower(), summ[best_id].get("title", "").lower())
    
    print(f"    Best match score: {score}")
    
    if score >= STRICT_THRESHOLD:
        return _commit(ref, summ[best_id], "MATCHED", best_id)
    elif score >= LOOSE_THRESHOLD:
        return _commit(ref, summ[best_id], "AMBIGUOUS", best_id)
    
    return None

async def match_against_pubmed_async(session: aiohttp.ClientSession, ref: Reference) -> Reference:
    """Async version with sequential search strategies"""
    if ref.status == "AMBIGUOUS" or not ref.title.strip():
        print(f"    Skipping PubMed search - status: {ref.status}, title empty: {not ref.title.strip()}")
        return ref

    title_q = clean_title_for_query(ref.title)
    print(f"Processing: {ref.title[:50]}... (Author: {ref.first_author}, Year: {ref.year})")

    # Quick exit for references without enough info
    if not ref.first_author and not ref.year and len(extract_key_words(title_q)) < 2:
        print("  Insufficient information for reliable matching")
        ref.status = "UNMATCHED"
        return ref

    key_words = extract_key_words(title_q, 3)
    
    # All 5 strategies in priority order - try sequentially and stop at first good match
    strategies = []
    
    # Strategy 1: Title keywords + Author + Year (highest precision)
    if ref.first_author and ref.year and key_words:
        strategies.append((
            f'{" ".join(key_words)} AND {ref.first_author}[AUTH] AND {ref.year}[DP]',
            "Keywords+Author+Year"
        ))
    
    # Strategy 2: Author + Year (high precision for unique authors)
    if ref.first_author and ref.year:
        strategies.append((
            f'{ref.first_author}[AUTH] AND {ref.year}[DP]',
            "Author+Year"
        ))
    
    # Strategy 3: Title keywords + Author (no year restriction)
    if ref.first_author and key_words:
        strategies.append((
            f'{" ".join(key_words)} AND {ref.first_author}[AUTH]',
            "Keywords+Author"
        ))
    
    # Strategy 4: Natural language search (broader)
    if ref.first_author and ref.year and key_words:
        strategies.append((
            f'{ref.first_author} {ref.year} {" ".join(key_words)}',
            "Natural Language"
        ))
    
    # Strategy 5: Title keywords only (for papers without clear authors)
    if key_words:
        extended_keywords = extract_key_words(title_q, 4 if not ref.first_author else 3)
        strategies.append((
            ' '.join(extended_keywords),
            "Keywords Only"
        ))

    # Try strategies in order, stopping at first successful match
    for i, (search_term, strategy_name) in enumerate(strategies):
        result = await try_search_strategy(session, ref, search_term, strategy_name)
        if result and result.status in ["MATCHED", "AMBIGUOUS"]:
            return result
        
        # Delay between different strategies
        if i < len(strategies) - 1:  # Don't delay after last strategy
            await asyncio.sleep(RATE_LIMIT_SEC)

    ref.status = "UNMATCHED"
    print(f"    No suitable match found - setting status to UNMATCHED")
    return ref

async def process_single_reference_async(session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, ref: Reference, index: int) -> Reference:
    """Process a single reference with concurrency control"""
    async with semaphore:
        print(f"\n--- Processing reference {index} against PubMed ---")
        original_status = ref.status
        processed_ref = await match_against_pubmed_async(session, ref)
        print(f"Status changed from '{original_status}' to '{processed_ref.status}'")
        return processed_ref

# ───────────────────────── ASYNC MAIN PIPELINE ─────────────────────
async def process_block_async(text: str) -> List[Reference]:
    """Main async processing pipeline"""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    print(f"\nProcessing {len(lines)} non-empty lines")
    print(f"Using NCBI API key: {'Yes' if Entrez.api_key else 'No'}")
    print(f"Rate limit: {RATE_LIMIT_SEC}s, Max concurrent: {MAX_CONCURRENT}")
    
    # Parse all references first (this is fast)
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
    
    if not valid_refs:
        return []
    
    # Create HTTP session with optimized settings
    connector = aiohttp.TCPConnector(
        limit=20,  # Total connection pool size
        limit_per_host=10,  # Max connections per host
        ttl_dns_cache=300,  # DNS cache TTL
        use_dns_cache=True,
    )
    
    timeout = aiohttp.ClientTimeout(total=60, connect=10)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # Use semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)
        
        # Process all references concurrently
        tasks = [
            process_single_reference_async(session, semaphore, ref, i+1) 
            for i, ref in enumerate(valid_refs)
        ]
        
        # Wait for all tasks to complete
        processed_refs = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle any exceptions
        final_refs = []
        for i, result in enumerate(processed_refs):
            if isinstance(result, Exception):
                print(f"Error processing reference {i+1}: {result}")
                # Return original reference with error status
                valid_refs[i].status = "UNMATCHED"
                final_refs.append(valid_refs[i])
            else:
                final_refs.append(result)
    
    # Debug: Print final status counts
    final_counts = {}
    for ref in final_refs:
        final_counts[ref.status] = final_counts.get(ref.status, 0) + 1
    print(f"\nFinal status counts: {final_counts}")
    
    return final_refs

# ───────────────────────── FASTAPI APPLICATION ────────────────────
app = FastAPI(title="Ruby - PubMed Reference Verifier")

# Add security middleware
app.add_middleware(SecurityMiddleware)

templates = Jinja2Templates(directory="templates")

# ───────────────────────── SECURITY ENDPOINTS ────────────────────
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None):
    """Display login page"""
    ip = get_client_ip(request)
    
    # Check if already authenticated
    token = get_session_token(request)
    if token and is_session_valid(token, ip):
        return RedirectResponse("/", status_code=302)
    
    # Check if IP is locked
    if is_ip_locked(ip):
        remaining_time = LOGIN_ATTEMPTS[ip].get("locked_until", 0) - time.time()
        error = f"Too many failed attempts. Please try again in {int(remaining_time/60)} minutes."
    
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
        "max_attempts": MAX_LOGIN_ATTEMPTS
    })

@app.post("/login")
async def login(request: Request, password: str = Form(...)):
    """Handle login submission"""
    ip = get_client_ip(request)
    
    # Check if IP is locked
    if is_ip_locked(ip):
        remaining_time = LOGIN_ATTEMPTS[ip].get("locked_until", 0) - time.time()
        error = f"Too many failed attempts. Please try again in {int(remaining_time/60)} minutes."
        return await login_page(request, error)
    
    # Validate password
    if password == ACCESS_PASSWORD:
        # Create session
        session_token = create_session_token(ip)
        AUTHENTICATED_SESSIONS.add(session_token)
        SESSION_DATA[session_token] = {
            "ip": ip,
            "created_at": time.time(),
            "last_access": time.time()
        }
        
        record_login_attempt(ip, success=True)
        
        # Set secure cookie
        response = RedirectResponse("/", status_code=302)
        is_https = request.url.scheme == "https" or request.headers.get("X-Forwarded-Proto") == "https"
        
        response.set_cookie(
            key="session_token",
            value=session_token,
            max_age=SESSION_DURATION,
            httponly=True,
            secure=is_https,  # Only send over HTTPS in production
            samesite="strict"
        )
        
        return response
    else:
        record_login_attempt(ip, success=False)
        error = "Invalid password. Please try again."
        return await login_page(request, error)

@app.get("/logout")
async def logout(request: Request):
    """Handle logout"""
    token = get_session_token(request)
    if token:
        cleanup_session(token)
        logger.info(f"User logged out from IP {get_client_ip(request)}")
    
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("session_token")
    return response

# ───────────────────────── MAIN APPLICATION ENDPOINTS ────────────────────
@app.get("/", response_class=HTMLResponse)
async def root(request: Request, _: str = Depends(require_auth)):
    """Main application page - requires authentication"""
    return templates.TemplateResponse("index.html", {
        "request": request,
        "matched_count": 0,
        "ambiguous_count": 0,
        "unmatched_count": 0,
        "logout_url": "/logout"
    })

@app.post("/process", response_class=HTMLResponse)
async def process_endpoint(request: Request, reference_text: str = Form(...), _: str = Depends(require_auth)):
    """Process references - requires authentication"""
    try:
        print(f"\n{'='*60}")
        print(f"Processing new request with {len(reference_text.splitlines())} lines")
        print(f"Using NCBI API key: {'Yes' if Entrez.api_key else 'No'}")
        print(f"Rate limit: {RATE_LIMIT_SEC}s, Max concurrent: {MAX_CONCURRENT}")
        print(f"{'='*60}")
        
        start_time = time.time()
        
        # Use async processing
        refs = await process_block_async(reference_text)
        
        processing_time = time.time() - start_time
        print(f"\nTotal processing time: {processing_time:.2f} seconds")
        
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
                unmatched += 1
        
        total_processed = matched + ambiguous + unmatched
        print(f"\nFINAL COUNTS:")
        print(f"  Matched: {matched}")
        print(f"  Ambiguous: {ambiguous}")
        print(f"  Unmatched: {unmatched}")
        print(f"  Total: {total_processed}")
        print(f"  References processed: {len(refs)}")
        print(f"  Average time per reference: {processing_time/max(len(refs), 1):.2f}s")

        blocks = []
        for i, r in enumerate(refs, 1):
            cls = ("unmatched-ref-text" if r.status == "UNMATCHED"
                   else "ambiguous-ref-text" if r.status == "AMBIGUOUS"
                   else "")
            sym = "✓" if r.status == "MATCHED" else \
                  "?" if r.status == "AMBIGUOUS" else "✗"
            
            # Clean title for display
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
            "logout_url": "/logout"
        })
    except TemplateNotFound:
        return HTMLResponse("Template not found", status_code=500)
    except Exception as exc:
        print(f"Error in processing: {exc}")
        import traceback
        traceback.print_exc()
        return HTMLResponse(f"Error: {exc}", status_code=500)

# ───────────────────────── STARTUP TASKS ────────────────────
@app.on_event("startup")
async def startup_event():
    """Initialize security and cleanup tasks"""
    logger.info("🔐 Ruby starting with enterprise security features")
    logger.info(f"Session duration: {SESSION_DURATION/3600:.1f} hours")
    logger.info(f"Login attempts limit: {MAX_LOGIN_ATTEMPTS}")
    logger.info(f"Using password: {'Yes' if ACCESS_PASSWORD != 'Cassowary' else 'No (using default)'}")
    
    # Start cleanup task
    asyncio.create_task(periodic_cleanup())

async def periodic_cleanup():
    """Periodic cleanup of expired sessions and login attempts"""
    while True:
        await asyncio.sleep(CLEANUP_INTERVAL)
        cleanup_expired_sessions()

# ───────────────────────── EXCEPTION HANDLERS ────────────────────
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom exception handler for authentication errors"""
    if exc.status_code == 401:
        return RedirectResponse("/login", status_code=302)
    
    return HTMLResponse(f"Error: {exc.detail}", status_code=exc.status_code)

# ─────────────────────── EMBED TEMPLATES ───────────────
if __name__ == "__main__":
    import pathlib, shutil
    
    # Always recreate the templates directory and files
    if os.path.exists("templates"):
        shutil.rmtree("templates")
    
    os.makedirs("templates", exist_ok=True)
    
    # Login template
    login_tpl = pathlib.Path("templates/login.html")
    login_tpl.write_text("""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Ruby PubMed Reference Verifier</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .login-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            padding: 40px;
            max-width: 400px;
            width: 100%;
            text-align: center;
        }
        
        .login-header {
            margin-bottom: 30px;
        }
        
        .login-header h1 {
            color: #4f46e5;
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 8px;
        }
        
        .login-header p {
            color: #6b7280;
            font-size: 1rem;
        }
        
        .login-form {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        
        .form-group {
            text-align: left;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #374151;
        }
        
        input[type="password"] {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e5e7eb;
            border-radius: 12px;
            font-size: 16px;
            transition: border-color 0.3s ease;
            outline: none;
        }
        
        input[type="password"]:focus {
            border-color: #4f46e5;
            box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1);
        }
        
        .login-btn {
            background: linear-gradient(135deg, #4f46e5 0%, #6366f1 100%);
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(79, 70, 229, 0.3);
        }
        
        .login-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(79, 70, 229, 0.4);
        }
        
        .login-btn:active {
            transform: translateY(0);
        }
        
        .error-message {
            background: #fee2e2;
            color: #dc2626;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            border: 1px solid #fecaca;
        }
        
        .security-info {
            margin-top: 20px;
            padding: 16px;
            background: #f0f9ff;
            border-radius: 12px;
            border: 1px solid #bae6fd;
        }
        
        .security-info h3 {
            color: #0369a1;
            margin-bottom: 8px;
            font-size: 14px;
        }
        
        .security-info p {
            color: #0369a1;
            font-size: 12px;
            line-height: 1.4;
        }
        
        .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            color: #6b7280;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>🔐 Ruby</h1>
            <p>PubMed Reference Verifier</p>
        </div>
        
        {% if error %}
        <div class="error-message">
            {{ error }}
        </div>
        {% endif %}
        
        <form method="post" class="login-form">
            <div class="form-group">
                <label for="password">Access Password</label>
                <input type="password" name="password" id="password" required autofocus>
            </div>
            
            <button type="submit" class="login-btn">Access Ruby →</button>
        </form>
        
        <div class="security-info">
            <h3>🛡️ Security Features</h3>
            <p>• Sessions are IP-bound and expire after 7 days<br>
            • Maximum {{ max_attempts }} login attempts per IP<br>
            • Automatic lockout after failed attempts<br>
            • Secure cookie-based authentication</p>
        </div>
        
        <div class="footer">
            &copy; 2025 MGB Center for Quantitative Health<br>
            Enterprise Security Edition
        </div>
    </div>
    
    <script>
        // Auto-focus password field
        document.getElementById('password').focus();
        
        // Handle form submission
        document.querySelector('.login-form').addEventListener('submit', function(e) {
            const btn = document.querySelector('.login-btn');
            btn.textContent = 'Authenticating...';
            btn.disabled = true;
        });
    </script>
</body>
</html>""")
    
    # Main template (updated with logout button)
    main_tpl = pathlib.Path("templates/index.html")
    main_tpl.write_text("""\
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

        .header-buttons {
            position: absolute;
            top: 15px;
            right: 20px;
            display: flex;
            gap: 10px;
            z-index: 2;
        }

        .header-btn {
            background: rgba(255, 255, 255, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 50%;
            width: 40px;
            height: 40px;
            color: white;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            backdrop-filter: blur(10px);
            text-decoration: none;
            font-size: 1.2rem;
        }

        .header-btn:hover {
            background: rgba(255, 255, 255, 0.25);
            transform: scale(1.1);
        }

        .logout-btn {
            background: rgba(239, 68, 68, 0.2);
            border-color: rgba(239, 68, 68, 0.3);
        }

        .logout-btn:hover {
            background: rgba(239, 68, 68, 0.3);
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
            min-height: 70px;
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
            color: #4f46e5;
            font-size: 0.85rem;
            background: linear-gradient(135deg, rgba(79, 70, 229, 0.1) 0%, rgba(102, 102, 241, 0.1) 100%);
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
            
            .header-buttons {
                top: 12px;
                right: 15px;
            }
            
            .header-btn {
                width: 36px;
                height: 36px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Ruby</h1>
            <p class="subtitle">PubMed Reference Verifier - Secure Edition</p>
            <div class="header-buttons">
                <button class="header-btn" id="helpButton">?</button>
                <a href="{{ logout_url }}" class="header-btn logout-btn" title="Logout">🔐</a>
            </div>
        </div>
        
        <div class="content">
            <div class="top-section">
                <div class="instructions">
                    <h3>How to Use Ruby</h3>
                    <p>
                        Paste references → Click Process → Review results: ✓ matched, ? ambiguous, ✗ unmatched<br>
                        <small><em>Now with enterprise security and async processing!</em></small>
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
            &copy; 2025 MGB Center for Quantitative Health • Enterprise Security Edition
        </div>
    </div>

    <div id="helpModal" class="modal">
        <div class="modal-content">
            <button class="close-button" id="closeModal">&times;</button>
            <h3>💎 Ruby</h3>
            <p>A secure tool to ensure references actually exist.</p>
            <p>Now with enterprise-level security and async processing.</p>
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
                this.outputArea.innerHTML = '<div style="text-align: center; padding: 40px; color: var(--primary);">⚡ Processing references...</div>';
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
    
    port = int(os.environ.get("PORT", 8000))
    print(f"🔐 Starting Ruby Secure Edition on port {port}")
    print(f"Password: {'Custom' if ACCESS_PASSWORD != 'Cassowary' else 'Default (Cassowary)'}")
    print(f"Session duration: {SESSION_DURATION/3600:.1f} hours")
    uvicorn.run(app, host="0.0.0.0", port=port)

# Test function for debugging individual references
def test_single_reference(ref_text: str):
    """Test a single reference for debugging"""
    print(f"\n=== TESTING REFERENCE ===")
    print(f"Input: {ref_text}")
    ref = parse_reference_line(ref_text)
    print(f"Parsed - Title: '{ref.title}', Author: '{ref.first_author}', Year: '{ref.year}', Status: '{ref.status}'")
    
    if ref.status != "AMBIGUOUS":
        # For testing, we'll use a simple async wrapper
        async def test_async():
            async with aiohttp.ClientSession() as session:
                return await match_against_pubmed_async(session, ref)
        
        result = asyncio.run(test_async())
        print(f"Final Result: {result.status}, PMID: {result.pmid}")
        if result.pmid:
            print(f"PubMed Title: {result.pubmed_title}")
    else:
        print("Skipped PubMed search (marked as ambiguous)")
        result = ref
    
    return result