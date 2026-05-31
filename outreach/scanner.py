"""Security header scanner for discovering leads with weak web security."""

import ssl
import socket
import time
import re
import csv
import io
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from . import database as db

try:
    from ddgs import DDGS
    HAS_DDGS = True
except ImportError:
    try:
        from duckduckgo_search import DDGS
        HAS_DDGS = True
    except ImportError:
        HAS_DDGS = False


# --- Security header definitions ---

SECURITY_HEADERS = {
    # header: (weight, severity, description)
    "Strict-Transport-Security": (15, "high", "Enforces HTTPS connections"),
    "Content-Security-Policy": (15, "high", "Prevents XSS and injection attacks"),
    "X-Content-Type-Options": (10, "medium", "Prevents MIME-type sniffing"),
    "X-Frame-Options": (10, "medium", "Prevents clickjacking attacks"),
    "Referrer-Policy": (10, "medium", "Controls referrer information"),
    "Permissions-Policy": (10, "medium", "Controls browser feature access"),
    "X-XSS-Protection": (5, "low", "Legacy XSS filter"),
    "Cross-Origin-Resource-Policy": (5, "low", "Cross-origin resource isolation"),
    "Cross-Origin-Embedder-Policy": (5, "low", "Cross-origin embedding control"),
    "Cross-Origin-Opener-Policy": (5, "low", "Cross-origin window isolation"),
}

INFO_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                "X-AspNetMvc-Version", "X-Generator"]

SKIP_DOMAINS = {
    "google.com", "google.co", "googleapis.com", "gstatic.com",
    "yelp.com", "facebook.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "youtube.com", "tiktok.com", "pinterest.com",
    "reddit.com", "wikipedia.org", "amazon.com", "apple.com",
    "bbb.org", "bing.com", "yahoo.com", "mapquest.com",
    "yellowpages.com", "whitepages.com", "chamberofcommerce.com",
    "glassdoor.com", "indeed.com", "crunchbase.com", "zoominfo.com",
    "manta.com", "dnb.com", "bloomberg.com", "tripadvisor.com",
    "nextdoor.com", "angieslist.com", "thumbtack.com",
    "healthgrades.com", "vitals.com", "zocdoc.com", "webmd.com",
    "npi-lookup.com", "healthcare4ppl.com", "doctor.com",
    "superpages.com", "citysearch.com", "foursquare.com",
    "inven.ai", "f6s.com", "builtincharlotte.com", "builtin.com",
    "lensa.com", "comparably.com", "owler.com", "pitchbook.com",
    "martindale.com", "avvo.com", "findlaw.com", "justia.com",
    "nerdwallet.com", "bankrate.com", "investopedia.com",
    "solvhealth.com", "castleconnolly.com", "usnews.com",
    "press-news.org", "prnewswire.com", "businesswire.com",
    "gov", "state.nc.us", "irs.gov",
    "arstechnica.com", "techcrunch.com", "wired.com", "cnet.com",
    "city-data.com", "niche.com", "areavibes.com", "bestplaces.net",
    "centurycommunities.com", "zillow.com", "realtor.com", "redfin.com",
    "rentbottomline.com", "apartments.com", "trulia.com",
    "makeamovetoday.com", "movoto.com", "point2homes.com",
    "conciergemedicinetoday.org", "turningwinds.com",
    "medicalassistantprogramscharlotte.com", "scdconsultingservices.com",
    "patch.com", "charlotteobserver.com", "wsoctv.com", "wcnc.com",
}

REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


# --- Data structures ---

@dataclass
class ScanResult:
    url: str
    final_url: str = ""
    reachable: bool = False
    status_code: int = 0
    response_time_ms: int = 0
    headers_present: dict = field(default_factory=dict)
    headers_missing: list = field(default_factory=list)
    ssl_valid: bool = False
    ssl_issuer: str = ""
    ssl_expiry: str = ""
    ssl_days_remaining: int = 0
    server_info: dict = field(default_factory=dict)
    cookie_issues: list = field(default_factory=list)
    grade: str = "F"
    score: int = 0
    scan_time: str = ""
    error: str = ""

    def to_notes(self) -> str:
        if not self.reachable:
            return f"[SCAN {datetime.now().strftime('%Y-%m-%d')}] Unreachable: {self.error}"

        parts = [f"[SCAN {datetime.now().strftime('%Y-%m-%d')}] Grade: {self.grade} ({self.score}/100)"]

        if self.headers_missing:
            missing_short = [h.replace("Cross-Origin-", "CO-") for h in self.headers_missing]
            parts.append(f"Missing: {', '.join(missing_short)}")

        server_parts = []
        for k, v in self.server_info.items():
            server_parts.append(f"{v}")
        if server_parts:
            parts.append(f"Server: {' | '.join(server_parts)}")

        if self.ssl_valid:
            parts.append(f"SSL: Valid ({self.ssl_issuer}, {self.ssl_days_remaining}d)")
        elif self.ssl_issuer:
            parts.append(f"SSL: EXPIRED ({self.ssl_issuer})")
        else:
            parts.append("SSL: Not configured")

        return " | ".join(parts)

    def to_dict(self) -> dict:
        return asdict(self)


# --- URL helpers ---

def normalize_url(url_or_domain: str) -> str:
    url = url_or_domain.strip().rstrip("/")
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def _normalize_domain(url_or_domain: str) -> str:
    parsed = urlparse(normalize_url(url_or_domain))
    domain = (parsed.netloc or parsed.path).lower()
    if domain.startswith("www."):
        domain = domain[4:]
    # Strip port
    if ":" in domain:
        domain = domain.split(":")[0]
    return domain


def _get_existing_domains() -> set:
    leads = db.list_leads()
    domains = set()
    for lead in leads:
        if lead.get("website"):
            domains.add(_normalize_domain(lead["website"]))
    return domains


def _is_skip_domain(domain: str) -> bool:
    for skip in SKIP_DOMAINS:
        if domain == skip or domain.endswith(f".{skip}"):
            return True
    return False


# --- SSL check ---

def _check_ssl(hostname: str, port: int = 443, timeout: int = 5) -> dict:
    result = {"valid": False, "issuer": "", "expiry": "", "days_remaining": 0, "error": ""}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    # Issuer
                    issuer_parts = cert.get("issuer", ())
                    for part in issuer_parts:
                        for key, val in part:
                            if key in ("organizationName", "commonName"):
                                result["issuer"] = val
                                break
                        if result["issuer"]:
                            break

                    # Expiry
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        result["expiry"] = expiry.strftime("%Y-%m-%d")
                        result["days_remaining"] = (expiry - datetime.utcnow()).days
                        result["valid"] = result["days_remaining"] > 0
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"SSL verification failed: {str(e)[:80]}"
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        result["error"] = f"SSL check failed: {str(e)[:80]}"
    return result


# --- Core scanning ---

def scan_website(url: str, timeout: int = 10) -> ScanResult:
    result = ScanResult(url=url, scan_time=datetime.now().isoformat())
    normalized = normalize_url(url)
    if not normalized:
        result.error = "Empty URL"
        return result

    result.url = normalized
    hostname = _normalize_domain(normalized)

    # HTTP request
    try:
        start = time.time()
        resp = requests.get(
            normalized, headers=REQUEST_HEADERS,
            timeout=timeout, allow_redirects=True, verify=True,
        )
        result.response_time_ms = int((time.time() - start) * 1000)
        result.reachable = True
        result.status_code = resp.status_code
        result.final_url = resp.url
    except requests.exceptions.SSLError:
        # Retry without SSL verification
        try:
            start = time.time()
            resp = requests.get(
                normalized, headers=REQUEST_HEADERS,
                timeout=timeout, allow_redirects=True, verify=False,
            )
            result.response_time_ms = int((time.time() - start) * 1000)
            result.reachable = True
            result.status_code = resp.status_code
            result.final_url = resp.url
        except Exception as e:
            result.error = f"Connection failed: {str(e)[:100]}"
            return result
    except requests.exceptions.ConnectionError as e:
        result.error = f"Connection failed: {str(e)[:100]}"
        return result
    except requests.exceptions.Timeout:
        result.error = f"Timeout after {timeout}s"
        return result
    except Exception as e:
        result.error = f"Error: {str(e)[:100]}"
        return result

    # Check security headers
    score = 0
    for header, (weight, severity, desc) in SECURITY_HEADERS.items():
        value = resp.headers.get(header)
        if value:
            result.headers_present[header] = value
            score += weight
        else:
            result.headers_missing.append(header)

    # Check info disclosure headers
    for header in INFO_HEADERS:
        value = resp.headers.get(header)
        if value:
            result.server_info[header] = value

    # Check cookies
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if cookie.has_nonstandard_attr("httponly") is False and "httponly" not in str(cookie).lower():
            issues.append("missing HttpOnly flag")
        if issues:
            result.cookie_issues.append(f"{cookie.name}: {', '.join(issues)}")

    # SSL check
    ssl_info = _check_ssl(hostname)
    result.ssl_valid = ssl_info["valid"]
    result.ssl_issuer = ssl_info["issuer"]
    result.ssl_expiry = ssl_info["expiry"]
    result.ssl_days_remaining = ssl_info["days_remaining"]

    if ssl_info["valid"]:
        score += 10 if ssl_info["days_remaining"] > 30 else 5

    # Grade
    result.score = score
    if score >= 90:
        result.grade = "A"
    elif score >= 75:
        result.grade = "B"
    elif score >= 60:
        result.grade = "C"
    elif score >= 40:
        result.grade = "D"
    else:
        result.grade = "F"

    return result


def scan_bulk(urls: list, delay: float = 1.5, timeout: int = 10,
              progress_callback=None) -> list:
    # Deduplicate by domain
    seen = set()
    unique_urls = []
    for url in urls:
        domain = _normalize_domain(url)
        if domain and domain not in seen:
            seen.add(domain)
            unique_urls.append(url)

    results = []
    for i, url in enumerate(unique_urls):
        if progress_callback:
            progress_callback(i + 1, len(unique_urls), url)
        result = scan_website(url, timeout=timeout)
        results.append(result)
        if i < len(unique_urls) - 1:
            time.sleep(delay)

    return results


# --- Discovery ---

def _extract_company_name(url: str, html_title: str = "") -> str:
    if html_title:
        # Strip common suffixes
        name = html_title
        for sep in [" | ", " - ", " :: ", " — ", " – "]:
            if sep in name:
                name = name.split(sep)[0]
        # Strip generic words
        for suffix in ["Home", "Welcome", "Official Site", "Official Website", "Homepage"]:
            name = re.sub(rf"\s*{re.escape(suffix)}\s*$", "", name, flags=re.IGNORECASE)
        name = name.strip()
        if len(name) > 3:
            return name

    # Fallback: domain name
    domain = _normalize_domain(url)
    if domain:
        name = domain.split(".")[0]
        return name.replace("-", " ").replace("_", " ").title()
    return "Unknown"


def _fetch_title(url: str, timeout: int = 8) -> str:
    try:
        resp = requests.get(normalize_url(url), headers=REQUEST_HEADERS,
                           timeout=timeout, allow_redirects=True, verify=False)
        soup = BeautifulSoup(resp.text[:10000], "html.parser")
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            return title_tag.string.strip()
    except Exception:
        pass
    return ""


def discover_leads(location: str, industry: str = "",
                   max_results: int = 20) -> list:
    if not HAS_DDGS:
        raise ImportError(
            "ddgs not installed. Run: pip install ddgs"
        )

    # Build targeted search queries for actual business websites
    industry_terms = {
        "healthcare": ["medical practice", "clinic", "healthcare provider", "medical group", "physician office"],
        "msp": ["managed service provider", "IT services company", "managed IT", "IT support company"],
        "fintech": ["financial services firm", "fintech company", "credit union", "accounting firm"],
        "legal": ["law firm", "attorney", "legal services"],
        "manufacturing": ["manufacturer", "manufacturing company", "industrial company"],
        "real_estate": ["real estate company", "property management", "commercial real estate"],
    }

    queries = []
    if industry:
        terms = industry_terms.get(industry.lower(), [f"{industry} company", f"{industry} firm"])
        for term in terms[:3]:
            queries.append(f'{term} {location}')
    else:
        queries.append(f'small business {location}')
        queries.append(f'local company {location}')
        queries.append(f'professional services firm {location}')

    discovered = []
    seen_domains = set()

    for query in queries:
        if len(discovered) >= max_results:
            break
        try:
            results = list(DDGS().text(query, max_results=min(max_results * 3, 60)))
            for item in results:
                if len(discovered) >= max_results:
                    break
                url = item.get("href", "")
                if not url:
                    continue
                domain = _normalize_domain(url)
                if not domain or domain in seen_domains:
                    continue
                if _is_skip_domain(domain):
                    continue
                seen_domains.add(domain)

                title = item.get("title", "")
                company_name = _extract_company_name(url, title)

                discovered.append({
                    "company_name": company_name,
                    "website": domain,
                    "title": title,
                    "source_url": url,
                })
            time.sleep(2)  # Rate limit between queries
        except Exception as e:
            print(f"Search error for '{query}': {e}")
            continue

    return discovered


def import_from_scan(results: list, industry: str = "", category: str = "",
                     min_grade: str = "C", dry_run: bool = False) -> dict:
    """Import scan results as CRM leads. Used by scan-bulk --import."""
    grade_order = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}
    min_grade_val = grade_order.get(min_grade, 2)
    existing = _get_existing_domains()

    stats = {"imported": 0, "skipped_good": 0, "skipped_duplicate": 0, "skipped_unreachable": 0}

    for result in results:
        domain = _normalize_domain(result.url)
        if not result.reachable:
            stats["skipped_unreachable"] += 1
            continue

        result_grade_val = grade_order.get(result.grade, 0)
        if domain in existing:
            stats["skipped_duplicate"] += 1
        elif result_grade_val > min_grade_val:
            stats["skipped_good"] += 1
        elif not dry_run:
            title = _fetch_title(result.url, timeout=8)
            company_name = _extract_company_name(result.url, title)
            db.add_lead(
                company=company_name,
                website=domain,
                industry=industry,
                category=category,
                notes=result.to_notes(),
                priority=_grade_to_priority(result.grade),
                source="security_scan",
            )
            stats["imported"] += 1
            existing.add(domain)

    return stats


def _grade_to_priority(grade: str) -> str:
    if grade in ("F", "D"):
        return "high"
    elif grade == "C":
        return "medium"
    return "low"


# --- CRM integration ---

def scan_and_import(location: str, industry: str = "",
                    max_results: int = 20, min_grade: str = "C",
                    dry_run: bool = False,
                    progress_callback=None) -> dict:
    grade_order = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}
    min_grade_val = grade_order.get(min_grade, 2)

    stats = {
        "discovered": 0, "scanned": 0, "imported": 0,
        "skipped_good": 0, "skipped_duplicate": 0,
        "results": [],
    }

    # Discover
    leads = discover_leads(location, industry, max_results)
    stats["discovered"] = len(leads)

    if not leads:
        return stats

    # Get existing domains for dedup
    existing = _get_existing_domains()

    # Scan
    urls = [l["website"] for l in leads]
    scan_results = scan_bulk(urls, delay=1.5, progress_callback=progress_callback)
    stats["scanned"] = len(scan_results)

    # Import
    lead_map = {_normalize_domain(l["website"]): l for l in leads}
    for result in scan_results:
        domain = _normalize_domain(result.url)
        lead_info = lead_map.get(domain, {})
        result_grade_val = grade_order.get(result.grade, 0)

        detail = {
            "company": lead_info.get("company_name", domain),
            "website": domain,
            "grade": result.grade,
            "score": result.score,
            "missing": len(result.headers_missing),
            "action": "",
        }

        if domain in existing:
            detail["action"] = "skipped_duplicate"
            stats["skipped_duplicate"] += 1
        elif result_grade_val > min_grade_val:
            detail["action"] = "skipped_good"
            stats["skipped_good"] += 1
        else:
            detail["action"] = "imported" if not dry_run else "would_import"
            if not dry_run:
                category = ""
                if industry:
                    cat_map = {
                        "healthcare": "healthcare", "medical": "healthcare",
                        "finance": "fintech", "fintech": "fintech", "banking": "fintech",
                        "legal": "legal", "law": "legal",
                        "msp": "msp", "it services": "msp", "managed services": "msp",
                        "manufacturing": "manufacturing",
                    }
                    category = cat_map.get(industry.lower(), industry.lower())

                db.add_lead(
                    company=lead_info.get("company_name", domain),
                    website=domain,
                    industry=industry,
                    category=category,
                    notes=result.to_notes(),
                    priority=_grade_to_priority(result.grade),
                    source="security_scan",
                )
                stats["imported"] += 1
            else:
                stats["imported"] += 1  # Count as would-import for dry_run

        stats["results"].append(detail)

    return stats


def scan_existing_leads(category: str = None, progress_callback=None) -> dict:
    leads = db.list_leads(category=category)
    leads_with_site = [l for l in leads if l.get("website")]

    stats = {"total": len(leads_with_site), "scanned": 0, "updated": 0, "unreachable": 0}

    urls = [l["website"] for l in leads_with_site]
    results = scan_bulk(urls, delay=1.5, progress_callback=progress_callback)

    domain_to_lead = {}
    for lead in leads_with_site:
        domain_to_lead[_normalize_domain(lead["website"])] = lead

    for result in results:
        stats["scanned"] += 1
        domain = _normalize_domain(result.url)
        lead = domain_to_lead.get(domain)
        if not lead:
            continue

        if not result.reachable:
            stats["unreachable"] += 1

        # Build new notes: scan result + existing notes
        scan_notes = result.to_notes()
        existing_notes = lead.get("notes", "")
        # Remove previous scan line if present
        existing_notes = re.sub(r"\[SCAN [^\]]+\].*?(\n|$)", "", existing_notes).strip()
        new_notes = f"{scan_notes}\n{existing_notes}".strip() if existing_notes else scan_notes

        db.update_lead(lead["id"], notes=new_notes, priority=_grade_to_priority(result.grade))
        stats["updated"] += 1

    return stats


def generate_outreach_email(lead: dict) -> tuple:
    """Generate a personalized cold email based on a lead's scan findings.

    Returns (subject, body) or (None, None) if no scan data.
    """
    notes = lead.get("notes", "")
    company = lead.get("company", "your company")
    category = lead.get("category", "")
    website = lead.get("website", "")

    # Parse scan data from notes
    grade = ""
    missing_count = 0
    missing_headers = []
    server = ""
    ssl_info = ""

    scan_match = re.search(r"\[SCAN [^\]]+\] Grade: (\w) \((\d+)/100\)", notes)
    if scan_match:
        grade = scan_match.group(1)
    missing_match = re.search(r"Missing: ([^|]+)", notes)
    if missing_match:
        missing_headers = [h.strip() for h in missing_match.group(1).split(",")]
        missing_count = len(missing_headers)
    server_match = re.search(r"Server: ([^|]+)", notes)
    if server_match:
        server = server_match.group(1).strip()
    ssl_match = re.search(r"SSL: (.+?)(?:\||$)", notes)
    if ssl_match:
        ssl_info = ssl_match.group(1).strip()

    if not grade:
        return None, None

    # Pick the most impactful missing headers for the email
    critical_missing = []
    for h in ["Strict-Transport-Security", "Content-Security-Policy",
              "X-Frame-Options", "X-Content-Type-Options"]:
        short = h.replace("Strict-Transport-Security", "HSTS") \
                 .replace("Content-Security-Policy", "CSP")
        if h in missing_headers or short in missing_headers:
            critical_missing.append(h)

    # Compliance angle based on category
    compliance_hook = ""
    if category == "healthcare":
        compliance_hook = "With HIPAA requiring reasonable safeguards for ePHI, these gaps could flag during an audit or, worse, a breach investigation."
    elif category == "fintech":
        compliance_hook = "For financial services, PCI-DSS and SOC 2 both require these controls -- missing them could be a compliance finding or a real risk."
    elif category == "msp":
        compliance_hook = "As an MSP, your clients trust you with their security -- and attackers know MSPs are high-value targets. These gaps could expose both you and your clients."
    elif category == "legal":
        compliance_hook = "Law firms handle highly sensitive client data -- these gaps could put attorney-client privilege at risk."
    else:
        compliance_hook = "These are low-hanging fruit that attackers scan for automatically, and fixing them is straightforward."

    # Build subject
    if grade == "F":
        subject = f"Found {missing_count} security gaps on {website}"
    elif grade == "D":
        subject = f"Quick security check on {website} -- a few concerns"
    else:
        subject = f"Noticed some security header gaps on {website}"

    # Build body
    findings_list = ""
    if "Strict-Transport-Security" in critical_missing:
        findings_list += "- No HSTS header (browsers aren't forced to use HTTPS)\n"
    if "Content-Security-Policy" in critical_missing:
        findings_list += "- No Content Security Policy (leaves the door open for XSS attacks)\n"
    if "X-Frame-Options" in critical_missing:
        findings_list += "- No clickjacking protection (X-Frame-Options missing)\n"
    if "X-Content-Type-Options" in critical_missing:
        findings_list += "- No MIME-sniffing protection\n"
    if not findings_list and missing_headers:
        for h in missing_headers[:3]:
            findings_list += f"- Missing {h}\n"

    server_note = ""
    if server and "apache" in server.lower():
        server_note = f" I also noticed the server is advertising its version ({server}), which gives attackers a head start."
    elif server and "php" in server.lower():
        server_note = f" The server is also disclosing its software stack ({server}), which is an easy fix."

    body = f"""Hi,

I was doing some cybersecurity research on {company.split(' - ')[0].split(' |')[0].strip()}'s web presence and noticed a few things on {website} that caught my eye:

{findings_list.strip()}
{server_note}
{compliance_hook}

I'm David with Voltsys AI here in Charlotte -- we do penetration testing and vulnerability assessments for local businesses. I'd be happy to put together a quick complimentary security overview for {company.split(' - ')[0].split(' |')[0].strip()} so you can see the full picture.

Would you be open to a 15-minute call this week to walk through what we found?

Best,
David Lopez
Voltsys AI
305-244-2536"""

    return subject, body


def generate_and_queue_scan_emails(source: str = "security_scan") -> dict:
    """Generate and queue outreach emails for all scan-discovered leads without emails yet.

    Returns stats dict.
    """
    leads = db.list_leads(status="new")
    stats = {"queued": 0, "skipped_no_scan": 0, "skipped_has_email": 0}

    for lead in leads:
        if lead.get("source") != source:
            continue

        # Check if we already have an outbound email for this lead
        existing_emails = db.get_emails_for_lead(lead["id"])
        has_outbound = any(e["direction"] == "outbound" for e in existing_emails)
        if has_outbound:
            stats["skipped_has_email"] += 1
            continue

        subject, body = generate_outreach_email(lead)
        if not subject:
            stats["skipped_no_scan"] += 1
            continue

        # We don't have contact emails for discovered leads,
        # so save as draft -- user can add emails and queue later
        db.add_email(
            lead_id=lead["id"],
            subject=subject,
            body=body,
            email_type="initial",
            direction="outbound",
            status="draft",
        )
        stats["queued"] += 1

    return stats


def scrape_contact_email(website: str, timeout: int = 10) -> str:
    """Scrape a website for contact email addresses.

    Checks homepage and /contact page for mailto: links and email patterns.
    Returns first business email found, or empty string.
    """
    email_pattern = re.compile(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    )
    skip_emails = {"example.com", "email.com", "domain.com", "yoursite.com",
                   "sentry.io", "wixpress.com", "wordpress.org", "w3.org",
                   "googleusercontent.com", "schema.org", "change.me"}

    found_emails = []
    pages_to_check = [
        normalize_url(website),
        normalize_url(website) + "/contact",
        normalize_url(website) + "/contact-us",
        normalize_url(website) + "/about",
    ]

    for page_url in pages_to_check:
        try:
            resp = requests.get(page_url, headers=REQUEST_HEADERS,
                               timeout=timeout, allow_redirects=True, verify=False)
            if resp.status_code != 200:
                continue

            # Check mailto: links first (most reliable)
            soup = BeautifulSoup(resp.text, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                if href.startswith("mailto:"):
                    email = href.replace("mailto:", "").split("?")[0].strip().lower()
                    domain = email.split("@")[-1] if "@" in email else ""
                    if domain and domain not in skip_emails:
                        found_emails.append(email)

            # Also regex the page text
            text_emails = email_pattern.findall(resp.text)
            for email in text_emails:
                email = email.lower()
                domain = email.split("@")[-1]
                if domain not in skip_emails and email not in found_emails:
                    # Prefer emails from the site's own domain
                    site_domain = _normalize_domain(website)
                    if site_domain in domain:
                        found_emails.insert(0, email)
                    else:
                        found_emails.append(email)

        except Exception:
            continue
        time.sleep(0.5)

    # Return the best email (prefer info@, contact@, admin@ from own domain)
    if not found_emails:
        return ""

    site_domain = _normalize_domain(website)
    # Priority: own domain emails first
    own_domain = [e for e in found_emails if site_domain in e.split("@")[-1]]
    if own_domain:
        # Prefer generic contact addresses
        for prefix in ["info", "contact", "hello", "admin", "office", "sales", "inquiries"]:
            for e in own_domain:
                if e.startswith(prefix + "@"):
                    return e
        return own_domain[0]

    return found_emails[0]


def scrape_emails_for_leads(source: str = "security_scan",
                            progress_callback=None) -> dict:
    """Scrape contact emails for all scan-discovered leads missing emails.

    Returns stats dict.
    """
    leads = db.list_leads()
    leads_to_scrape = [l for l in leads if l.get("source") == source
                       and not l.get("contact_email") and l.get("website")]

    stats = {"total": len(leads_to_scrape), "found": 0, "not_found": 0}

    for i, lead in enumerate(leads_to_scrape):
        if progress_callback:
            progress_callback(i + 1, len(leads_to_scrape), lead["website"])

        email = scrape_contact_email(lead["website"])
        if email:
            db.update_lead(lead["id"], contact_email=email)
            stats["found"] += 1
        else:
            stats["not_found"] += 1

        if i < len(leads_to_scrape) - 1:
            time.sleep(1)

    return stats


def export_results_csv(results: list) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["URL", "Grade", "Score", "Status", "Missing Headers",
                     "Server", "SSL Valid", "SSL Issuer", "SSL Expiry",
                     "Response Time (ms)", "Error"])
    for r in results:
        missing = ", ".join(r.headers_missing) if r.headers_missing else "None"
        server = " | ".join(r.server_info.values()) if r.server_info else ""
        writer.writerow([
            r.url, r.grade, r.score, r.status_code, missing,
            server, r.ssl_valid, r.ssl_issuer, r.ssl_expiry,
            r.response_time_ms, r.error,
        ])
    return output.getvalue()
