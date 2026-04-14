import re
import socket
import requests
import email
from email import policy
from urllib.parse import urlparse
from colorama import Fore, Style, init

init(autoreset=True)

HIGH   = "HIGH"
MEDIUM = "MEDIUM"
LOW    = "LOW"
INFO   = "INFO"

RISK_COLOURS = {
    HIGH:   Fore.RED,
    MEDIUM: Fore.YELLOW,
    LOW:    Fore.GREEN,
    INFO:   Fore.CYAN,
}

# ─── KNOWN PHISHING INDICATORS ──────────────────────────────────────────────
URGENCY_PHRASES = [
    "verify your account", "account suspended", "immediate action",
    "click here now", "limited time", "act now", "your account will be",
    "confirm your identity", "unusual activity", "security alert",
    "update your payment", "your account has been", "will be terminated",
    "verify immediately", "respond within", "failure to verify",
    "unauthorized access", "suspicious login", "account locked",
    "won a prize", "you have been selected", "claim your reward",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".online", ".site", ".info",
    ".biz", ".tk", ".ml", ".ga", ".cf", ".gq",
]

LEGITIMATE_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "apple.com", "microsoft.com", "paypal.com", "amazon.com",
    "google.com", "facebook.com", "shopee.ph", "bdo.com.ph",
    "bpi.com.ph", "metrobank.com.ph", "gcash.com",
]

def print_finding(risk, message):
    colour = RISK_COLOURS.get(risk, Fore.WHITE)
    print(f"  {colour}[{risk}]{Style.RESET_ALL} {message}")

def parse_email_headers(raw_email):
    """
    Python's email library parses raw email text into a structured
    object. policy.default enables modern email parsing (RFC 6532)
    which correctly handles Unicode characters in headers.

    email.message_from_string() converts the raw text into an
    EmailMessage object — we can then access headers like a
    dictionary: msg['From'], msg['Subject'], etc.
    """
    try:
        msg = email.message_from_string(raw_email, policy=policy.default)
        return msg
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Could not parse email: {e}{Style.RESET_ALL}")
        return None

def extract_domain(email_address):
    """
    Extracts the domain from an email address string.
    e.g. "John Smith <john@suspicious-domain.xyz>" → "suspicious-domain.xyz"

    The regex pattern matches the @ symbol and everything after it,
    stopping at the closing angle bracket > or end of string.
    We use re.search() rather than split('@') because display names
    like "PayPal Support <noreply@phishing.xyz>" would break a simple split.
    """
    if not email_address:
        return None
    match = re.search(r'@([\w\.\-]+)', email_address)
    return match.group(1).lower() if match else None

def check_sender_mismatch(msg, findings):
    """
    One of the most reliable phishing indicators is a mismatch between:
    - The From: header (what you SEE as the sender)
    - The Reply-To: header (where your reply actually goes)
    - The Return-Path: header (where bounces go — reveals real sender)

    Legitimate organisations always have these aligned to the same domain.
    A phishing email might show "From: paypal@paypal.com" but have
    "Reply-To: collect@suspicious.xyz" — your reply goes to the attacker.
    """
    from_addr    = str(msg.get("From", ""))
    reply_to     = str(msg.get("Reply-To", ""))
    return_path  = str(msg.get("Return-Path", ""))

    from_domain       = extract_domain(from_addr)
    reply_to_domain   = extract_domain(reply_to) if reply_to else None
    return_path_domain= extract_domain(return_path) if return_path else None

    print(f"\n{Fore.CYAN}[*] Checking sender information...{Style.RESET_ALL}")
    print(f"    From:        {from_addr}")
    print(f"    Reply-To:    {reply_to or 'Not set'}")
    print(f"    Return-Path: {return_path or 'Not set'}")

    if from_domain:
        if reply_to_domain and reply_to_domain != from_domain:
            findings.append({
                "check": "Reply-To Mismatch",
                "risk": HIGH,
                "explanation": f"From domain ({from_domain}) does not match Reply-To domain ({reply_to_domain}). Replies go to a different server — classic phishing technique.",
            })
            print_finding(HIGH, f"Reply-To mismatch: {from_domain} → {reply_to_domain}")

        if return_path_domain and return_path_domain != from_domain:
            findings.append({
                "check": "Return-Path Mismatch",
                "risk": HIGH,
                "explanation": f"Return-Path domain ({return_path_domain}) differs from From domain ({from_domain}). Sender is masking true origin.",
            })
            print_finding(HIGH, f"Return-Path mismatch: {from_domain} → {return_path_domain}")

        if from_domain.endswith(tuple(SUSPICIOUS_TLDS)):
            findings.append({
                "check": "Suspicious Sender TLD",
                "risk": HIGH,
                "explanation": f"Sender domain uses a high-risk TLD: {from_domain}. Commonly used in throwaway phishing domains.",
            })
            print_finding(HIGH, f"Suspicious sender TLD: {from_domain}")

        is_legit = any(from_domain == d or from_domain.endswith("." + d)
                      for d in LEGITIMATE_DOMAINS)
        if not is_legit:
            findings.append({
                "check": "Unknown Sender Domain",
                "risk": MEDIUM,
                "explanation": f"Sender domain ({from_domain}) is not in the known-legitimate domain list. Verify before trusting.",
            })
            print_finding(MEDIUM, f"Unrecognised sender domain: {from_domain}")
        else:
            print_finding(INFO, f"Sender domain recognised: {from_domain}")

    return from_domain

def check_subject_urgency(msg, findings):
    """
    Analyses the email subject line for urgency/fear language.
    Phishing emails rely heavily on psychological pressure —
    fear of account loss, urgency to act, promises of reward.

    We check the subject against our URGENCY_PHRASES list
    using case-insensitive matching (lower() on both sides).
    """
    subject = str(msg.get("Subject", "")).lower()
    print(f"\n{Fore.CYAN}[*] Checking subject line for urgency patterns...{Style.RESET_ALL}")
    print(f"    Subject: {msg.get('Subject', 'No subject')}")

    matched = [p for p in URGENCY_PHRASES if p in subject]
    if matched:
        findings.append({
            "check": "Urgency Language in Subject",
            "risk": HIGH,
            "explanation": f"Subject contains urgency/fear trigger phrases: {', '.join(matched)}. Classic social engineering.",
        })
        print_finding(HIGH, f"Urgency phrases detected: {', '.join(matched)}")
    else:
        print_finding(INFO, "No urgency phrases detected in subject")

def check_body_content(raw_email, findings):
    """
    Scans the full email body text for urgency phrases and
    extracts all URLs using regex for further analysis.

    URL extraction regex breakdown:
    https?://     — matches http:// or https://
    [^\s<>"{}|\\^`\[\]]+ — matches any character that isn't
                   whitespace or a special HTML/bracket character.
                   This catches full URLs including paths and query strings.

    We then run each URL through check_url() for deeper analysis.
    """
    print(f"\n{Fore.CYAN}[*] Scanning email body content...{Style.RESET_ALL}")

    body_lower = raw_email.lower()
    matched_body = [p for p in URGENCY_PHRASES if p in body_lower]
    if matched_body:
        findings.append({
            "check": "Urgency Language in Body",
            "risk": MEDIUM,
            "explanation": f"Body contains pressure language: {', '.join(matched_body[:3])}{'...' if len(matched_body) > 3 else ''}",
        })
        print_finding(MEDIUM, f"Body urgency phrases: {', '.join(matched_body[:3])}")

    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, raw_email)

    if urls:
        print(f"\n{Fore.CYAN}[*] Found {len(urls)} URL(s) — analysing...{Style.RESET_ALL}")
        for url in set(urls):
            check_url(url, findings)
    else:
        print_finding(INFO, "No URLs found in email body")

def check_url(url, findings):
    """
    Analyses a single URL for phishing indicators:

    1. Domain extraction via urlparse() — breaks URL into components:
       scheme (https), netloc (domain), path, query, fragment.
       We only need netloc for domain analysis.

    2. IP address check — legitimate services never use raw IP addresses
       in links (e.g. http://192.168.1.1/login). Only phishing does.

    3. Suspicious TLD check — same logic as sender domain.

    4. Domain impersonation check — looks for legitimate brand names
       embedded in suspicious domains:
       e.g. "paypal-secure-login.xyz" contains "paypal" but isn't paypal.com

    5. URL shortener check — bit.ly, tinyurl, etc. hide the real destination.
       Not automatically malicious but warrants caution.

    6. Redirect following — follows the URL to see where it actually lands.
       We use a HEAD request (no body downloaded — fast and safe) with
       allow_redirects=True. The final URL after all redirects is the
       real destination.
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")

        print(f"\n    {Fore.WHITE}Analysing: {url[:80]}{'...' if len(url) > 80 else ''}{Style.RESET_ALL}")

        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.match(ip_pattern, domain):
            findings.append({
                "check": f"IP Address in URL",
                "risk": HIGH,
                "explanation": f"URL uses a raw IP address ({domain}) instead of a domain name. Legitimate services never do this.",
            })
            print_finding(HIGH, f"Raw IP address in URL: {domain}")
            return

        if domain.endswith(tuple(SUSPICIOUS_TLDS)):
            findings.append({
                "check": "Suspicious URL TLD",
                "risk": HIGH,
                "explanation": f"URL domain uses high-risk TLD: {domain}",
            })
            print_finding(HIGH, f"Suspicious TLD in URL: {domain}")

        brand_names = ["paypal", "apple", "microsoft", "google", "amazon",
                       "facebook", "netflix", "bdo", "bpi", "gcash",
                       "shopee", "lazada", "grab", "maya"]
        for brand in brand_names:
            if brand in domain and not domain.endswith(f"{brand}.com") \
                    and not domain.endswith(f"{brand}.ph"):
                findings.append({
                    "check": f"Brand Impersonation: {brand}",
                    "risk": HIGH,
                    "explanation": f"URL contains '{brand}' but domain is '{domain}'. This is a common impersonation technique.",
                })
                print_finding(HIGH, f"Brand impersonation detected: '{brand}' in {domain}")

        shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl",
                      "ow.ly", "short.link", "rb.gy", "cutt.ly"]
        if any(s in domain for s in shorteners):
            findings.append({
                "check": "URL Shortener Detected",
                "risk": MEDIUM,
                "explanation": f"URL uses a shortener ({domain}) which hides the real destination. Always expand before clicking.",
            })
            print_finding(MEDIUM, f"URL shortener detected: {domain}")

        try:
            response = requests.head(url, allow_redirects=True, timeout=5,
                                    headers={"User-Agent": "Mozilla/5.0"})
            final_url = response.url
            if final_url != url:
                final_domain = urlparse(final_url).netloc.lower()
                findings.append({
                    "check": "URL Redirect Detected",
                    "risk": MEDIUM,
                    "explanation": f"URL redirects to: {final_domain}. Verify the destination is expected.",
                })
                print_finding(MEDIUM, f"Redirects to: {final_domain}")
            else:
                print_finding(INFO, f"No redirect detected — resolves directly")
        except Exception:
            print_finding(LOW, f"Could not follow URL (may be offline or blocked)")

    except Exception as e:
        print(f"{Fore.YELLOW}    [WARN] URL analysis error: {e}{Style.RESET_ALL}")

def check_virustotal(url, api_key):
    """
    Submits a URL to VirusTotal for community-sourced
    malware and phishing analysis.

    VirusTotal API v3 workflow:
    1. POST the URL to /urls endpoint — returns an analysis ID
    2. GET /analyses/{id} — returns the scan results

    The URL must be base64-encoded (URL-safe, no padding)
    for the GET request. This is a VirusTotal API requirement
    to safely encode URLs that contain special characters.

    Response structure:
      data.attributes.stats contains:
        malicious   — engines that flagged as malicious
        suspicious  — engines that flagged as suspicious
        harmless    — engines that cleared it
        undetected  — engines with no verdict

    Rate limit on free tier: 4 requests/minute, 500/day.
    We handle 429 (rate limit) gracefully.
    """
    import base64
    if not api_key or api_key == "YOUR_KEY_HERE":
        return None

    findings = []
    headers = {
        "x-apikey":     api_key,
        "Accept":       "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        # Step 1 — Submit URL
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data=f"url={requests.utils.quote(url, safe='')}",
            timeout=10
        )
        if resp.status_code == 429:
            findings.append({
                "check":       "VirusTotal Rate Limited",
                "risk":        INFO,
                "explanation": "VirusTotal rate limit reached (4 req/min free tier). Wait 60 seconds.",
            })
            return findings

        if resp.status_code not in (200, 201):
            return findings

        analysis_id = resp.json().get("data", {}).get("id", "")
        if not analysis_id:
            return findings

        # Step 2 — Get results
        import time
        time.sleep(3)  # Brief wait for analysis to complete
        result_resp = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=10
        )
        if result_resp.status_code != 200:
            return findings

        stats = result_resp.json().get(
            "data", {}).get("attributes", {}).get("stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        total      = malicious + suspicious + harmless + stats.get("undetected", 0)

        if malicious > 0:
            findings.append({
                "check":       f"VirusTotal: MALICIOUS URL",
                "risk":        HIGH,
                "explanation": f"{malicious}/{total} security vendors flagged this URL as malicious. Do not visit.",
            })
            print_finding(HIGH, f"VirusTotal: {malicious}/{total} engines — MALICIOUS")
        elif suspicious > 0:
            findings.append({
                "check":       f"VirusTotal: Suspicious URL",
                "risk":        MEDIUM,
                "explanation": f"{suspicious}/{total} security vendors flagged this URL as suspicious.",
            })
            print_finding(MEDIUM, f"VirusTotal: {suspicious}/{total} engines — suspicious")
        else:
            findings.append({
                "check":       f"VirusTotal: Clean URL",
                "risk":        INFO,
                "explanation": f"0/{total} security vendors flagged this URL. Appears clean.",
            })
            print_finding(INFO, f"VirusTotal: 0/{total} engines — clean")

    except Exception as e:
        findings.append({
            "check":       "VirusTotal Check Failed",
            "risk":        INFO,
            "explanation": f"VirusTotal check failed: {e}",
        })
    return findings


def check_cert_for_url(url):
    """
    Wrapper that extracts the hostname from a URL
    and calls the HTTPS certificate validator.
    Imports from audit.py to avoid code duplication.
    """
    try:
        from modules.audit import check_https_certificate
        parsed   = urlparse(url)
        hostname = parsed.netloc.replace("www.", "")
        if hostname and url.startswith("https://"):
            return check_https_certificate(hostname)
    except Exception:
        pass
    return []

def check_authentication_headers(msg, findings):
    """
    Modern email servers add authentication headers that reveal
    whether an email genuinely came from the claimed sender.

    SPF  (Sender Policy Framework) — verifies sending server
         is authorised to send for the From domain.
    DKIM (DomainKeys Identified Mail) — cryptographic signature
         proving the email wasn't modified in transit.
    DMARC (Domain-based Message Authentication) — policy that
         tells receiving servers what to do if SPF/DKIM fail.

    A legitimate email from a major organisation will pass all three.
    A phishing email spoofing that organisation will typically fail
    at least one — and the receiving server records this in headers.

    We look for "fail", "none", or "softfail" in the relevant headers.
    """
    print(f"\n{Fore.CYAN}[*] Checking email authentication headers...{Style.RESET_ALL}")

    auth_results = str(msg.get("Authentication-Results", "")).lower()
    received_spf = str(msg.get("Received-SPF", "")).lower()

    checks = {
        "SPF":   ["spf=fail", "spf=softfail", "spf=none"],
        "DKIM":  ["dkim=fail", "dkim=none"],
        "DMARC": ["dmarc=fail", "dmarc=none"],
    }

    any_auth_found = False
    for auth_type, fail_patterns in checks.items():
        for pattern in fail_patterns:
            if pattern in auth_results or pattern in received_spf:
                findings.append({
                    "check": f"{auth_type} Authentication Failed",
                    "risk": HIGH,
                    "explanation": f"{auth_type} check {pattern.split('=')[1].upper()} — sender could not be verified as authentic.",
                })
                print_finding(HIGH, f"{auth_type} authentication: {pattern.split('=')[1].upper()}")
                any_auth_found = True
                break

    if not auth_results and not received_spf:
        findings.append({
            "check": "No Authentication Headers",
            "risk": MEDIUM,
            "explanation": "Email has no SPF/DKIM/DMARC authentication headers. Cannot verify sender authenticity.",
        })
        print_finding(MEDIUM, "No authentication headers found (SPF/DKIM/DMARC)")
    elif not any_auth_found:
        print_finding(INFO, "Authentication headers present — no failures detected")

def calculate_risk_score(findings):
    """
    Converts findings into a 0-100 risk score.

    Weighting:
      HIGH   = 25 points each (capped at 4 findings = 100)
      MEDIUM = 10 points each
      LOW    =  3 points each

    Score interpretation:
      0–25   → Low Risk
      26–50  → Moderate Risk
      51–75  → High Risk
      76–100 → Critical Risk

    min(score, 100) ensures the score never exceeds 100
    even if multiple HIGH findings stack beyond that.
    """
    score = 0
    for f in findings:
        risk = f.get("risk", INFO)
        if risk == HIGH:   score += 25
        elif risk == MEDIUM: score += 10
        elif risk == LOW:    score += 3
    return min(score, 100)

def get_risk_label(score):
    if score >= 76: return ("CRITICAL", Fore.RED)
    if score >= 51: return ("HIGH RISK", Fore.RED)
    if score >= 26: return ("MODERATE", Fore.YELLOW)
    return ("LOW RISK", Fore.GREEN)

def run_phishing_analysis(raw_email):
    """
    Master function for phishing analysis.
    Loads VirusTotal API key from .env file.
    Runs all checks in sequence and returns consolidated results.
    """
    import os
    from dotenv import load_dotenv
    load_dotenv()
    vt_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  SECURECHECK — Phishing Email Analyzer")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    findings = []
    msg = parse_email_headers(raw_email)

    if not msg:
        return {"error": "Could not parse email", "findings": [], "score": 0}

    from_domain = check_sender_mismatch(msg, findings)
    check_subject_urgency(msg, findings)
    check_authentication_headers(msg, findings)

    # Extract URLs and run full analysis per URL
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = list(set(re.findall(url_pattern, raw_email)))

    if urls:
        print(f"\n{Fore.CYAN}[*] Found {len(urls)} URL(s) — running full analysis...{Style.RESET_ALL}")
        for url in urls[:5]:  # Cap at 5 URLs to respect rate limits
            check_url(url, findings)

            # HTTPS cert validation
            if url.startswith("https://"):
                print(f"    {Fore.CYAN}[*] Checking TLS certificate...{Style.RESET_ALL}")
                cert_findings = check_cert_for_url(url)
                findings.extend(cert_findings)

            # VirusTotal
            if vt_api_key:
                print(f"    {Fore.CYAN}[*] Checking VirusTotal...{Style.RESET_ALL}")
                vt_findings = check_virustotal(url, vt_api_key)
                if vt_findings:
                    findings.extend(vt_findings)
            else:
                print(f"    {Fore.YELLOW}[!] No VirusTotal API key — skipping VT check{Style.RESET_ALL}")
    else:
        print_finding(INFO, "No URLs found in email body")

    # Body urgency scan
    body_lower = raw_email.lower()
    matched_body = [p for p in URGENCY_PHRASES if p in body_lower]
    if matched_body:
        findings.append({
            "check": "Urgency Language in Body",
            "risk": MEDIUM,
            "explanation": f"Body contains pressure language: {', '.join(matched_body[:3])}{'...' if len(matched_body) > 3 else ''}",
        })
        print_finding(MEDIUM, f"Body urgency phrases: {', '.join(matched_body[:3])}")

    # HIBP check on sender
    if from_domain:
        from modules.audit import check_hibp_email
        sender_addr = str(msg.get("From", ""))
        import re as _re
        email_match = _re.search(r'[\w\.\-\+]+@[\w\.\-]+', sender_addr)
        if email_match:
            print(f"\n{Fore.CYAN}[*] Checking sender against HaveIBeenPwned...{Style.RESET_ALL}")
            hibp = check_hibp_email(email_match.group(0))
            findings.extend(hibp)

    score = calculate_risk_score(findings)
    label, colour = get_risk_label(score)

    high_count   = sum(1 for f in findings if f.get("risk") == HIGH)
    medium_count = sum(1 for f in findings if f.get("risk") == MEDIUM)

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  ANALYSIS COMPLETE")
    print(f"  Risk Score: {colour}{score}/100 — {label}{Style.RESET_ALL}")
    print(f"  {Fore.RED}{high_count} HIGH  {Fore.YELLOW}{medium_count} MEDIUM")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

    return {
        "findings":    findings,
        "score":       score,
        "risk_label":  label,
        "high_count":  high_count,
        "medium_count":medium_count,
        "from":        str(msg.get("From", "Unknown")),
        "subject":     str(msg.get("Subject", "No subject")),
        "date":        str(msg.get("Date", "Unknown")),
    }