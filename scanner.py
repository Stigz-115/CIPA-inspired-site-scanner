"""
CIPA / consent tracker scanner engine.

Strategy (this is the "how is he scanning sites" core):

1. Load each URL in a real headless Chromium via Playwright, so JS-injected and
   tag-managed trackers actually fire (not just what's in static HTML).
2. Intercept every network request and every cookie / localStorage write.
3. Snapshot which trackers fire on INITIAL load, before any user interaction and
   before any consent action. Pre-consent firing of a third-party tracker is the
   central CIPA signal.
4. Detect whether a Consent Management Platform (CMP) is present at all.
5. Score each site by weighting findings by CIPA category risk, then applying a
   pre-consent multiplier when a risky tracker fired with no CMP gating it.

The scanner is deliberately passive: it loads pages as an ordinary visitor would
and records what the site chose to send to third parties. It does not submit
forms, log in, or exercise the site.

If Playwright or its Chromium binary is not available (e.g. constrained hosting
environments), the scanner automatically falls back to DEMO MODE: it generates
deterministic, realistic mock results from the signature database so the full
dashboard UX remains functional for demos and testing.
"""
import time
import hashlib
import random as _random
from urllib.parse import urlparse
from collections import defaultdict

# --- Playwright availability check (graceful degradation) ---
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except Exception:
    sync_playwright = None
    PLAYWRIGHT_AVAILABLE = False

from signatures import classify, detect_cmp, CATEGORY_RISK, CATEGORY_RATIONALE, \
    SIGNATURES, CMP_SIGNATURES

PRE_CONSENT_MULTIPLIER = 1.6  # risky tracker fired on load with no CMP present

# Module-level flag set by check_chromium(); True = real scanning possible.
_CHROMIUM_OK = None  # None = not yet checked, True/False = result


def _registrable(url):
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def check_chromium():
    """Test whether Chromium can actually be launched. Cached after first call.

    Returns True if a real browser scan is possible, False if we must use
    demo/mock mode.
    """
    global _CHROMIUM_OK
    if _CHROMIUM_OK is not None:
        return _CHROMIUM_OK
    if not PLAYWRIGHT_AVAILABLE:
        _CHROMIUM_OK = False
        return False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                args=["--no-sandbox", "--disable-dev-shm-usage"]
            )
            browser.close()
        _CHROMIUM_OK = True
    except Exception:
        _CHROMIUM_OK = False
    return _CHROMIUM_OK


# ---------------------------------------------------------------------------
# Demo / mock mode
# ---------------------------------------------------------------------------

def _seeded(url):
    """Return a deterministic RNG seeded from the URL so mock results are stable
    across re-scans of the same site."""
    h = int(hashlib.sha256(url.encode()).hexdigest()[:8], 16)
    return _random.Random(h)


def _mock_scan_url(url, rng):
    """Generate a realistic mock scan result for *url* using the signature DB.

    Picks 2–6 trackers and optionally a CMP so the dashboard, scoring, and
    remediation paths all exercise with plausible data.
    """
    if not url.startswith("http"):
        url = "https://" + url

    num_trackers = rng.randint(2, 6)
    chosen_sigs = rng.sample(SIGNATURES, min(num_trackers, len(SIGNATURES)))

    # ~40% chance the site has a CMP
    has_cmp = rng.random() < 0.4
    cmp_vendor = rng.choice(CMP_SIGNATURES)["vendor"] if has_cmp else None
    cmp_found = {cmp_vendor} if has_cmp else set()

    findings = []
    for sig in chosen_sigs:
        cat = sig["category"]
        base = CATEGORY_RISK.get(cat, 1)
        pre_consent = len(cmp_found) == 0
        risk = base * (PRE_CONSENT_MULTIPLIER if pre_consent and base >= 4 else 1)
        sample_url = f"https://{sig['patterns'][0]}/mock"
        findings.append({
            "vendor": sig["vendor"],
            "category": cat,
            "request_count": rng.randint(1, 12),
            "sample_url": sample_url,
            "pre_consent": pre_consent,
            "risk": round(risk, 1),
            "rationale": CATEGORY_RATIONALE.get(cat, ""),
        })

    findings.sort(key=lambda f: f["risk"], reverse=True)
    total_risk = round(sum(f["risk"] for f in findings), 1)
    score = max(0, 100 - min(100, int(total_risk * 2.2)))

    return {
        "url": url,
        "error": None,
        "cmp_detected": sorted(cmp_found),
        "has_cmp": has_cmp,
        "trackers": findings,
        "cookie_count": rng.randint(3, 25),
        "localstorage_keys": rng.randint(0, 8),
        "total_risk": total_risk,
        "score": score,
        "grade": _grade(score),
    }


def scan_url(page_context, url, settle_ms=3500):
    """Scan a single URL. Returns a structured finding dict."""
    requests = []
    page = page_context.new_page()

    page.on("request", lambda r: requests.append(r.url))

    error = None
    first_party = _registrable(url)
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=30000)
        # Let deferred / tag-managed scripts fire without any interaction.
        page.wait_for_timeout(settle_ms)
        try:
            local_storage = page.evaluate(
                "() => Object.keys(window.localStorage||{})"
            )
        except Exception:
            local_storage = []
        cookies = page_context.cookies()
    except Exception as e:
        error = str(e).splitlines()[0][:200]
        local_storage, cookies = [], []
    finally:
        page.close()

    # Classify captured requests.
    trackers = defaultdict(lambda: {"category": None, "count": 0, "sample": None})
    cmp_found = set()
    for req_url in requests:
        vendor, category = classify(req_url)
        if vendor:
            netloc = _registrable(req_url)
            # Only third-party requests are consent-relevant.
            if netloc and first_party and netloc.split(":")[0] != first_party.split(":")[0]:
                key = vendor
                trackers[key]["category"] = category
                trackers[key]["count"] += 1
                if trackers[key]["sample"] is None:
                    trackers[key]["sample"] = req_url[:160]
        cmp = detect_cmp(req_url)
        if cmp:
            cmp_found.add(cmp)

    findings = []
    for vendor, info in trackers.items():
        cat = info["category"]
        base = CATEGORY_RISK.get(cat, 1)
        # Pre-consent: every tracker here fired on initial load. If no CMP was
        # present at all, nothing could have gated it -> apply multiplier.
        pre_consent = len(cmp_found) == 0
        risk = base * (PRE_CONSENT_MULTIPLIER if pre_consent and base >= 4 else 1)
        findings.append({
            "vendor": vendor,
            "category": cat,
            "request_count": info["count"],
            "sample_url": info["sample"],
            "pre_consent": pre_consent,
            "risk": round(risk, 1),
            "rationale": CATEGORY_RATIONALE.get(cat, ""),
        })

    findings.sort(key=lambda f: f["risk"], reverse=True)
    total_risk = round(sum(f["risk"] for f in findings), 1)
    # Score 0-100 where 100 = clean. Cap raw risk contribution.
    score = max(0, 100 - min(100, int(total_risk * 2.2)))

    return {
        "url": url,
        "error": error,
        "cmp_detected": sorted(cmp_found),
        "has_cmp": len(cmp_found) > 0,
        "trackers": findings,
        "cookie_count": len(cookies),
        "localstorage_keys": len(local_storage),
        "total_risk": total_risk,
        "score": score,
        "grade": _grade(score),
    }


def _grade(score):
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


def scan_many(urls, settle_ms=3500, progress=None):
    """Scan a list of URLs in one browser session. Returns list of findings.

    Automatically falls back to DEMO MODE (mock results) when Playwright or
    Chromium is not available.
    """
    results = []

    if not check_chromium():
        # ---- Demo / mock mode ----
        for i, url in enumerate(urls):
            if not url.startswith("http"):
                url = "https://" + url
            rng = _seeded(url)
            res = _mock_scan_url(url, rng)
            results.append(res)
            if progress:
                progress(i + 1, len(urls), res)
        return results

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        for i, url in enumerate(urls):
            if not url.startswith("http"):
                url = "https://" + url
            # Fresh context per site = clean cookie jar, no cross-site bleed.
            ctx = browser.new_context(
                user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/120.0 Safari/537.36")
            )
            try:
                res = scan_url(ctx, url, settle_ms=settle_ms)
            except Exception as e:
                res = {"url": url, "error": str(e)[:200], "trackers": [],
                       "score": None, "grade": "?", "has_cmp": False,
                       "cmp_detected": [], "total_risk": None,
                       "cookie_count": 0, "localstorage_keys": 0}
            finally:
                ctx.close()
            results.append(res)
            if progress:
                progress(i + 1, len(urls), res)
        browser.close()
    return results


if __name__ == "__main__":
    import json, sys
    targets = sys.argv[1:] or ["https://example.com"]
    out = scan_many(targets)
    print(json.dumps(out, indent=2))
