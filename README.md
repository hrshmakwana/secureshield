# SecureShield – Web-Based Cyber Security Monitoring Platform

SecureShield is a modular Flask application that delivers secure authentication, file integrity monitoring, web vulnerability scanning (SQLi & XSS), PDF reporting, and activity logging with role-based access control.

## Stack
- Python 3.11+
- Flask + Flask-Login + Flask-WTF (CSRF)
- Flask-SQLAlchemy (SQLite dev DB)
- bcrypt for password hashing
- requests for enhanced heuristic scanning
- reportlab for PDF reports

## Project Layout
```
secureshield/
├── app/
│   ├── __init__.py          # app factory, security headers, logging hook
│   ├── models.py            # User, FileMonitoring, ScanHistory, ActivityLog
│   ├── routes/              # auth, file, scan, admin, main
│   ├── services/            # hash, scan, report helpers
│   ├── templates/           # Bootstrap 5 pages
│   └── static/              # CSS/JS assets
├── config.py                # config + upload/report folders
├── run.py                   # entrypoint (creates DB then runs)
├── requirements.txt
└── README.md
```

## Quick Start
1. **Create env & install deps**
   ```bash
   cd secureshield
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Run**
   ```bash
   python run.py
   ```
   App defaults to http://127.0.0.1:5000

3. **Create an admin (optional)**
   ```bash
   flask shell
   >>> from app import db
   >>> from app.models import User
   >>> u = User(username='admin', email='admin@example.com', role='admin'); u.set_password('Str0ng!Pass'); db.session.add(u); db.session.commit()
   ```

## Security Features
- Password hashing with `bcrypt`
- CSRF protection via Flask-WTF
- Secure session cookies (HTTPOnly, SameSite Lax)
- File validation: allow-listed extensions + 10MB max
- SQLAlchemy ORM to avoid raw SQL injection
- URL validation before scans
- Basic per-user scan cooldown to reduce abuse
- Activity logging (user, timestamp, IP)

## Core Flows
- **Auth**: register/login/logout, password strength validation, role-based access.
- **File Integrity**: upload baseline (SHA-256), re-upload to compare, status + timestamps.
- **Scanning**: SQLi & XSS payload checks (multiple payloads, timing anomaly heuristic, evidence snippets), severity heuristic, searchable/paginated history, PDF export.
- **Dashboards**: user dashboard with stats + recent scans; admin dashboard with users, scans, logs.

## Testing Pointers
Manual cases to try:
- Incorrect login (expect flash error)
- Invalid URL on scan (blocked)
- Upload disallowed file type (blocked)
- Re-upload altered file (status shows Modified)
- Non-admin visiting /admin/dashboard (403)

## Future Scalability
- Swap SQLite for Postgres/MySQL; add migrations.
- Real-time monitoring agents feeding hashes/logs.
- Deploy behind gunicorn/uwsgi + Nginx; enable HTTPS & secure cookies.
- Integrate richer scanning engines or external threat-intel APIs.
- Add background workers for long-running scans & notification hooks.

### Scope control
Set `ALLOWED_SCAN_HOSTS` (comma separated, no scheme) to whitelist which hosts can be scanned, e.g.
```bash
export ALLOWED_SCAN_HOSTS=example.com,staging.example.com
```
If unset, any host is allowed (not recommended for production).


### Enhanced scanner (what it now does)
- Multiple SQLi & XSS payloads per parameter
- Same-host link crawl (up to 5 links) then scans each target
- Timing anomaly heuristic for possible blind SQLi
- Header-reflection XSS check (X-Forwarded-For)
- Randomized User-Agent per scan
- Evidence captured (payload, param/header, snippet, timing)

### Recommended next milestones (not yet implemented)
- Headless DOM XSS (Playwright) for script-executed sinks
- Auth/session-aware scans (login flow + cookie reuse)
- Background job queue for long scans (Celery/RQ) with progress UI
- Rich payload libraries (per-DB SQLi, context-aware XSS) and rate limiting/backoff
- Request/response archiving and PDF evidence

### DOM XSS (optional)
- Install playwright dependency already listed; then download a browser once: `python -m playwright install chromium`
- DOM scan runs if checkbox is on; if playwright is missing, it skips with a message.

### Auth-assisted scans
- You can supply a `Cookie` header (e.g., `session=abc; csrftoken=xyz`) on the scan form; it is used only for that scan.

### Evidence storage
- Evidence snippets (payload, param/header, status, timing) are stored in DB table `scan_evidence` and text files under `EVIDENCE_FOLDER` (default `secureshield/evidence`).

### Background tasks (next step)
- Scans still run synchronously. To offload long scans, add Celery/RQ with a worker and change `/scan` route to enqueue jobs.

**Note on Playwright / DOM XSS**: The optional DOM scan uses Playwright. Current wheels for `greenlet` (a dependency) are not published for Python 3.13 on macOS, so install Playwright only if you're on Python 3.12/3.11 (recommended). On 3.13 the app will skip DOM scan automatically and you can leave Playwright uninstalled.
