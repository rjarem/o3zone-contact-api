"""o3.zone contact form backend.

POST /api/contact  {name, email, message, website(honeypot), elapsed(ms)}
Emails tito@o3.zone via MXroute SMTP. Anti-spam: honeypot, min fill time,
rate limiting per IP, disposable-domain blocklist, length caps.
"""
import ipaddress
import json
import logging
import os
import re
import smtplib
import time
from collections import defaultdict, deque
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("contact")

SMTP_HOST = os.environ.get("SMTP_HOST", "witcher.mxrouting.net")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ["SMTP_USER"]
SMTP_PASS = os.environ["SMTP_PASS"]
TO_EMAIL = os.environ.get("TO_EMAIL", "tito@o3.zone")
FROM_NAME = os.environ.get("FROM_NAME", "o3.zone Contact Form")

RATE_HOURLY = int(os.environ.get("RATE_HOURLY", "3"))
RATE_DAILY = int(os.environ.get("RATE_DAILY", "8"))

MIN_ELAPSED_MS = 3000        # human fill time
MAX_MESSAGE = 5000
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "temp-mail.org", "yopmail.com", "trashmail.com", "sharklasers.com",
    "throwawaymail.com", "getnada.com", "dispostable.com", "maildrop.cc",
    "fakeinbox.com", "mytemp.email", "mohmal.com", "linshiyouxiang.net",
}

RATE_STORE_PATH = os.environ.get("RATE_STORE", "/data/ratelimits.json")


def _load_store() -> dict:
    try:
        with open(RATE_STORE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_store(store: dict) -> None:
    try:
        with open(RATE_STORE_PATH, "w") as f:
            json.dump(store, f)
    except Exception:
        log.exception("could not persist rate store")


class RateLimiter:
    """Sliding-window counters persisted to disk (survives restarts)."""

    def __init__(self, hourly: int, daily: int):
        self.hourly = hourly
        self.daily = daily
        self.events = defaultdict(deque)  # ip -> deque[timestamps]
        store = _load_store()
        now = time.time()
        for ip, stamps in store.items():
            self.events[ip] = deque(t for t in stamps if now - t < 86400)
        self._dirty = bool(store)

    def _prune(self, ip: str, now: float) -> deque:
        dq = self.events[ip]
        while dq and now - dq[0] > 86400:
            dq.popleft()
        return dq

    def allow(self, ip: str) -> tuple[bool, str]:
        now = time.time()
        dq = self._prune(ip, now)
        hour = sum(1 for t in dq if now - t <= 3600)
        day = len(dq)
        if hour >= self.hourly:
            return False, "too_many_hourly"
        if day >= self.daily:
            return False, "too_many_daily"
        dq.append(now)
        self._dirty = True
        return True, "ok"

    def flush(self) -> None:
        if not self._dirty:
            return
        now = time.time()
        store = {}
        for ip, dq in self.events.items():
            stamps = [t for t in dq if now - t < 86400]
            if stamps:
                store[ip] = stamps
        _save_store(store)
        self._dirty = False


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
limiter = RateLimiter(RATE_HOURLY, RATE_DAILY)


def real_ip(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for", "")
    first = xff.split(",")[0].strip()
    if first:
        try:
            ipaddress.ip_address(first)
            return first
        except ValueError:
            pass
    return req.client.host if req.client else "unknown"


def send_mail(from_email: str, reply_to: str, name: str, body: str, user_agent: str, ip: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["From"] = formataddr((Header(FROM_NAME, "utf-8").encode(), SMTP_USER))
    msg["To"] = TO_EMAIL
    msg["Reply-To"] = reply_to
    subject = f"New message from {name} via o3.zone"
    msg["Subject"] = Header(subject, "utf-8")
    text = f"Name: {name}\nEmail: {reply_to}\nSent: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\nIP: {ip}\n\n{body}"
    html = (
        f"<h2 style='font-family:sans-serif'>New message from o3.zone</h2>"
        f"<p><b>Name:</b> {name}<br><b>Email:</b> {reply_to}<br>"
        f"<b>Sent:</b> {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())} UTC<br>"
        f"<b>IP:</b> {ip}<br><b>Browser:</b> {user_agent}</p><hr>"
        f"<p style='white-space:pre-wrap;font-family:sans-serif'>{body}</p>"
    )
    msg.attach(MIMEText(text, "plain", "utf-8"))
    msg.attach(MIMEText(html, "html", "utf-8"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)


@app.post("/api/contact")
async def contact(request: Request):
    ip = real_ip(request)
    ua = (request.headers.get("user-agent") or "")[:300]
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "bad_request"}, status_code=400)
    if not isinstance(data, dict):
        return JSONResponse({"ok": False, "error": "bad_request"}, status_code=400)

    # generic rejection for every anti-spam failure (do not leak which)
    deny = lambda: JSONResponse({"ok": False, "error": "rejected"}, status_code=202)

    honeypot = str(data.get("website") or "")
    if honeypot:
        log.info("honeypot hit from %s", ip)
        return deny()

    name = str(data.get("name") or "").strip()
    email = str(data.get("email") or "").strip().lower()
    message = str(data.get("message") or "").strip()
    try:
        elapsed = int(data.get("elapsed") or 0)
    except (TypeError, ValueError):
        return deny()

    if not name or len(name) > 100 or "\n" in name:
        return deny()
    if not EMAIL_RE.match(email) or email.split("@")[1] in DISPOSABLE:
        return deny()
    if not message or len(message) < 10 or len(message) > MAX_MESSAGE:
        return deny()
    if elapsed < MIN_ELAPSED_MS or elapsed > 86400_000:
        return deny()

    ok, _reason = limiter.allow(ip)
    limiter.flush()
    if not ok:
        return JSONResponse({"ok": False, "error": "rate_limited"}, status_code=429)

    try:
        send_mail(email, email, name, message, ua, ip)
        log.info("delivered message from %s <%s> ip=%s", name, email, ip)
        return JSONResponse({"ok": True})
    except Exception:
        log.exception("smtp failure")
        return JSONResponse({"ok": False, "error": "send_failed"}, status_code=502)


@app.get("/api/contact/health")
async def health():
    return {"ok": True, "service": "o3zone-contact"}
