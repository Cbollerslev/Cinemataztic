import os
import re
import sys
import json
import time
import getpass
import hashlib
import logging
import secrets as pysecrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import psycopg
import requests
import click
from cryptography.fernet import Fernet
from flask import (
    Flask, jsonify, render_template_string, request, session,
    redirect, url_for, flash,
)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("onetime-secret")

# --- Kerne-konfiguration ---
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
MASTER_KEY = os.getenv("MASTER_KEY", "").strip()
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "").strip()
APP_BASE_URL = os.getenv("APP_BASE_URL", "").strip().rstrip("/")
MAX_SECRET_LENGTH = int(os.getenv("MAX_SECRET_LENGTH", "10000"))
MAX_TTL_MINUTES = int(os.getenv("MAX_TTL_MINUTES", "10080"))
SESSION_HOURS = int(os.getenv("SESSION_HOURS", "8"))
INVITE_HOURS = int(os.getenv("INVITE_HOURS", "48"))

# --- Bootstrap-bruger (oprettes ved opstart hvis sat) ---
BOOTSTRAP_ADMIN_EMAIL = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
BOOTSTRAP_ADMIN_PASSWORD = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "").strip()

# --- Rate limit for login ---
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_LOCKOUT_MINUTES = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))

# --- SMS-konfiguration ---
SMS_URL = os.getenv("SMS_URL", "https://smsoutbound.api.v1.smscph.dk/SendSms").strip()
SMS_AUTH_TOKEN = os.getenv("SMS_AUTH_TOKEN", "").strip()
SMS_CHANNEL = os.getenv("SMS_CHANNEL", "1900").strip()
SMS_SERVICE_ID = os.getenv("SMS_SERVICE_ID", "single_sms").strip()
SMS_DEFAULT_SENDER = os.getenv("SMS_DEFAULT_SENDER", "UNICEF").strip()
SMS_TIMEOUT_SECONDS = int(os.getenv("SMS_TIMEOUT_SECONDS", "15"))
MAX_SMS_TEXT_LENGTH = int(os.getenv("MAX_SMS_TEXT_LENGTH", "1000"))

# --- Mail ---
DEFAULT_EMAIL_SUBJECT = os.getenv("DEFAULT_EMAIL_SUBJECT", "Sikkert engangslink fra UNICEF").strip()

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required")
if not MASTER_KEY:
    raise RuntimeError("MASTER_KEY is required")
if not ADMIN_TOKEN:
    raise RuntimeError("ADMIN_TOKEN is required")
if not FLASK_SECRET_KEY:
    raise RuntimeError("FLASK_SECRET_KEY is required (brug fx 'python -c \"import secrets; print(secrets.token_urlsafe(48))\"')")

fernet = Fernet(MASTER_KEY.encode())

app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_HOURS),
)

DEFAULT_SMS_TEMPLATE = (
    "Hej {name}\n\n"
    "Her er din kode: {passphrase}\n\n"
    "Venlig hilsen\n"
    "UNICEF"
)

# Login-forsøg pr. IP (in-memory). Nulstilles ved restart.
_login_attempts: dict[str, list[float]] = {}


# =====================================================================
# Templates
# =====================================================================

LOGIN_TEMPLATE = """
<!doctype html>
<html lang="da">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Log ind</title>
  <style>
    body { font-family: Arial, sans-serif; background:#0f172a; color:#e2e8f0; margin:0;
           min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px; }
    .card { max-width:420px; width:100%; background:#111827; border:1px solid #334155;
            border-radius:12px; padding:32px; }
    h1 { margin-top:0; }
    label { display:block; margin:16px 0 6px; font-weight:600; }
    input, button { width:100%; box-sizing:border-box; border-radius:8px; border:1px solid #475569;
                    background:#0b1220; color:#e2e8f0; padding:12px; font-size:15px; }
    button { background:#2563eb; border:none; cursor:pointer; font-weight:700; margin-top:20px; }
    button:hover { background:#1d4ed8; }
    .msg { margin:16px 0 0 0; padding:12px 14px; border-radius:8px; }
    .err { background:#450a0a; border:1px solid #991b1b; }
    .ok  { background:#052e16; border:1px solid #166534; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Log ind</h1>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, message in messages %}
        <div class="msg {{ 'err' if category == 'error' else 'ok' }}">{{ message }}</div>
      {% endfor %}
    {% endwith %}
    <form method="post" action="/login" autocomplete="off">
      <label>Email</label>
      <input type="email" name="email" required autofocus>
      <label>Kodeord</label>
      <input type="password" name="password" required>
      <button type="submit">Log ind</button>
    </form>
  </div>
</body>
</html>
"""

CREATE_TEMPLATE = """
<!doctype html>
<html lang="da">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>One-time secret</title>
  <style>
    body { font-family: Arial, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:40px; }
    .card { max-width: 920px; margin: 0 auto; background:#111827; border:1px solid #334155; border-radius:12px; padding:24px; }
    .topbar { display:flex; justify-content:space-between; align-items:center; max-width:920px;
              margin: 0 auto 12px auto; color:#94a3b8; font-size:14px; }
    .topbar a { color:#60a5fa; text-decoration:none; }
    .topbar a:hover { text-decoration:underline; }
    h1 { margin-top:0; }
    h2 { margin-top:28px; font-size:18px; color:#cbd5e1; border-bottom:1px solid #334155; padding-bottom:6px; }
    label { display:block; margin:16px 0 6px; font-weight:600; }
    input, textarea, button { width:100%; box-sizing:border-box; border-radius:8px; border:1px solid #475569; background:#0b1220; color:#e2e8f0; padding:12px; }
    textarea { min-height:140px; resize:vertical; font-family: Arial, sans-serif; }
    button { background:#2563eb; border:none; cursor:pointer; font-weight:700; margin-top:20px; }
    button:hover { background:#1d4ed8; }
    button.secondary { background:#0ea5e9; }
    button.secondary:hover { background:#0284c7; }
    .btn-row { display:flex; gap:10px; margin-top:14px; }
    .btn-row button { margin-top:0; }
    .msg { margin:16px 0; padding:12px 14px; border-radius:8px; }
    .ok { background:#052e16; border:1px solid #166534; }
    .err { background:#450a0a; border:1px solid #991b1b; }
    code, pre { background:#020617; padding:3px 6px; border-radius:6px; }
    pre { white-space:pre-wrap; word-break:break-word; padding:16px; }
    .small { color:#94a3b8; font-size:14px; }
    .hint { color:#94a3b8; font-size:13px; margin-top:4px; }
    .row { display:grid; grid-template-columns: 1fr 1fr; gap:16px; }
    @media (max-width: 700px) { .row { grid-template-columns: 1fr; } .btn-row { flex-direction: column; } }
  </style>
</head>
<body>
  <div class="topbar">
    <span>Logget ind som <strong>{{ current_user }}</strong> &middot; <a href="/users">Brugere</a></span>
    <a href="/logout">Log ud</a>
  </div>

  <div class="card">
    <h1>One-time secret</h1>
    <p class="small">
      Linket genereres som <code>/s#token</code>, så token ikke sendes til serveren i URL'en
      og derfor normalt ikke ender i access logs.
    </p>

    {% if error %}
      <div class="msg err">{{ error }}</div>
    {% endif %}

    {% if result %}
      <div class="msg ok">
        <div><strong>Link oprettet</strong></div>
        <div>Udløber: {{ result.expires_at }}</div>
        {% if result.sms_status %}
          <div>SMS: {{ result.sms_status }}</div>
        {% endif %}
        <pre id="linkBox">{{ result.url }}</pre>
        <div class="btn-row">
          <button type="button" onclick="copyLink()">Kopiér link</button>
          {% if result.email_to %}
            <button type="button" class="secondary" onclick="openMail()">Åbn mail i Outlook</button>
          {% endif %}
        </div>
      </div>

      {% if result.email_to %}
        <script>
          window.__mail = {
            to: {{ result.email_to|tojson }},
            subject: {{ result.email_subject|tojson }},
            recipientName: {{ result.email_recipient_name|tojson }},
            link: {{ result.url|tojson }},
            smsSent: {{ result.sms_was_sent|tojson }}
          };
        </script>
      {% endif %}
    {% endif %}

    <form method="post" action="/create" autocomplete="off">
      <h2>Secret</h2>

      <label>Secret</label>
      <textarea name="secret" required></textarea>

      <div class="row">
        <div>
          <label>TTL i minutter</label>
          <input type="number" name="ttl_minutes" min="1" max="10080" value="1440" required>
        </div>
        <div>
          <label>Passphrase (valgfri, men anbefalet hvis SMS bruges)</label>
          <input type="text" name="passphrase" placeholder="Ekstra kode, kan sendes via SMS">
        </div>
      </div>

      <h2>SMS (valgfri)</h2>
      <p class="small">
        Udfyldes modtagernummeret, sendes der automatisk en SMS via smscph.dk med passphrasen.
      </p>

      <div class="row">
        <div>
          <label>Modtagernummer</label>
          <input type="text" name="recipient_msisdn" placeholder="fx 12345678 eller 4512345678">
          <div class="hint">8 cifre antages som DK og får automatisk 45-prefix.</div>
        </div>
        <div>
          <label>Modtagernavn</label>
          <input type="text" name="recipient_name" placeholder="fx Anne Hansen">
        </div>
      </div>

      <label>Afsendernavn (senderAlias)</label>
      <input type="text" name="sender_alias" maxlength="11" value="UNICEF" placeholder="Max 11 tegn">

      <h2>Mail (valgfri)</h2>
      <p class="small">
        Udfyldes modtagermailen, vises en knap efter oprettelse, der åbner en forudfyldt mail i Outlook.
      </p>

      <div class="row">
        <div>
          <label>Modtagermail</label>
          <input type="email" name="recipient_email" placeholder="fx anne@unicef.dk">
        </div>
        <div>
          <label>Emnefelt (valgfri)</label>
          <input type="text" name="email_subject" placeholder="{{ default_subject }}">
        </div>
      </div>

      <button type="submit">Opret engangslink</button>
    </form>
  </div>

  <script>
    async function copyLink() {
      const value = document.getElementById("linkBox")?.innerText || "";
      if (!value) return;
      await navigator.clipboard.writeText(value);
      alert("Link kopieret");
    }

    function openMail() {
      const m = window.__mail;
      if (!m) return;

      const greeting = m.recipientName ? "Hej " + m.recipientName + "," : "Hej,";
      const smsLine = m.smsSent
        ? "Koden til at åbne linket har du modtaget separat via SMS."
        : "";

      const bodyLines = [
        greeting,
        "",
        "Du har modtaget et sikkert engangslink. Linket kan kun åbnes én gang og udløber automatisk.",
        ""
      ];
      if (smsLine) {
        bodyLines.push(smsLine, "");
      }
      bodyLines.push(
        "Link:",
        m.link,
        "",
        "Venlig hilsen",
        "UNICEF"
      );
      const body = bodyLines.join("\\n");

      const href =
        "mailto:" + encodeURIComponent(m.to) +
        "?subject=" + encodeURIComponent(m.subject) +
        "&body=" + encodeURIComponent(body);

      window.location.href = href;
    }
  </script>
</body>
</html>
"""

USERS_TEMPLATE = """
<!doctype html>
<html lang="da">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Brugere</title>
  <style>
    body { font-family: Arial, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:40px; }
    .card { max-width: 920px; margin: 0 auto; background:#111827; border:1px solid #334155; border-radius:12px; padding:24px; }
    .topbar { display:flex; justify-content:space-between; align-items:center; max-width:920px;
              margin: 0 auto 12px auto; color:#94a3b8; font-size:14px; }
    .topbar a { color:#60a5fa; text-decoration:none; }
    .topbar a:hover { text-decoration:underline; }
    h1 { margin-top:0; }
    h2 { margin-top:28px; font-size:18px; color:#cbd5e1; border-bottom:1px solid #334155; padding-bottom:6px; }
    label { display:block; margin:16px 0 6px; font-weight:600; }
    input, button { width:100%; box-sizing:border-box; border-radius:8px; border:1px solid #475569; background:#0b1220; color:#e2e8f0; padding:12px; }
    button { background:#2563eb; border:none; cursor:pointer; font-weight:700; margin-top:20px; }
    button:hover { background:#1d4ed8; }
    button.secondary { background:#0ea5e9; }
    button.secondary:hover { background:#0284c7; }
    .btn-row { display:flex; gap:10px; margin-top:14px; }
    .btn-row button { margin-top:0; }
    .msg { margin:16px 0; padding:12px 14px; border-radius:8px; }
    .ok { background:#052e16; border:1px solid #166534; }
    .err { background:#450a0a; border:1px solid #991b1b; }
    code, pre { background:#020617; padding:3px 6px; border-radius:6px; }
    pre { white-space:pre-wrap; word-break:break-word; padding:16px; }
    table { width:100%; border-collapse:collapse; margin-top:12px; }
    th, td { text-align:left; padding:10px; border-bottom:1px solid #334155; font-size:14px; }
    th { color:#94a3b8; font-weight:600; }
    .small { color:#94a3b8; font-size:13px; }
  </style>
</head>
<body>
  <div class="topbar">
    <span>Logget ind som <strong>{{ current_user }}</strong> &middot; <a href="/">Opret link</a></span>
    <a href="/logout">Log ud</a>
  </div>

  <div class="card">
    <h1>Brugere</h1>

    {% if error %}
      <div class="msg err">{{ error }}</div>
    {% endif %}

    {% if invite_result %}
      <div class="msg ok">
        <div><strong>Invitation oprettet til {{ invite_result.email }}</strong></div>
        <div>Udløber: {{ invite_result.expires_at }}</div>
        <pre id="inviteLink">{{ invite_result.url }}</pre>
        <div class="btn-row">
          <button type="button" onclick="copyInvite()">Kopiér link</button>
          <button type="button" class="secondary" onclick="openMail()">Åbn mail i Outlook</button>
        </div>
      </div>
      <script>
        window.__invite = {
          to: {{ invite_result.email|tojson }},
          link: {{ invite_result.url|tojson }},
          hours: {{ invite_hours|tojson }}
        };
      </script>
    {% endif %}

    <h2>Inviter ny bruger</h2>
    <form method="post" action="/users/invite" autocomplete="off">
      <label>Email</label>
      <input type="email" name="email" required placeholder="fx anne@unicef.dk">
      <button type="submit">Opret invitation</button>
    </form>

    <h2>Eksisterende brugere</h2>
    {% if users %}
      <table>
        <thead><tr><th>Email</th><th>Oprettet</th><th>Sidste login</th></tr></thead>
        <tbody>
          {% for u in users %}
            <tr>
              <td>{{ u.email }}</td>
              <td class="small">{{ u.created_at }}</td>
              <td class="small">{{ u.last_login_at or 'aldrig' }}</td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <p class="small">Ingen brugere.</p>
    {% endif %}

    <h2>Afventende invitationer</h2>
    {% if invites %}
      <table>
        <thead><tr><th>Email</th><th>Oprettet</th><th>Udløber</th><th>Af</th></tr></thead>
        <tbody>
          {% for i in invites %}
            <tr>
              <td>{{ i.email }}</td>
              <td class="small">{{ i.created_at }}</td>
              <td class="small">{{ i.expires_at }}</td>
              <td class="small">{{ i.created_by }}</td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <p class="small">Ingen afventende invitationer.</p>
    {% endif %}
  </div>

  <script>
    async function copyInvite() {
      const value = document.getElementById("inviteLink")?.innerText || "";
      if (!value) return;
      await navigator.clipboard.writeText(value);
      alert("Link kopieret");
    }

    function openMail() {
      const i = window.__invite;
      if (!i) return;

      const subject = "Adgang til UNICEF secret-værktøj";
      const bodyLines = [
        "Hej,",
        "",
        "Du er blevet inviteret som bruger af UNICEF's interne værktøj til sikre engangslinks.",
        "",
        "Brug linket nedenfor til at vælge dit kodeord. Linket udløber om " + i.hours + " timer og kan kun bruges én gang.",
        "",
        "Link:",
        i.link,
        "",
        "Venlig hilsen",
        "UNICEF"
      ];
      const body = bodyLines.join("\\n");
      const href =
        "mailto:" + encodeURIComponent(i.to) +
        "?subject=" + encodeURIComponent(subject) +
        "&body=" + encodeURIComponent(body);
      window.location.href = href;
    }
  </script>
</body>
</html>
"""

INVITE_TEMPLATE = """
<!doctype html>
<html lang="da">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Vælg kodeord</title>
  <style>
    body { font-family: Arial, sans-serif; background:#0f172a; color:#e2e8f0; margin:0;
           min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px; }
    .card { max-width:460px; width:100%; background:#111827; border:1px solid #334155;
            border-radius:12px; padding:32px; }
    h1 { margin-top:0; }
    label { display:block; margin:16px 0 6px; font-weight:600; }
    input, button { width:100%; box-sizing:border-box; border-radius:8px; border:1px solid #475569;
                    background:#0b1220; color:#e2e8f0; padding:12px; font-size:15px; }
    button { background:#2563eb; border:none; cursor:pointer; font-weight:700; margin-top:20px; }
    button:hover { background:#1d4ed8; }
    .msg { margin:16px 0 0 0; padding:12px 14px; border-radius:8px; }
    .err { background:#450a0a; border:1px solid #991b1b; }
    .ok  { background:#052e16; border:1px solid #166534; }
    .small { color:#94a3b8; font-size:13px; margin-top:8px; }
    input[readonly] { background:#020617; color:#94a3b8; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Vælg kodeord</h1>
    <p class="small">Færdiggør oprettelsen af din bruger ved at vælge et kodeord (mindst 8 tegn).</p>

    <div id="errorBox" class="msg err" hidden></div>
    <div id="okBox" class="msg ok" hidden></div>

    <form id="setForm" autocomplete="off">
      <label>Email</label>
      <input type="email" id="email" readonly>
      <label>Nyt kodeord</label>
      <input type="password" id="password" minlength="8" required autofocus>
      <label>Bekræft kodeord</label>
      <input type="password" id="password2" minlength="8" required>
      <button type="submit">Gem og log ind</button>
    </form>
  </div>

  <script>
    const errorBox = document.getElementById("errorBox");
    const okBox = document.getElementById("okBox");
    const setForm = document.getElementById("setForm");
    const emailField = document.getElementById("email");

    function showError(msg) {
      okBox.hidden = true;
      errorBox.hidden = false;
      errorBox.textContent = msg;
    }
    function showOk(msg) {
      errorBox.hidden = true;
      okBox.hidden = false;
      okBox.textContent = msg;
    }

    const token = window.location.hash ? window.location.hash.substring(1) : "";
    if (!token) {
      setForm.hidden = true;
      showError("Linket er ikke komplet. Kontrollér, at du har åbnet hele linket, præcis som det blev sendt til dig.");
    } else {
      // Hent email tilhørende token
      fetch("/api/invites/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: token })
      }).then(r => r.json().then(d => ({ ok: r.ok, data: d })))
        .then(({ ok, data }) => {
          if (!ok) {
            setForm.hidden = true;
            showError(data.error || "Invite-linket er ugyldigt eller udløbet.");
            return;
          }
          emailField.value = data.email;
        }).catch(() => {
          setForm.hidden = true;
          showError("Kunne ikke validere linket. Prøv igen om et øjeblik.");
        });
    }

    setForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const password = document.getElementById("password").value;
      const password2 = document.getElementById("password2").value;
      if (password !== password2) {
        showError("Kodeordene matcher ikke.");
        return;
      }
      try {
        const response = await fetch("/api/invites/consume", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: token, password: password })
        });
        const data = await response.json();
        if (!response.ok) {
          showError(data.error || "Kunne ikke gemme kodeordet.");
          return;
        }
        showOk("Bruger oprettet. Du sendes til log ind-siden ...");
        setTimeout(() => { window.location.href = "/login"; }, 1500);
      } catch (err) {
        showError("Midlertidig forbindelsesfejl. Prøv igen om et øjeblik.");
      }
    });
  </script>
</body>
</html>
"""

REVEAL_TEMPLATE = """
<!doctype html>
<html lang="da">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sikker adgang til delt nøgle</title>
  <style>
    :root {
      --bg: #0b1020; --bg2: #11172a; --card: rgba(17, 24, 39, 0.88);
      --border: rgba(148, 163, 184, 0.16); --text: #e5eefc; --muted: #9fb0cc;
      --primary: #4f8cff; --primary-hover: #3d79eb;
      --success-bg: rgba(22, 101, 52, 0.18); --success-border: rgba(34, 197, 94, 0.35);
      --error-bg: rgba(127, 29, 29, 0.22); --error-border: rgba(248, 113, 113, 0.32);
      --input: rgba(15, 23, 42, 0.75); --shadow: 0 20px 60px rgba(0,0,0,0.35);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; font-family: Inter, Arial, sans-serif; color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(79,140,255,0.20), transparent 30%),
        radial-gradient(circle at top right, rgba(59,130,246,0.16), transparent 25%),
        linear-gradient(180deg, var(--bg) 0%, var(--bg2) 100%);
      min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 32px 20px;
    }
    .wrap { width: 100%; max-width: 760px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 20px; box-shadow: var(--shadow); overflow: hidden; backdrop-filter: blur(10px); }
    .hero { padding: 28px 28px 18px 28px; border-bottom: 1px solid rgba(148, 163, 184, 0.10); background: linear-gradient(180deg, rgba(79,140,255,0.10) 0%, rgba(79,140,255,0.03) 100%); }
    .badge { display: inline-flex; align-items: center; gap: 8px; font-size: 12px; letter-spacing: 0.04em; text-transform: uppercase; color: #c7d7ff; background: rgba(79,140,255,0.12); border: 1px solid rgba(79,140,255,0.22); padding: 8px 12px; border-radius: 999px; margin-bottom: 16px; }
    h1 { margin: 0 0 12px 0; font-size: 30px; line-height: 1.15; font-weight: 700; }
    .lead { margin: 0; color: var(--muted); font-size: 16px; line-height: 1.6; max-width: 620px; }
    .body { padding: 28px; }
    .panel { background: rgba(2, 6, 23, 0.38); border: 1px solid rgba(148, 163, 184, 0.10); border-radius: 16px; padding: 22px; margin-bottom: 18px; }
    .panel h2 { margin: 0 0 8px 0; font-size: 18px; }
    .panel p { margin: 0; color: var(--muted); line-height: 1.6; font-size: 15px; }
    input { width: 100%; padding: 14px 14px; border-radius: 12px; border: 1px solid rgba(148, 163, 184, 0.18); background: var(--input); color: var(--text); outline: none; font-size: 15px; }
    input:focus { border-color: rgba(79,140,255,0.55); box-shadow: 0 0 0 4px rgba(79,140,255,0.12); }
    button { width: 100%; margin-top: 18px; border: 0; border-radius: 12px; background: var(--primary); color: white; font-weight: 700; font-size: 15px; padding: 14px 16px; cursor: pointer; transition: background 0.15s ease, transform 0.05s ease; }
    button:hover { background: var(--primary-hover); }
    button:active { transform: translateY(1px); }
    .msg { margin-bottom: 18px; padding: 16px 18px; border-radius: 14px; line-height: 1.55; font-size: 15px; }
    .ok { background: var(--success-bg); border: 1px solid var(--success-border); }
    .err { background: var(--error-bg); border: 1px solid var(--error-border); }
    .msg strong { display: block; margin-bottom: 4px; }
    .secret-box { position: relative; margin-top: 14px; background: rgba(2, 6, 23, 0.72); border: 1px solid rgba(148, 163, 184, 0.10); border-radius: 12px; overflow: hidden; }
    .copy-chip { position: absolute; top: 12px; right: 12px; width: auto; margin: 0; padding: 8px 12px; border-radius: 10px; background: rgba(79,140,255,0.18); border: 1px solid rgba(79,140,255,0.30); color: #eaf2ff; font-size: 13px; font-weight: 700; line-height: 1; z-index: 2; }
    .copy-chip:hover { background: rgba(79,140,255,0.28); }
    pre { margin: 0; white-space: pre-wrap; word-break: break-word; padding: 52px 16px 16px 16px; color: #f8fbff; font-size: 14px; overflow: auto; background: transparent; border: 0; }
    .copy-status { margin-top: 10px; color: #bbf7d0; font-size: 13px; display: none; }
    .note { margin-top: 12px; color: var(--muted); font-size: 13px; line-height: 1.6; }
    .footer { padding: 0 28px 24px 28px; color: var(--muted); font-size: 13px; line-height: 1.6; }
    @media (max-width: 640px) {
      h1 { font-size: 24px; }
      .hero, .body, .footer { padding-left: 20px; padding-right: 20px; }
      .copy-chip { top: 10px; right: 10px; }
      pre { padding-top: 50px; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="hero">
        <div class="badge">Sikker engangsadgang</div>
        <h1>Sikker adgang til delt nøgle</h1>
        <p class="lead">Denne nøgle er delt sikkert og kan kun vises én gang.</p>
      </div>
      <div class="body">
        <div id="errorBox" class="msg err" hidden></div>
        <div class="panel">
          <h2>Før du fortsætter</h2>
          <p>UNICEF har sendt en kode, som skal indtastes nedenfor for at få adgang til nøglen.</p>
        </div>
        <form id="revealForm" autocomplete="off">
          <input type="text" id="passphrase" placeholder="Indtast koden fra UNICEF" required>
          <button type="submit">Vis nøgle sikkert</button>
        </form>
        <div id="resultBox" class="msg ok" hidden>
          <strong>Nøglen er nu vist</strong>
          <div>Indholdet nedenfor er nu forbrugt og kan ikke hentes igen via samme link.</div>
          <div class="secret-box">
            <button type="button" class="copy-chip" onclick="copySecret()">Kopiér</button>
            <pre id="secretValue"></pre>
          </div>
          <div id="copyStatus" class="copy-status">Nøglen er kopieret til udklipsholderen.</div>
          <div class="note">Gem nøglen sikkert med det samme, hvis du skal bruge den senere.</div>
        </div>
      </div>
      <div class="footer">Af sikkerhedsmæssige årsager bliver nøglen ikke vist automatisk og kan kun åbnes én gang.</div>
    </div>
  </div>
  <script>
    const errorBox = document.getElementById("errorBox");
    const revealForm = document.getElementById("revealForm");
    const resultBox = document.getElementById("resultBox");
    const secretValue = document.getElementById("secretValue");
    const copyStatus = document.getElementById("copyStatus");

    function showError(title, message) {
      errorBox.hidden = false;
      errorBox.innerHTML = "<strong>" + title + "</strong><div>" + message + "</div>";
    }
    async function copySecret() {
      const value = secretValue.textContent || "";
      if (!value) return;
      try {
        await navigator.clipboard.writeText(value);
        copyStatus.style.display = "block";
        copyStatus.textContent = "Nøglen er kopieret til udklipsholderen.";
      } catch (err) {
        copyStatus.style.display = "block";
        copyStatus.textContent = "Kunne ikke kopiere automatisk. Markér og kopiér nøglen manuelt.";
      }
    }
    const token = window.location.hash ? window.location.hash.substring(1) : "";
    if (!token) {
      revealForm.hidden = true;
      showError("Linket er ikke komplet", "Det ser ud til, at linket mangler den sikre adgangsdel. Kontrollér, at du har åbnet hele linket, præcis som det blev sendt til dig.");
    }
    revealForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const passphrase = document.getElementById("passphrase").value;
      try {
        const response = await fetch("/api/reveal", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: token, passphrase: passphrase })
        });
        const data = await response.json();
        if (!response.ok) {
          showError("Adgang kunne ikke gennemføres", data.error || "Nøglen kunne ikke hentes. Kontrollér linket og prøv igen.");
          return;
        }
        revealForm.hidden = true;
        errorBox.hidden = true;
        copyStatus.style.display = "none";
        resultBox.hidden = false;
        secretValue.textContent = data.secret;
      } catch (err) {
        showError("Midlertidig forbindelsesfejl", "Der opstod en fejl under hentning af nøglen. Prøv igen om et øjeblik.");
      }
    });
  </script>
</body>
</html>
"""


# =====================================================================
# DB
# =====================================================================

def get_conn():
    return psycopg.connect(DATABASE_URL)


def init_db():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    id BIGSERIAL PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    encrypted_secret BYTEA NOT NULL,
                    passphrase_hash TEXT NULL,
                    expires_at BIGINT NOT NULL,
                    created_at BIGINT NOT NULL
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets (expires_at)"
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id BIGSERIAL PRIMARY KEY,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at BIGINT NOT NULL,
                    last_login_at BIGINT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS user_invites (
                    id BIGSERIAL PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL,
                    expires_at BIGINT NOT NULL,
                    created_at BIGINT NOT NULL,
                    created_by TEXT NOT NULL
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_invites_expires_at ON user_invites (expires_at)"
            )


def now_epoch():
    return int(datetime.now(timezone.utc).timestamp())


def iso_z(epoch_value: int) -> str:
    return (
        datetime.fromtimestamp(epoch_value, timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def cleanup_expired(cur):
    cur.execute("DELETE FROM secrets WHERE expires_at <= %s", (now_epoch(),))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def get_base_url():
    if APP_BASE_URL:
        return APP_BASE_URL
    proto = request.headers.get("X-Forwarded-Proto", request.scheme)
    host = request.headers.get("X-Forwarded-Host", request.host)
    return f"{proto}://{host}"


# =====================================================================
# Bruger-administration
# =====================================================================

def normalize_email(email: str) -> str:
    return (email or "").strip().lower()


def upsert_user(email: str, password: str) -> None:
    """Opretter eller opdaterer bruger med ny adgangskode."""
    email = normalize_email(email)
    if not email or "@" not in email:
        raise ValueError("Ugyldig email.")
    if not password or len(password) < 8:
        raise ValueError("Adgangskode skal være mindst 8 tegn.")

    password_hash = generate_password_hash(password)
    now = now_epoch()
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (email, password_hash, created_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (email) DO UPDATE
                  SET password_hash = EXCLUDED.password_hash
                """,
                (email, password_hash, now),
            )


def get_user_by_email(email: str):
    email = normalize_email(email)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, email, password_hash FROM users WHERE email = %s",
                (email,),
            )
            return cur.fetchone()


def update_last_login(user_id: int) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET last_login_at = %s WHERE id = %s",
                (now_epoch(), user_id),
            )


# ---------- Invite-funktioner ----------

def cleanup_expired_invites(cur):
    cur.execute("DELETE FROM user_invites WHERE expires_at <= %s", (now_epoch(),))


def create_invite(email: str, created_by: str) -> tuple[str, int]:
    """
    Opretter et invite-token til den givne email.
    Fejler hvis bruger allerede findes.
    Returnerer (token, expires_at_epoch).
    """
    email = normalize_email(email)
    if not email or not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        raise ValueError("Ugyldig email.")
    if len(email) > 254:
        raise ValueError("Email er for lang.")

    existing = get_user_by_email(email)
    if existing:
        raise ValueError(f"Bruger {email} findes allerede.")

    token = pysecrets.token_urlsafe(32)
    token_hash = sha256_text(token)
    created_at = now_epoch()
    expires_at = created_at + (INVITE_HOURS * 3600)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cleanup_expired_invites(cur)
            cur.execute(
                """
                INSERT INTO user_invites (token_hash, email, expires_at, created_at, created_by)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (token_hash, email, expires_at, created_at, created_by),
            )

    log.info("Invite oprettet email=%s created_by=%s", email, created_by)
    return token, expires_at


def lookup_invite_email(token: str) -> str | None:
    """Returnerer email hvis token er gyldigt og ikke udløbet, ellers None."""
    if not isinstance(token, str) or not token or len(token) > 500:
        return None
    token_hash = sha256_text(token)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cleanup_expired_invites(cur)
            cur.execute(
                """
                SELECT email FROM user_invites
                WHERE token_hash = %s AND expires_at > %s
                """,
                (token_hash, now_epoch()),
            )
            row = cur.fetchone()
            return row[0] if row else None


def consume_invite(token: str, password: str) -> tuple[str | None, str | None, int]:
    """
    Forbruger et invite-token og opretter brugeren med det valgte kodeord.
    Returnerer (email_eller_None, fejl_eller_None, http_status).
    """
    if not isinstance(token, str) or not token or len(token) > 500:
        return None, "Ugyldigt invite-link.", 400
    if not password or len(password) < 8:
        return None, "Adgangskode skal være mindst 8 tegn.", 400
    if len(password) > 1024:
        return None, "Adgangskode er for lang.", 400

    token_hash = sha256_text(token)
    password_hash = generate_password_hash(password)
    now = now_epoch()

    with get_conn() as conn:
        with conn.cursor() as cur:
            cleanup_expired_invites(cur)
            cur.execute(
                """
                SELECT id, email FROM user_invites
                WHERE token_hash = %s AND expires_at > %s
                FOR UPDATE
                """,
                (token_hash, now_epoch()),
            )
            row = cur.fetchone()
            if row is None:
                return None, "Invite-linket er ugyldigt, udløbet eller allerede brugt.", 404

            invite_id, email = row

            # Tjek igen om brugeren er blevet oprettet i mellemtiden
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                cur.execute("DELETE FROM user_invites WHERE id = %s", (invite_id,))
                return None, "Bruger findes allerede. Brug log ind-siden.", 409

            cur.execute(
                """
                INSERT INTO users (email, password_hash, created_at)
                VALUES (%s, %s, %s)
                """,
                (email, password_hash, now),
            )
            cur.execute("DELETE FROM user_invites WHERE id = %s", (invite_id,))

    log.info("Bruger oprettet via invite email=%s", email)
    return email, None, 200


def list_users() -> list[dict]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT email, created_at, last_login_at FROM users ORDER BY created_at DESC"
            )
            rows = cur.fetchall()
    return [
        {
            "email": email,
            "created_at": iso_z(created),
            "last_login_at": iso_z(last) if last else None,
        }
        for (email, created, last) in rows
    ]


def list_pending_invites() -> list[dict]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cleanup_expired_invites(cur)
            cur.execute(
                """
                SELECT email, created_at, expires_at, created_by
                FROM user_invites
                ORDER BY created_at DESC
                """
            )
            rows = cur.fetchall()
    return [
        {
            "email": email,
            "created_at": iso_z(created),
            "expires_at": iso_z(expires),
            "created_by": created_by,
        }
        for (email, created, expires, created_by) in rows
    ]


def bootstrap_user_if_configured():
    if not BOOTSTRAP_ADMIN_EMAIL or not BOOTSTRAP_ADMIN_PASSWORD:
        return
    existing = get_user_by_email(BOOTSTRAP_ADMIN_EMAIL)
    if existing:
        return
    try:
        upsert_user(BOOTSTRAP_ADMIN_EMAIL, BOOTSTRAP_ADMIN_PASSWORD)
        log.info("Bootstrap-bruger oprettet: %s", BOOTSTRAP_ADMIN_EMAIL)
    except ValueError as exc:
        log.error("Kunne ikke oprette bootstrap-bruger: %s", exc)


# =====================================================================
# Auth helpers
# =====================================================================

def client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_rate_limited(ip: str) -> bool:
    cutoff = time.time() - (LOGIN_LOCKOUT_MINUTES * 60)
    attempts = [t for t in _login_attempts.get(ip, []) if t > cutoff]
    _login_attempts[ip] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def record_failed_login(ip: str) -> None:
    _login_attempts.setdefault(ip, []).append(time.time())


def clear_failed_logins(ip: str) -> None:
    _login_attempts.pop(ip, None)


def extract_admin_token() -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    header_token = request.headers.get("X-Admin-Token")
    if header_token:
        return header_token.strip()
    json_body = request.get_json(silent=True) or {}
    json_token = json_body.get("admin_token")
    if json_token:
        return str(json_token).strip()
    return ""


def is_admin_token_valid() -> bool:
    provided = extract_admin_token()
    return bool(provided) and pysecrets.compare_digest(provided, ADMIN_TOKEN)


def is_logged_in() -> bool:
    return bool(session.get("user_email"))


def current_user_label() -> str:
    return session.get("user_email") or "API"


def login_required_web(view):
    """Sender til /login hvis ikke logget ind."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def api_auth_required(view):
    """Accepterer enten session eller admin-token."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if is_logged_in() or is_admin_token_valid():
            return view(*args, **kwargs)
        return jsonify({"error": "Unauthorized"}), 401
    return wrapper


# =====================================================================
# Validering
# =====================================================================

def normalize_msisdn(raw: str) -> str:
    if not raw:
        raise ValueError("Modtagernummer mangler.")
    cleaned = re.sub(r"[\s\-\(\)\.]", "", raw.strip())
    if cleaned.startswith("+"):
        cleaned = cleaned[1:]
    if not cleaned.isdigit():
        raise ValueError("Modtagernummer må kun indeholde cifre (evt. med + prefix).")
    if len(cleaned) == 8:
        cleaned = "45" + cleaned
    if len(cleaned) < 9 or len(cleaned) > 15:
        raise ValueError("Modtagernummer skal være 8 cifre (DK) eller 9-15 cifre med landekode.")
    return cleaned


def validate_sender_alias(alias: str) -> str:
    alias = (alias or "").strip()
    if not alias:
        return SMS_DEFAULT_SENDER
    if len(alias) > 11:
        raise ValueError("Afsendernavn må maks være 11 tegn.")
    if not re.match(r"^[A-Za-z0-9 ]+$", alias):
        raise ValueError("Afsendernavn må kun indeholde bogstaver, cifre og mellemrum.")
    return alias


def validate_email_address(email: str) -> str:
    email = (email or "").strip()
    if not email:
        raise ValueError("Modtagermail mangler.")
    if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        raise ValueError("Modtagermail har ugyldigt format.")
    if len(email) > 254:
        raise ValueError("Modtagermail er for lang.")
    return email


# =====================================================================
# SMS
# =====================================================================

def render_sms_text(template: str, *, name: str, passphrase: str, link: str) -> str:
    text = template or DEFAULT_SMS_TEMPLATE
    name_clean = (name or "").strip()
    if not name_clean:
        text = re.sub(r"^Hej\s*\{name\}\s*\n+", "", text)
    text = text.replace("{name}", name_clean)
    text = text.replace("{passphrase}", passphrase or "")
    text = text.replace("{link}", link or "")
    return text.strip()


def send_sms(msisdn: str, sender_alias: str, text: str) -> dict:
    if not SMS_AUTH_TOKEN:
        raise RuntimeError("SMS_AUTH_TOKEN er ikke konfigureret.")
    if not text:
        raise RuntimeError("SMS-tekst er tom.")
    if len(text) > MAX_SMS_TEXT_LENGTH:
        raise RuntimeError(f"SMS-tekst overstiger {MAX_SMS_TEXT_LENGTH} tegn.")

    payload = {
        "channel": SMS_CHANNEL,
        "senderAlias": sender_alias,
        "serviceId": SMS_SERVICE_ID,
        "msisdn": msisdn,
        "text": text,
    }
    body_str = json.dumps(payload, separators=(",", ":"))
    md5_hash = hashlib.md5(body_str.encode("utf-8")).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "Content-MD5": md5_hash,
        "Authorization": SMS_AUTH_TOKEN,
    }

    try:
        response = requests.post(SMS_URL, data=body_str, headers=headers, timeout=SMS_TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        log.warning("SMS network error to msisdn=%s: %s", msisdn, exc)
        raise RuntimeError(f"Netværksfejl ved SMS-afsendelse: {exc}") from exc

    raw_text = response.text or ""
    try:
        body = response.json()
    except ValueError:
        body = {"raw": raw_text}

    if response.status_code >= 400:
        log.warning("SMS API error msisdn=%s status=%s", msisdn, response.status_code)
        raise RuntimeError(f"SMS API svarede {response.status_code}: {raw_text[:300]}")

    message_id = None
    if isinstance(body, dict):
        message_id = body.get("messageId") or body.get("id") or body.get("reference")

    log.info("SMS sendt msisdn=%s status=%s message_id=%s", msisdn, response.status_code, message_id)
    return {
        "ok": True,
        "http_status": response.status_code,
        "message_id": message_id,
    }


# =====================================================================
# Secret-operationer
# =====================================================================

def create_secret_record(secret_value: str, ttl_minutes, passphrase: str | None):
    if not isinstance(secret_value, str) or secret_value == "":
        raise ValueError("Secret må ikke være tom.")

    if len(secret_value) > MAX_SECRET_LENGTH:
        raise ValueError(f"Secret er for lang. Maks længde er {MAX_SECRET_LENGTH} tegn.")

    try:
        ttl_minutes = int(ttl_minutes)
    except Exception:
        raise ValueError("TTL skal være et heltal i minutter.")

    if ttl_minutes < 1 or ttl_minutes > MAX_TTL_MINUTES:
        raise ValueError(f"TTL skal være mellem 1 og {MAX_TTL_MINUTES} minutter.")

    token = pysecrets.token_urlsafe(32)
    token_hash = sha256_text(token)
    created_at = now_epoch()
    expires_at = created_at + (ttl_minutes * 60)
    encrypted_secret = fernet.encrypt(secret_value.encode("utf-8"))
    passphrase_hash = generate_password_hash(passphrase) if passphrase else None

    with get_conn() as conn:
        with conn.cursor() as cur:
            cleanup_expired(cur)
            cur.execute(
                """
                INSERT INTO secrets (token_hash, encrypted_secret, passphrase_hash, expires_at, created_at)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (token_hash, encrypted_secret, passphrase_hash, expires_at, created_at),
            )
            row_id = cur.fetchone()[0]

    return row_id, token, expires_at


def delete_secret_by_id(row_id: int) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM secrets WHERE id = %s", (row_id,))


def reveal_secret_record(token: str, passphrase: str | None):
    if not isinstance(token, str) or token == "" or len(token) > 500:
        return None, "Mangler eller ugyldigt token.", 400

    token_hash = sha256_text(token)

    with get_conn() as conn:
        with conn.cursor() as cur:
            cleanup_expired(cur)

            cur.execute(
                """
                SELECT id, encrypted_secret, passphrase_hash
                FROM secrets
                WHERE token_hash = %s
                  AND expires_at > %s
                FOR UPDATE
                """,
                (token_hash, now_epoch()),
            )
            row = cur.fetchone()

            if row is None:
                return None, "Secret findes ikke, er udløbet eller er allerede brugt.", 404

            row_id, encrypted_secret, passphrase_hash = row

            if passphrase_hash:
                if not passphrase:
                    return None, "Passphrase er påkrævet.", 400

                if not check_password_hash(passphrase_hash, passphrase):
                    return None, "Forkert passphrase.", 403

            secret_value = fernet.decrypt(bytes(encrypted_secret)).decode("utf-8")
            cur.execute("DELETE FROM secrets WHERE id = %s", (row_id,))

    return secret_value, None, 200


# =====================================================================
# Orkestrering
# =====================================================================

def create_and_optionally_sms(
    *,
    secret_value: str,
    ttl_minutes,
    passphrase: str | None,
    recipient_msisdn: str | None,
    recipient_name: str | None,
    sender_alias: str | None,
    message_text: str | None,
):
    sms_enabled = bool((recipient_msisdn or "").strip())

    normalized_msisdn = None
    validated_sender = None
    if sms_enabled:
        if not (passphrase or "").strip():
            raise ValueError("Passphrase er påkrævet, når SMS skal sendes (koden indgår i beskeden).")
        normalized_msisdn = normalize_msisdn(recipient_msisdn)
        validated_sender = validate_sender_alias(sender_alias)

    row_id, token, expires_at = create_secret_record(secret_value, ttl_minutes, passphrase)

    sms_info = None
    if sms_enabled:
        one_time_url = f"{get_base_url()}/s#{token}"
        text = render_sms_text(
            message_text,
            name=(recipient_name or "").strip(),
            passphrase=(passphrase or "").strip(),
            link=one_time_url,
        )
        try:
            sms_info = send_sms(normalized_msisdn, validated_sender, text)
        except Exception:
            try:
                delete_secret_by_id(row_id)
            except Exception as cleanup_exc:
                log.error("Failed to roll back secret %s after SMS error: %s", row_id, cleanup_exc)
            raise

    return token, expires_at, sms_info


# =====================================================================
# Middleware
# =====================================================================

@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none';"
    )
    return response


# =====================================================================
# Routes
# =====================================================================

@app.route("/healthz", methods=["GET"])
def healthz():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
    return jsonify({"status": "ok"}), 200


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if is_logged_in():
            return redirect(url_for("index"))
        return render_template_string(LOGIN_TEMPLATE)

    ip = client_ip()
    if is_rate_limited(ip):
        flash(f"For mange mislykkede forsøg. Prøv igen om {LOGIN_LOCKOUT_MINUTES} minutter.", "error")
        return render_template_string(LOGIN_TEMPLATE), 429

    email = normalize_email(request.form.get("email", ""))
    password = request.form.get("password", "")

    user = get_user_by_email(email) if email else None

    # Konstant-tid: hash altid noget, så timing ikke afslører om brugeren findes
    if user is None:
        # Hash en dummy for at modvirke timing attacks
        check_password_hash(generate_password_hash("dummy"), "dummy_attempt")
        record_failed_login(ip)
        log.warning("Login fejlet (ukendt bruger) ip=%s email=%s", ip, email)
        flash("Forkert email eller kodeord.", "error")
        return render_template_string(LOGIN_TEMPLATE), 401

    user_id, user_email, password_hash = user
    if not check_password_hash(password_hash, password):
        record_failed_login(ip)
        log.warning("Login fejlet (forkert kode) ip=%s email=%s", ip, email)
        flash("Forkert email eller kodeord.", "error")
        return render_template_string(LOGIN_TEMPLATE), 401

    clear_failed_logins(ip)
    session.clear()
    session.permanent = True
    session["user_email"] = user_email
    session["user_id"] = user_id
    update_last_login(user_id)
    log.info("Login OK ip=%s email=%s", ip, user_email)
    return redirect(url_for("index"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- Bruger-administration (web) ----------

@app.route("/users", methods=["GET"])
@login_required_web
def users_page():
    return render_template_string(
        USERS_TEMPLATE,
        error=None,
        invite_result=None,
        users=list_users(),
        invites=list_pending_invites(),
        invite_hours=INVITE_HOURS,
        current_user=current_user_label(),
    )


@app.route("/users/invite", methods=["POST"])
@login_required_web
def users_invite():
    email = (request.form.get("email") or "").strip()
    try:
        token, expires_at = create_invite(email, current_user_label())
        invite_url = f"{get_base_url()}/invite#{token}"
        return render_template_string(
            USERS_TEMPLATE,
            error=None,
            invite_result={
                "email": normalize_email(email),
                "url": invite_url,
                "expires_at": iso_z(expires_at),
            },
            users=list_users(),
            invites=list_pending_invites(),
            invite_hours=INVITE_HOURS,
            current_user=current_user_label(),
        )
    except ValueError as exc:
        return render_template_string(
            USERS_TEMPLATE,
            error=str(exc),
            invite_result=None,
            users=list_users(),
            invites=list_pending_invites(),
            invite_hours=INVITE_HOURS,
            current_user=current_user_label(),
        ), 400


@app.route("/invite", methods=["GET"])
def invite_page():
    """Selve siden hvor brugeren vælger kodeord. Token kommer som fragment."""
    return render_template_string(INVITE_TEMPLATE)


@app.route("/api/invites/lookup", methods=["POST"])
def invite_lookup_api():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    email = lookup_invite_email(token)
    if not email:
        return jsonify({"error": "Invite-linket er ugyldigt, udløbet eller allerede brugt."}), 404
    return jsonify({"email": email}), 200


@app.route("/api/invites/consume", methods=["POST"])
def invite_consume_api():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    password = data.get("password", "")
    email, error, status_code = consume_invite(token, password)
    if error:
        return jsonify({"error": error}), status_code
    return jsonify({"email": email}), 200


@app.route("/", methods=["GET"])
@login_required_web
def index():
    return render_template_string(
        CREATE_TEMPLATE,
        error=None,
        result=None,
        default_message=DEFAULT_SMS_TEMPLATE,
        default_subject=DEFAULT_EMAIL_SUBJECT,
        current_user=current_user_label(),
    )


@app.route("/create", methods=["POST"])
@login_required_web
def create_form():
    secret_value = request.form.get("secret", "")
    ttl_minutes = request.form.get("ttl_minutes", "1440")
    passphrase = request.form.get("passphrase", "") or None
    recipient_msisdn = request.form.get("recipient_msisdn", "") or None
    recipient_name = request.form.get("recipient_name", "") or None
    sender_alias = request.form.get("sender_alias", "") or None
    recipient_email_raw = request.form.get("recipient_email", "").strip()
    email_subject_raw = request.form.get("email_subject", "").strip()
    message_text = None

    validated_email = None
    if recipient_email_raw:
        try:
            validated_email = validate_email_address(recipient_email_raw)
        except ValueError as exc:
            return render_template_string(
                CREATE_TEMPLATE,
                error=str(exc),
                result=None,
                default_message=DEFAULT_SMS_TEMPLATE,
                default_subject=DEFAULT_EMAIL_SUBJECT,
                current_user=current_user_label(),
            ), 400

    try:
        token, expires_at, sms_info = create_and_optionally_sms(
            secret_value=secret_value,
            ttl_minutes=ttl_minutes,
            passphrase=passphrase,
            recipient_msisdn=recipient_msisdn,
            recipient_name=recipient_name,
            sender_alias=sender_alias,
            message_text=message_text,
        )
        one_time_url = f"{get_base_url()}/s#{token}"
        sms_status = None
        if sms_info:
            mid = sms_info.get("message_id")
            sms_status = f"sendt (HTTP {sms_info.get('http_status')}{', id ' + str(mid) if mid else ''})"

        result = {
            "url": one_time_url,
            "expires_at": iso_z(expires_at),
            "sms_status": sms_status,
            "sms_was_sent": bool(sms_info),
        }
        if validated_email:
            result["email_to"] = validated_email
            result["email_subject"] = email_subject_raw or DEFAULT_EMAIL_SUBJECT
            result["email_recipient_name"] = (recipient_name or "").strip()

        return render_template_string(
            CREATE_TEMPLATE,
            error=None,
            result=result,
            default_message=DEFAULT_SMS_TEMPLATE,
            default_subject=DEFAULT_EMAIL_SUBJECT,
            current_user=current_user_label(),
        )
    except ValueError as exc:
        return render_template_string(
            CREATE_TEMPLATE,
            error=str(exc),
            result=None,
            default_message=DEFAULT_SMS_TEMPLATE,
            default_subject=DEFAULT_EMAIL_SUBJECT,
            current_user=current_user_label(),
        ), 400
    except RuntimeError as exc:
        return render_template_string(
            CREATE_TEMPLATE,
            error=f"SMS-afsendelse fejlede. Secret blev ikke oprettet. Detalje: {exc}",
            result=None,
            default_message=DEFAULT_SMS_TEMPLATE,
            default_subject=DEFAULT_EMAIL_SUBJECT,
            current_user=current_user_label(),
        ), 502


@app.route("/api/secrets", methods=["POST"])
@api_auth_required
def create_api():
    data = request.get_json(silent=True) or {}
    secret_value = data.get("secret", "")
    ttl_minutes = data.get("ttl_minutes", 1440)
    passphrase = data.get("passphrase") or None
    recipient_msisdn = data.get("recipient_msisdn") or None
    recipient_name = data.get("recipient_name") or None
    sender_alias = data.get("sender_alias") or None
    message_text = data.get("message_text") or None

    try:
        token, expires_at, sms_info = create_and_optionally_sms(
            secret_value=secret_value,
            ttl_minutes=ttl_minutes,
            passphrase=passphrase,
            recipient_msisdn=recipient_msisdn,
            recipient_name=recipient_name,
            sender_alias=sender_alias,
            message_text=message_text,
        )
        one_time_url = f"{get_base_url()}/s#{token}"
        response_body = {
            "one_time_url": one_time_url,
            "expires_at": iso_z(expires_at),
        }
        if sms_info:
            response_body["sms"] = {
                "delivered_to_gateway": True,
                "http_status": sms_info.get("http_status"),
                "message_id": sms_info.get("message_id"),
            }
        return jsonify(response_body), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except RuntimeError as exc:
        return jsonify({"error": f"SMS failed, secret not created: {exc}"}), 502


@app.route("/s", methods=["GET"])
def reveal_page():
    return render_template_string(REVEAL_TEMPLATE)


@app.route("/api/reveal", methods=["POST"])
def reveal_api():
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    passphrase = data.get("passphrase") or None

    secret_value, error, status_code = reveal_secret_record(token, passphrase)

    if error:
        return jsonify({"error": error}), status_code

    return jsonify({"secret": secret_value}), 200


# =====================================================================
# CLI
# =====================================================================

@app.cli.group("users")
def users_cli():
    """Bruger-administration."""


@users_cli.command("add")
@click.argument("email")
@click.option("--password", default=None, help="Kodeord. Spørges interaktivt hvis ikke angivet.")
def cli_add_user(email, password):
    """Tilføj ny bruger eller opdater eksisterende."""
    if password is None:
        password = getpass.getpass("Adgangskode: ")
        confirm = getpass.getpass("Bekræft: ")
        if password != confirm:
            click.echo("Kodeord matcher ikke.", err=True)
            sys.exit(1)
    try:
        upsert_user(email, password)
        click.echo(f"Bruger {email} oprettet/opdateret.")
    except ValueError as exc:
        click.echo(f"Fejl: {exc}", err=True)
        sys.exit(1)


@users_cli.command("set-password")
@click.argument("email")
def cli_set_password(email):
    """Skift kodeord for eksisterende bruger."""
    user = get_user_by_email(email)
    if not user:
        click.echo(f"Bruger {email} findes ikke. Brug 'users add' i stedet.", err=True)
        sys.exit(1)
    password = getpass.getpass("Nyt kodeord: ")
    confirm = getpass.getpass("Bekræft: ")
    if password != confirm:
        click.echo("Kodeord matcher ikke.", err=True)
        sys.exit(1)
    try:
        upsert_user(email, password)
        click.echo(f"Kodeord opdateret for {email}.")
    except ValueError as exc:
        click.echo(f"Fejl: {exc}", err=True)
        sys.exit(1)


@users_cli.command("list")
def cli_list_users():
    """List alle brugere."""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT email, created_at, last_login_at FROM users ORDER BY created_at DESC"
            )
            rows = cur.fetchall()
    if not rows:
        click.echo("Ingen brugere.")
        return
    for email, created, last_login in rows:
        last = iso_z(last_login) if last_login else "aldrig"
        click.echo(f"{email}  oprettet={iso_z(created)}  sidste_login={last}")


# =====================================================================
# Init
# =====================================================================

init_db()
bootstrap_user_if_configured()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
