import os
import hashlib
import secrets as pysecrets
from datetime import datetime, timezone

import psycopg
from cryptography.fernet import Fernet
from flask import Flask, jsonify, render_template_string, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
MASTER_KEY = os.getenv("MASTER_KEY", "").strip()
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()
APP_BASE_URL = os.getenv("APP_BASE_URL", "").strip().rstrip("/")
MAX_SECRET_LENGTH = int(os.getenv("MAX_SECRET_LENGTH", "10000"))
MAX_TTL_MINUTES = int(os.getenv("MAX_TTL_MINUTES", "10080"))

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required")

if not MASTER_KEY:
    raise RuntimeError("MASTER_KEY is required")

if not ADMIN_TOKEN:
    raise RuntimeError("ADMIN_TOKEN is required")

fernet = Fernet(MASTER_KEY.encode())

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
    h1 { margin-top:0; }
    label { display:block; margin:16px 0 6px; font-weight:600; }
    input, textarea, button { width:100%; box-sizing:border-box; border-radius:8px; border:1px solid #475569; background:#0b1220; color:#e2e8f0; padding:12px; }
    textarea { min-height:180px; resize:vertical; }
    button { background:#2563eb; border:none; cursor:pointer; font-weight:700; margin-top:20px; }
    button:hover { background:#1d4ed8; }
    .msg { margin:16px 0; padding:12px 14px; border-radius:8px; }
    .ok { background:#052e16; border:1px solid #166534; }
    .err { background:#450a0a; border:1px solid #991b1b; }
    code, pre { background:#020617; padding:3px 6px; border-radius:6px; }
    pre { white-space:pre-wrap; word-break:break-word; padding:16px; }
    .small { color:#94a3b8; font-size:14px; }
    .row { display:grid; grid-template-columns: 1fr 1fr; gap:16px; }
    @media (max-width: 700px) { .row { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
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
        <pre id="linkBox">{{ result.url }}</pre>
        <button type="button" onclick="copyLink()">Kopiér link</button>
      </div>
    {% endif %}

    <form method="post" action="/create" autocomplete="off">
      <label>Admin token</label>
      <input type="password" name="admin_token" required>

      <label>Secret</label>
      <textarea name="secret" required></textarea>

      <div class="row">
        <div>
          <label>TTL i minutter</label>
          <input type="number" name="ttl_minutes" min="1" max="10080" value="1440" required>
        </div>
        <div>
          <label>Passphrase (valgfri)</label>
          <input type="text" name="passphrase" placeholder="Ekstra kode sendt i separat kanal">
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
  <title>Hent hemmelighed</title>
  <style>
    body { font-family: Arial, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:40px; }
    .card { max-width: 920px; margin: 0 auto; background:#111827; border:1px solid #334155; border-radius:12px; padding:24px; }
    h1 { margin-top:0; }
    label { display:block; margin:16px 0 6px; font-weight:600; }
    input, button { width:100%; box-sizing:border-box; border-radius:8px; border:1px solid #475569; background:#0b1220; color:#e2e8f0; padding:12px; }
    button { background:#2563eb; border:none; cursor:pointer; font-weight:700; margin-top:20px; }
    button:hover { background:#1d4ed8; }
    .msg { margin:16px 0; padding:12px 14px; border-radius:8px; }
    .ok { background:#052e16; border:1px solid #166534; }
    .err { background:#450a0a; border:1px solid #991b1b; }
    .small { color:#94a3b8; font-size:14px; }
    pre { white-space:pre-wrap; word-break:break-word; background:#020617; padding:16px; border-radius:8px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Hent hemmelighed</h1>
    <p class="small">
      Hemmeligheden hentes først når du klikker på knappen nedenfor.
      Linket kan kun bruges én gang.
    </p>

    <div id="errorBox" class="msg err" hidden></div>

    <form id="revealForm" autocomplete="off">
      <label>Passphrase (kun hvis afsender har givet dig en separat kode)</label>
      <input type="text" id="passphrase" placeholder="Valgfri passphrase">
      <button type="submit">Vis hemmelighed én gang</button>
    </form>

    <div id="resultBox" class="msg ok" hidden>
      <div><strong>Hemmelighed</strong></div>
      <pre id="secretValue"></pre>
      <div class="small">Denne værdi er nu forbrugt og kan ikke hentes igen med samme link.</div>
    </div>
  </div>

  <script>
    const errorBox = document.getElementById("errorBox");
    const revealForm = document.getElementById("revealForm");
    const resultBox = document.getElementById("resultBox");
    const secretValue = document.getElementById("secretValue");

    function showError(message) {
      errorBox.hidden = false;
      errorBox.innerText = message;
    }

    const token = window.location.hash ? window.location.hash.substring(1) : "";

    if (!token) {
      revealForm.hidden = true;
      showError("Mangler token i linket. Kontroller at hele URL'en er kopieret.");
    }

    revealForm.addEventListener("submit", async (e) => {
      e.preventDefault();

      const passphrase = document.getElementById("passphrase").value;

      try {
        const response = await fetch("/api/reveal", {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            token: token,
            passphrase: passphrase
          })
        });

        const data = await response.json();

        if (!response.ok) {
          showError(data.error || "Kunne ikke hente hemmeligheden");
          return;
        }

        revealForm.hidden = true;
        resultBox.hidden = false;
        secretValue.textContent = data.secret;
      } catch (err) {
        showError("Netværksfejl ved hentning af hemmeligheden");
      }
    });
  </script>
</body>
</html>
"""


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


def extract_admin_token():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()

    header_token = request.headers.get("X-Admin-Token")
    if header_token:
        return header_token.strip()

    form_token = request.form.get("admin_token")
    if form_token:
        return form_token.strip()

    json_body = request.get_json(silent=True) or {}
    json_token = json_body.get("admin_token")
    if json_token:
        return str(json_token).strip()

    return ""


def is_admin_authenticated() -> bool:
    provided = extract_admin_token()
    return bool(provided) and pysecrets.compare_digest(provided, ADMIN_TOKEN)


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
                """,
                (token_hash, encrypted_secret, passphrase_hash, expires_at, created_at),
            )

    return token, expires_at


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


@app.route("/healthz", methods=["GET"])
def healthz():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
    return jsonify({"status": "ok"}), 200


@app.route("/", methods=["GET"])
def index():
    return render_template_string(CREATE_TEMPLATE, error=None, result=None)


@app.route("/create", methods=["POST"])
def create_form():
    if not is_admin_authenticated():
        return render_template_string(
            CREATE_TEMPLATE,
            error="Ugyldig admin token.",
            result=None,
        ), 401

    secret_value = request.form.get("secret", "")
    ttl_minutes = request.form.get("ttl_minutes", "1440")
    passphrase = request.form.get("passphrase", "") or None

    try:
        token, expires_at = create_secret_record(secret_value, ttl_minutes, passphrase)
        one_time_url = f"{get_base_url()}/s#{token}"
        return render_template_string(
            CREATE_TEMPLATE,
            error=None,
            result={
                "url": one_time_url,
                "expires_at": iso_z(expires_at),
            },
        )
    except ValueError as exc:
        return render_template_string(
            CREATE_TEMPLATE,
            error=str(exc),
            result=None,
        ), 400


@app.route("/api/secrets", methods=["POST"])
def create_api():
    if not is_admin_authenticated():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    secret_value = data.get("secret", "")
    ttl_minutes = data.get("ttl_minutes", 1440)
    passphrase = data.get("passphrase") or None

    try:
        token, expires_at = create_secret_record(secret_value, ttl_minutes, passphrase)
        one_time_url = f"{get_base_url()}/s#{token}"
        return jsonify(
            {
                "one_time_url": one_time_url,
                "expires_at": iso_z(expires_at),
            }
        ), 201
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


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


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
