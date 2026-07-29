"""
Azure Function (HTTP trigger) — the decrypt engine behind the Sentinel playbook.

This is the Sentinel analog of Splunk's `| cribldecrypt` search command. KQL /
Log Analytics cannot run inline Python (the python() plugin is ADX-only), so
instead a Sentinel **playbook (Logic App)** calls THIS function on demand for the
specific encrypted entities on an incident. The analyst clicks "Run playbook",
the function decrypts, and the cleartext is written back as an incident comment.

Key material lives in Azure Key Vault (one secret per Cribl keyId), NOT in code.
The function's managed identity is granted "Key Vault Secrets User".

Each Cribl token embeds its own keyId (`#<keyId>:<iv>:<ct>#`), so the function
derives the key per value from the token. A request-level "keyId" is only needed
as a fallback for bare ciphertexts that carry no keyId.

Request body:
    {
      "values": ["#smSLT3::q84MIayg9+65UD1MiPextGKhE8wXfSBT2jQkFJKs0PE#", "..."],
      "keyId": "smSLT3"   // optional fallback for bare ciphertexts
    }
Response:
    { "results": [{"input": "...", "plaintext": "...", "ok": true}, ...] }
"""

from __future__ import annotations

import json
import logging
import os
import re

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

from cribl_decrypt.core import CriblKey, decrypt_value, parse_token

app = func.FunctionApp()

_KV_URI = os.environ.get("KEY_VAULT_URI", "")
_secret_client: SecretClient | None = None
_key_cache: dict[str, CriblKey] = {}


def _get_secret_client() -> SecretClient:
    global _secret_client
    if _secret_client is None:
        _secret_client = SecretClient(vault_url=_KV_URI, credential=DefaultAzureCredential())
    return _secret_client


def _load_key(key_id: str) -> CriblKey:
    """Fetch a Cribl key from Key Vault. Secret name convention: cribl-key-<keyId>.

    keyId is the alphanumeric Cribl key id (e.g. "smSLT3"), not an integer.
    Secret value is JSON: {"keyHex": "...", "algorithm": "aes-256-cbc", "useIV": false}
    """
    if key_id in _key_cache:
        return _key_cache[key_id]
    secret = _get_secret_client().get_secret(f"cribl-key-{key_id}")
    meta = json.loads(secret.value)
    key = CriblKey.from_hex(
        key_id=key_id,
        key_hex=meta["keyHex"],
        algorithm=meta.get("algorithm", "aes-256-cbc"),
        use_iv=bool(meta.get("useIV", False)),
        key_class=int(meta.get("keyclass", 0)),
    )
    _key_cache[key_id] = key
    return key


def _collect_tokens(body: dict, req: func.HttpRequest) -> list[str]:
    """Accept tokens as a JSON array ('values'), a delimited string ('tokens',
    split on whitespace/commas), or a 'tokens' query param. The string form avoids
    the nested-quote escaping that breaks Azure Workbook Custom Endpoint bodies."""
    values = body.get("values")
    if isinstance(values, list):
        return values
    raw = body.get("tokens") or req.params.get("tokens") or ""
    if isinstance(raw, str) and raw.strip():
        return [t for t in re.split(r"[\s,]+", raw.strip()) if t]
    return []


@app.route(route="decrypt", auth_level=func.AuthLevel.FUNCTION)
def decrypt(req: func.HttpRequest) -> func.HttpResponse:
    try:
        body = req.get_json()
    except ValueError:
        body = {}  # tolerate empty/non-JSON bodies; tokens may be in the query string

    fallback_key_id = body.get("keyId")  # optional; only used for bare ciphertexts
    values = _collect_tokens(body, req)

    results = []
    for v in values:
        # The token embeds its keyId; fall back to the request-level keyId for
        # bare ciphertexts that don't carry one.
        key_id = parse_token(v).key_id or fallback_key_id
        if not key_id:
            results.append({"input": v, "error": "no_key_id", "ok": False})
            continue
        try:
            key = _load_key(str(key_id))
            results.append({"input": v, "plaintext": decrypt_value(v, key), "ok": True})
        except Exception as e:  # noqa: BLE001 — never leak crypto details to caller
            logging.warning("decrypt failed for one value: %s", e)
            results.append({"input": v, "error": "decrypt_failed", "ok": False})

    return func.HttpResponse(
        json.dumps({"results": results}), mimetype="application/json", status_code=200
    )


# A tiny self-contained decrypt page served by the Function itself. Because the
# page and the /api/decrypt call share the same origin, there is no CORS and no
# Workbook "trusted host" gate. Open /api/ui?code=<functionKey> and the page reuses
# that key for the decrypt call. Zero extra cost — same Function.
_UI_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>Cribl Decrypt</title>
<style>
 body{font-family:Segoe UI,system-ui,sans-serif;margin:2rem;max-width:900px;color:#222}
 h1{font-size:1.3rem} textarea{width:100%;height:7rem;font-family:monospace;font-size:.9rem}
 button{padding:.5rem 1rem;font-size:1rem;cursor:pointer;margin:.6rem 0}
 table{border-collapse:collapse;width:100%;margin-top:1rem} th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;font-size:.9rem}
 th{background:#f3f3f3} code{font-family:monospace} .ok{color:#137333} .bad{color:#b00020}
 .hint{color:#666;font-size:.85rem}
</style></head><body>
<h1>Cribl decrypt</h1>
<p class="hint">Paste Cribl <code>#keyId:iv:ct#</code> tokens (one per line, or space/comma-separated). Keys stay in Key Vault — this page only shows plaintext for an authorized call.</p>
<textarea id="toks">#TWPLRh::2B0RXsyqPFimLaEjyjZx8ga/XOpXn+HIDVnbKOigKwg#</textarea>
<button onclick="run()">Decrypt</button>
<div id="out"></div>
<script>
 const code = new URLSearchParams(location.search).get('code') || '';
 async function run(){
   const out = document.getElementById('out');
   out.textContent = 'Decrypting...';
   try{
     const r = await fetch('decrypt?code=' + encodeURIComponent(code), {
       method:'POST', headers:{'Content-Type':'application/json'},
       body: JSON.stringify({tokens: document.getElementById('toks').value})
     });
     if(!r.ok){ out.textContent = 'HTTP ' + r.status; return; }
     const data = await r.json();
     let h = '<table><tr><th>Token</th><th>Plaintext</th></tr>';
     for(const x of data.results){
       const cell = x.ok ? '<span class="ok">'+escapeHtml(x.plaintext)+'</span>'
                         : '<span class="bad">&lt;'+escapeHtml(x.error||'failed')+'&gt;</span>';
       h += '<tr><td><code>'+escapeHtml(x.input)+'</code></td><td>'+cell+'</td></tr>';
     }
     out.innerHTML = h + '</table>';
   }catch(e){ out.textContent = 'Error: ' + e; }
 }
 function escapeHtml(s){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
</script></body></html>"""


@app.route(route="ui", auth_level=func.AuthLevel.FUNCTION, methods=["GET"])
def ui(req: func.HttpRequest) -> func.HttpResponse:
    """Serve the same-origin decrypt page (no CORS / no trusted-host gate)."""
    return func.HttpResponse(_UI_HTML, mimetype="text/html", status_code=200)


# ---------------------------------------------------------------------------
# Recurring auto-decrypt: every minute, decrypt any new tokens in the encrypted
# table and write {Token, Plaintext} to a parallel table so analysts can JOIN and
# see plaintext inline in a KQL query. (KQL itself can't AES-decrypt.)
#
# Reads CriblEncrypted_CL via the workspace query API (function MSI needs
# "Log Analytics Reader"); writes CriblDecrypted_CL via the Logs ingestion path.
# Env: WORKSPACE_ID (customer GUID), WORKSPACE_KEY (shared key for the writer),
#      ENCRYPTED_TABLE (default CriblEncrypted_CL), DECRYPTED_LOG_TYPE (CriblDecrypted).
# ---------------------------------------------------------------------------
_WS_ID = os.environ.get("WORKSPACE_ID", "")
_WS_KEY = os.environ.get("WORKSPACE_KEY", "")
_ENC_TABLE = os.environ.get("ENCRYPTED_TABLE", "CriblEncrypted_CL")
_DEC_LOGTYPE = os.environ.get("DECRYPTED_LOG_TYPE", "CriblDecrypted")
_logs_client = None


def _get_logs_client():
    global _logs_client
    if _logs_client is None:
        from azure.monitor.query import LogsQueryClient
        _logs_client = LogsQueryClient(DefaultAzureCredential())
    return _logs_client


def _write_dataclient(rows: list[dict], log_type: str) -> None:
    """Append rows to <log_type>_CL via the HTTP Data Collector API."""
    import base64
    import datetime
    import hashlib
    import hmac
    import urllib.request

    body = json.dumps(rows)
    rfc = datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    clen = len(body.encode("utf-8"))
    to_sign = f"POST\n{clen}\napplication/json\nx-ms-date:{rfc}\n/api/logs"
    sig = base64.b64encode(
        hmac.new(base64.b64decode(_WS_KEY), to_sign.encode("utf-8"), hashlib.sha256).digest()
    ).decode()
    req = urllib.request.Request(
        f"https://{_WS_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
        data=body.encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"SharedKey {_WS_ID}:{sig}",
            "Log-Type": log_type,
            "x-ms-date": rfc,
        },
    )
    urllib.request.urlopen(req, timeout=30).read()


# Finds Cribl tokens EMBEDDED anywhere in a string cell (vs core's anchored
# parser): #<keyId>:<iv_b64>:<ct_b64># — both wrapping '#' required here so we
# don't false-positive on arbitrary colon-separated text.
_TOKEN_SCAN_RE = re.compile(r"#[A-Za-z0-9]+:[A-Za-z0-9+/=]*:[A-Za-z0-9+/=]+#")
_MAX_TOKENS_PER_QUERY = 5000


def _already_decrypted(tokens: list[str]) -> set[str]:
    """Return the subset of tokens already materialized in the decrypted table,
    so repeated workbook submissions don't write duplicate rows. Best-effort:
    if the table doesn't exist yet (first ever run), treat all as new."""
    found: set[str] = set()
    for i in range(0, len(tokens), 1000):  # chunk to keep the query body small
        chunk = tokens[i : i + 1000]
        kql = (
            f"{_DEC_LOGTYPE}_CL | where Token_s in (dynamic({json.dumps(chunk)})) "
            "| distinct Token_s"
        )
        try:
            resp = _get_logs_client().query_workspace(_WS_ID, kql, timespan=None)
            tables = getattr(resp, "tables", None) or getattr(resp, "partial_data", [])
            found.update(row[0] for table in tables for row in table.rows)
        except Exception as e:  # noqa: BLE001 — table may not exist yet
            logging.warning("dedup query failed (treating chunk as new): %s", e)
    return found


@app.route(route="query-decrypt", auth_level=func.AuthLevel.FUNCTION, methods=["POST"])
def query_decrypt(req: func.HttpRequest) -> func.HttpResponse:
    """On-demand decrypt driven by the decrypt-request-cribl workbook.

    Flow: workbook Submit → Logic App (cribl-decrypt-microsoft) → here.
    Body: {"query": "<KQL>"} — the analyst's query selecting encrypted rows.
    Runs the KQL against the workspace, scans every string cell of the results
    for embedded Cribl tokens, decrypts them, and appends only-new
    {Token, Plaintext} rows to CriblDecrypted_CL so the analyst can JOIN:

        CriblEncrypted_CL
        | join kind=leftouter (CriblDecrypted_CL | distinct Token_s, Plaintext_s)
          on $left.EncryptedField_s == $right.Token_s
    """
    try:
        body = req.get_json()
    except ValueError:
        body = {}
    query = (body.get("query") or "").strip()
    if not query:
        return func.HttpResponse(
            json.dumps({"error": "missing 'query' in request body"}),
            mimetype="application/json", status_code=400,
        )
    if not _WS_ID:
        return func.HttpResponse(
            json.dumps({"error": "WORKSPACE_ID not configured"}),
            mimetype="application/json", status_code=500,
        )

    # Run the analyst's KQL. timespan=None → the query's own time filters rule.
    try:
        resp = _get_logs_client().query_workspace(_WS_ID, query, timespan=None)
    except Exception as e:  # noqa: BLE001
        logging.warning("query_decrypt: KQL failed: %s", e)
        return func.HttpResponse(
            json.dumps({"error": "query_failed", "detail": str(e)[:500]}),
            mimetype="application/json", status_code=400,
        )
    tables = getattr(resp, "tables", None) or getattr(resp, "partial_data", [])

    # Scan every string cell for embedded tokens.
    tokens: list[str] = []
    seen: set[str] = set()
    row_count = 0
    for table in tables:
        for row in table.rows:
            row_count += 1
            for cell in row:
                if isinstance(cell, str) and "#" in cell:
                    for tok in _TOKEN_SCAN_RE.findall(cell):
                        if tok not in seen:
                            seen.add(tok)
                            tokens.append(tok)
    truncated = len(tokens) > _MAX_TOKENS_PER_QUERY
    tokens = tokens[:_MAX_TOKENS_PER_QUERY]

    already = _already_decrypted(tokens) if tokens else set()

    rows, failed = [], 0
    for tok in tokens:
        if tok in already:
            continue
        key_id = parse_token(tok).key_id
        if not key_id:
            failed += 1
            continue
        try:
            rows.append({"Token": tok, "Plaintext": decrypt_value(tok, _load_key(str(key_id)))})
        except Exception as e:  # noqa: BLE001
            logging.warning("query_decrypt: failed one token: %s", e)
            failed += 1

    written = 0
    if rows and _WS_ID and _WS_KEY:
        _write_dataclient(rows, _DEC_LOGTYPE)
        written = len(rows)

    summary = {
        "rows_scanned": row_count,
        "tokens_found": len(seen),
        "already_decrypted": len(already),
        "newly_decrypted": written,
        "failed": failed,
        "truncated": truncated,
        "decrypted_table": f"{_DEC_LOGTYPE}_CL",
        "note": (
            "Join in KQL: ... | join kind=leftouter "
            f"({_DEC_LOGTYPE}_CL | distinct Token_s, Plaintext_s) "
            "on $left.EncryptedField_s == $right.Token_s "
            "(allow a minute for ingestion of newly decrypted rows)"
        ),
    }
    return func.HttpResponse(
        json.dumps(summary), mimetype="application/json", status_code=200
    )


@app.timer_trigger(schedule="0 */5 * * * *", arg_name="timer", run_on_startup=True)
def decrypt_sweep(timer: func.TimerRequest) -> None:
    """Decrypt newly-arrived tokens and materialize them into CriblDecrypted_CL.

    DISABLED by default (set ENABLE_DECRYPT_SWEEP=true to re-enable): continuous
    sweeping double-ingests every encrypted row. Superseded by the on-demand
    /api/query-decrypt endpoint driven by the decrypt-request-cribl workbook.

    Processes a non-overlapping 5-minute band that's old enough (6-11 min) to be
    fully ingested — so each token is decrypted once, without a dedup query that
    ingestion lag would defeat. (Read side still de-dupes on Token_s.)
    """
    if os.environ.get("ENABLE_DECRYPT_SWEEP", "").lower() != "true":
        logging.info("decrypt_sweep: disabled (ENABLE_DECRYPT_SWEEP != true)")
        return
    if not (_WS_ID and _WS_KEY):
        logging.warning("decrypt_sweep: WORKSPACE_ID/WORKSPACE_KEY not set, skipping")
        return
    from datetime import timedelta

    query = f"""
        {_ENC_TABLE}
        | where TimeGenerated >= ago(11m) and TimeGenerated < ago(6m)
        | distinct EncryptedField_s
        | take 2000
    """
    try:
        resp = _get_logs_client().query_workspace(_WS_ID, query, timespan=timedelta(minutes=15))
    except Exception as e:  # noqa: BLE001
        logging.exception("decrypt_sweep query failed: %s", e)
        return
    tokens = [row[0] for table in resp.tables for row in table.rows if row and row[0]]
    if not tokens:
        logging.info("decrypt_sweep: no new tokens")
        return

    rows = []
    for tok in tokens:
        key_id = parse_token(tok).key_id
        if not key_id:
            continue
        try:
            rows.append({"Token": tok, "Plaintext": decrypt_value(tok, _load_key(str(key_id)))})
        except Exception as e:  # noqa: BLE001
            logging.warning("decrypt_sweep: failed one token: %s", e)
    if rows:
        _write_dataclient(rows, _DEC_LOGTYPE)
        logging.info("decrypt_sweep: wrote %d decrypted rows", len(rows))
