#!/usr/bin/env python3
"""Small Flask control UI for a local sing-box Clash API.

Recommended deployment:
  sing-box Clash API: 127.0.0.1:9090
  this Flask app:     0.0.0.0:9091

Environment:
  SING_BOX_CONTROLLER=http://127.0.0.1:9090
  SING_BOX_SECRET=change-this
  WEB_SECRET=optional-login-password
  FLASK_SECRET_KEY=optional-session-key
"""

from __future__ import annotations

import hmac
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from html import escape

from flask import Flask, redirect, render_template_string, request, session, url_for


CONTROLLER = os.environ.get("SING_BOX_CONTROLLER", "http://127.0.0.1:9090")
SING_BOX_SECRET = os.environ.get("SING_BOX_SECRET", "")
WEB_SECRET = os.environ.get("WEB_SECRET", "")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)


def api_request(method: str, path: str, body=None):
    url = CONTROLLER.rstrip("/") + path
    data = None
    headers = {}
    if SING_BOX_SECRET:
        headers["Authorization"] = f"Bearer {SING_BOX_SECRET}"
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            raw = response.read()
            if not raw:
                return None
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"{method} {url} failed: HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"{method} {url} failed: {exc.reason}") from exc


def require_login():
    if not WEB_SECRET:
        return None
    if session.get("ok") is True:
        return None
    return redirect(url_for("login", next=request.path))


@app.before_request
def auth_gate():
    if request.endpoint in {"login", "static"}:
        return None
    return require_login()


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        supplied = request.form.get("secret", "")
        if hmac.compare_digest(supplied, WEB_SECRET):
            session["ok"] = True
            return redirect(request.args.get("next") or url_for("index"))
        error = "Bad secret"
    return render_template_string(LOGIN_HTML, error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET"])
def index():
    error = ""
    configs = {}
    proxy = {}
    proxies = {}
    try:
        configs = api_request("GET", "/configs") or {}
        proxy = api_request("GET", "/proxies/Proxy") or {}
        all_proxies = api_request("GET", "/proxies") or {}
        proxies = all_proxies.get("proxies", {}) if isinstance(all_proxies, dict) else {}
    except Exception as exc:  # show UI with visible error
        error = str(exc)

    mode = configs.get("mode", "")
    mode_list = configs.get("mode-list", []) or ["Rule", "Global", "Direct"]
    now = proxy.get("now", "")
    selectable = proxy.get("all", [])
    if not selectable and "Proxy" in proxies:
        selectable = proxies.get("Proxy", {}).get("all", [])

    return render_template_string(
        INDEX_HTML,
        error=error,
        mode=mode,
        mode_list=mode_list,
        now=now,
        selectable=selectable,
        controller=CONTROLLER,
        auth_enabled=bool(WEB_SECRET),
    )


@app.route("/mode", methods=["POST"])
def set_mode():
    mode = request.form.get("mode", "")
    if mode:
        api_request("PATCH", "/configs", {"mode": mode})
    return redirect(url_for("index"))


@app.route("/proxy", methods=["POST"])
def set_proxy():
    node = request.form.get("node", "")
    if node:
        selector = urllib.parse.quote("Proxy", safe="")
        api_request("PUT", f"/proxies/{selector}", {"name": node})
    return redirect(url_for("index"))


LOGIN_HTML = """
<!doctype html>
<title>Pi Proxy Login</title>
<style>
body { font-family: system-ui, sans-serif; margin: 2rem; max-width: 36rem; }
input, button { font-size: 1rem; padding: .5rem; }
.error { color: #b00020; }
</style>
<h1>Pi Proxy</h1>
{% if error %}<p class="error">{{ error }}</p>{% endif %}
<form method="post">
  <input type="password" name="secret" placeholder="Web secret" autofocus>
  <button type="submit">Login</button>
</form>
"""


INDEX_HTML = """
<!doctype html>
<title>Pi Proxy</title>
<style>
body { font-family: system-ui, sans-serif; margin: 2rem; max-width: 70rem; }
button, select { font-size: 1rem; padding: .45rem .7rem; margin: .2rem; }
.card { border: 1px solid #ddd; border-radius: 10px; padding: 1rem; margin: 1rem 0; }
.error { color: #b00020; white-space: pre-wrap; }
.node { display: block; width: 100%; text-align: left; margin: .15rem 0; }
.current { font-weight: 700; }
small { color: #666; }
</style>
<h1>Pi Proxy</h1>
<small>Controller: {{ controller }}</small>
{% if auth_enabled %}
<form method="post" action="/logout" style="float:right"><button>Logout</button></form>
{% endif %}
{% if error %}<div class="card error">{{ error }}</div>{% endif %}

<div class="card">
  <h2>Mode</h2>
  <p>Current: <span class="current">{{ mode }}</span></p>
  <form method="post" action="/mode">
    {% for m in mode_list %}
      <button name="mode" value="{{ m }}">{{ m }}</button>
    {% endfor %}
  </form>
</div>

<div class="card">
  <h2>Proxy Selector</h2>
  <p>Current: <span class="current">{{ now }}</span></p>
  <form method="post" action="/proxy">
    {% for node in selectable %}
      <button class="node" name="node" value="{{ node }}">{{ node }}</button>
    {% endfor %}
  </form>
</div>
"""


if __name__ == "__main__":
    host = os.environ.get("WEB_HOST", "0.0.0.0")
    port = int(os.environ.get("WEB_PORT", "9091"))
    app.run(host=host, port=port)
