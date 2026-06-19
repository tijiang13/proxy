#!/usr/bin/env python3
"""
maomao2surge — log into a maomao (V2Board/Xboard) account, fetch your
subscription, and emit either a sanitized full Surge profile or a proxy list.

Usage:
    python3 maomao2surge.py --email you@mail.com --password 'pw'
    python3 maomao2surge.py --email you@mail.com --password 'pw' --proxy-only
    python3 maomao2surge.py --email you@mail.com --password 'pw'         --enable-autoupgrade -o surge_full.conf

Defaults:
    - Full sanitized Surge profile is written to surge_full.conf
    - Automatic managed updates are disabled by default
    - Proxy-list-only output is enabled only with --proxy-only

Only the Python standard library is used (no pip needed).
"""
import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (Linux; Android 13) maomao/2.3.1"
BOOTSTRAP_URL = "https://maomaoyunapp.oss-cn-beijing.aliyuncs.com/android.txt"
PROVIDER_DOH = "https://dns.maomaovpn.com/dns-query/b21fb37a924bbd327154e3b06635fbde"
FALLBACK_DOH = "https://doh.pub/dns-query"
HOST_RULE = f"*.maomao678.com = server:{PROVIDER_DOH}"
GENERAL_OVERRIDES = {
    "encrypted-dns-server": f"{PROVIDER_DOH}, {FALLBACK_DOH}",
    "dns-server": "system, 223.5.5.5, 119.29.29.29, 114.114.114.114",
    "ipv6": "false",
}
REMOVE_GENERAL_KEYS = {"doh-server"}
INFO_MARK = "："
INFO_PREFIXES = ("剩余流量", "距离下次重置剩余", "套餐到期", "官网")
SECTION_RE = re.compile(r"^\[[^\]]+\]\s*$")


def http(method, url, data=None, headers=None, timeout=20):
    request_headers = {"User-Agent": UA, "Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def api(base, path, token=None, data=None):
    url = base.rstrip("/") + path
    headers = {"Authorization": token} if token else None
    status, raw = http("POST" if data else "GET", url, data=data, headers=headers)
    try:
        return status, json.loads(raw)
    except Exception:
        return status, raw


def resolve_base():
    status, raw = http("GET", BOOTSTRAP_URL)
    if status != 200:
        sys.exit(f"bootstrap fetch failed (HTTP {status})")
    cfg = json.loads(raw)
    domains = cfg.get("api") or cfg.get("url") or []
    print(f"[*] bootstrap domains: {domains}", file=sys.stderr)
    for domain in domains:
        domain = domain.rstrip("/")
        try:
            status, payload = api(domain, "/api/v1/guest/comm/config")
            if status == 200 and isinstance(payload, dict) and payload.get("status") == "success":
                print(f"[*] using base: {domain}", file=sys.stderr)
                return domain
        except Exception:
            pass
    sys.exit("no live API domain found from bootstrap")


def login(base, email, password):
    status, payload = api(
        base,
        "/api/v1/passport/auth/login",
        data={"email": email, "password": password},
    )
    if status != 200 or not isinstance(payload, dict):
        sys.exit(f"login failed (HTTP {status}): {payload!r}")
    data = payload.get("data", {})
    token = data.get("auth_data") or data.get("token") or data.get("authToken")
    if not token:
        sys.exit(f"login ok but no token in response: {payload}")
    return token


def get_subscribe_url(base, token):
    status, payload = api(base, "/api/v1/user/getSubscribe", token=token)
    if status == 200 and isinstance(payload, dict):
        subscribe_url = payload.get("data", {}).get("subscribe_url")
        if subscribe_url:
            return subscribe_url
    sys.exit(f"could not get subscribe_url (HTTP {status}): {payload!r}")


def fetch_surge_text(subscribe_url, retries=4):
    sep = "&" if "?" in subscribe_url else "?"
    url = subscribe_url + sep + "flag=surge"
    last = None
    for _ in range(retries):
        try:
            status, raw = http("GET", url, headers={"User-Agent": "Surge/2700"})
            if status == 200 and raw:
                text = raw.decode("utf-8", "replace")
                if "[Proxy]" in text:
                    return text
            last = f"HTTP {status}"
        except Exception as exc:
            last = str(exc)
    sys.exit(f"[!] could not fetch surge subscription ({last})")


def extract_proxy_lines(text, keep_info=False):
    lines = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[Proxy]"):
            in_block = True
            continue
        if in_block and stripped.startswith("["):
            break
        if not in_block or not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name = stripped.split("=", 1)[0]
        if not keep_info and (
            INFO_MARK in name or name.startswith(INFO_PREFIXES)
        ):
            continue
        lines.append(stripped)
    return lines


def split_sections(lines):
    sections = []
    current_name = None
    current_lines = []
    preamble = []
    for line in lines:
        if SECTION_RE.match(line):
            if current_name is None:
                if preamble:
                    sections.append((None, preamble))
                preamble = []
            else:
                sections.append((current_name, current_lines))
            current_name = line.strip()[1:-1]
            current_lines = [line]
            continue
        if current_name is None:
            preamble.append(line)
        else:
            current_lines.append(line)
    if current_name is None:
        if preamble:
            sections.append((None, preamble))
    else:
        sections.append((current_name, current_lines))
    return sections


def normalize_general(lines):
    out = []
    seen = set()
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            out.append(line)
            continue
        if "=" not in line:
            out.append(line)
            continue
        key, _value = [part.strip() for part in line.split("=", 1)]
        if key in REMOVE_GENERAL_KEYS:
            continue
        if key in GENERAL_OVERRIDES:
            if key not in seen:
                out.append(f"{key} = {GENERAL_OVERRIDES[key]}\n")
                seen.add(key)
            continue
        out.append(line)
    insert_at = 1 if out and out[0].strip() == "[General]" else 0
    for key, value in GENERAL_OVERRIDES.items():
        if key not in seen:
            out.insert(insert_at, f"{key} = {value}\n")
            insert_at += 1
    return out


def normalize_proxy(lines):
    out = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("["):
            out.append(line)
            continue
        if "=" not in line:
            out.append(line)
            continue
        name = stripped.split("=", 1)[0]
        if name.startswith(INFO_PREFIXES) or INFO_MARK in name:
            continue
        out.append(line)
    return out


def ensure_host_section(sections):
    host_lines = ["[Host]\n", HOST_RULE + "\n"]
    out = []
    inserted = False
    for name, lines in sections:
        if name == "Host":
            out.append((name, host_lines))
            inserted = True
            continue
        out.append((name, lines))
        if name == "Panel" and not inserted:
            out.append(("Host", host_lines))
            inserted = True
    if not inserted:
        out.append(("Host", host_lines))
    return out


def sanitize_full_config(text, enable_autoupgrade=False):
    lines = text.splitlines(keepends=True)
    if lines and lines[0].startswith("#!MANAGED-CONFIG ") and not enable_autoupgrade:
        source = lines[0].strip()[len("#!MANAGED-CONFIG "):]
        lines[0] = f"# Managed source: {source}\n"
    sections = split_sections(lines)
    normalized = []
    for name, section_lines in sections:
        if name == "General":
            section_lines = normalize_general(section_lines)
        elif name == "Proxy":
            section_lines = normalize_proxy(section_lines)
        normalized.append((name, section_lines))
    normalized = ensure_host_section(normalized)

    rendered = []
    for _name, section_lines in normalized:
        rendered.extend(section_lines)
    return "".join(rendered)


def write_output(path, text):
    if path == "-":
        sys.stdout.write(text)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"[*] wrote {path}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument(
        "--base",
        default=None,
        help=(
            "panel API base URL. If omitted, it is auto-resolved from the app's "
            "OSS bootstrap (survives domain rotation)."
        ),
    )
    ap.add_argument(
        "--proxy-only",
        action="store_true",
        help="emit only the [Proxy] rows instead of a full Surge profile",
    )
    ap.add_argument(
        "--enable-autoupgrade",
        action="store_true",
        help="keep the provider's #!MANAGED-CONFIG header in full-profile mode",
    )
    ap.add_argument(
        "-o",
        "--out",
        default=None,
        help="output file. Defaults to surge_full.conf or surge_proxies.conf with --proxy-only",
    )
    ap.add_argument(
        "--keep-info",
        action="store_true",
        help="keep the notice rows in --proxy-only mode",
    )
    args = ap.parse_args()

    base = args.base or resolve_base()
    print(f"[*] logging in to {base} ...", file=sys.stderr)
    token = login(base, args.email, args.password)
    subscribe_url = get_subscribe_url(base, token)
    print(f"[*] subscribe_url: {subscribe_url}", file=sys.stderr)

    text = fetch_surge_text(subscribe_url)
    if args.proxy_only:
        lines = extract_proxy_lines(text, keep_info=args.keep_info)
        if not lines:
            sys.exit("[!] no proxies found in surge subscription")
        print(f"[*] {len(lines)} nodes found", file=sys.stderr)
        output = "\n".join(lines) + "\n"
        out_path = args.out or "surge_proxies.conf"
    else:
        output = sanitize_full_config(text, enable_autoupgrade=args.enable_autoupgrade)
        out_path = args.out or "surge_full.conf"

    write_output(out_path, output)


if __name__ == "__main__":
    main()
