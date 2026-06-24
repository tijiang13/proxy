#!/usr/bin/env python3
"""
Convert Maomao/Surge AnyTLS profiles into a Raspberry Pi friendly sing-box
client config, and optionally control/run sing-box from the CLI.

The important bit for large provider profiles is preserving Surge policy groups
and route rules instead of flattening all nodes into one constantly-tested group.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path


INFO_MARK = "："
INFO_PREFIXES = ("剩余流量", "距离下次重置剩余", "套餐到期", "官网")
PROVIDER_DOH_HOST = "dns.maomaovpn.com"
PROVIDER_DOH_PATH = "/dns-query/b21fb37a924bbd327154e3b06635fbde"
DEFAULT_TEST_URL = "http://www.gstatic.com/generate_204"
DEFAULT_CONTROLLER = "http://127.0.0.1:9090"
DIRECT_NAMES = {"DIRECT", "direct"}
REJECT_NAMES = {"REJECT", "REJECT-DROP", "REJECT-TINYGIF"}
UNSUPPORTED_RULE_TYPES = {"USER-AGENT", "URL-REGEX", "PROCESS-NAME", "SCRIPT"}


@dataclass
class SurgeGroup:
    name: str
    kind: str
    members: list[str]
    params: dict[str, str]


@dataclass
class ParsedProfile:
    proxies: list[dict]
    proxy_tags: list[str]
    groups: list[SurgeGroup]
    general_resolve_rules: list[dict]
    general_direct_rules: list[dict]
    dns_rules: list[dict]
    route_rules: list[dict]
    final_outbound: str
    provider_doh_host: str
    provider_doh_path: str
    bootstrap_dns: str | None
    proxy_test_url: str | None
    ipv4_only: bool
    warnings: list[str]


def is_info_name(name: str) -> bool:
    return INFO_MARK in name or name.startswith(INFO_PREFIXES)


def normalize_policy_name(name: str) -> str:
    name = name.strip()
    if name in DIRECT_NAMES:
        return "direct"
    if name in REJECT_NAMES:
        return "block"
    return name


def unique_tag(name: str, used: set[str]) -> str:
    tag = name.strip()
    if tag not in used:
        used.add(tag)
        return tag
    index = 2
    while f"{tag} #{index}" in used:
        index += 1
    tag = f"{tag} #{index}"
    used.add(tag)
    return tag


def read_sections(path: Path) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            sections.setdefault(current, [])
            continue
        if current:
            sections.setdefault(current, []).append(line)
    return sections


def read_proxy_lines(path: Path) -> list[str]:
    sections = read_sections(path)
    if "Proxy" in sections:
        return [line for line in sections["Proxy"] if "=" in line]
    # Proxy-only files do not have sections.
    result = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            result.append(line)
    return result


def csv_parts(spec: str) -> list[str]:
    return [part.strip() for part in next(csv.reader([spec], skipinitialspace=True))]


def parse_surge_anytls(path: Path) -> list[dict]:
    proxies = []
    used_tags: set[str] = set()
    for line in read_proxy_lines(path):
        name, spec = line.split("=", 1)
        name = name.strip()
        if is_info_name(name):
            continue

        parts = csv_parts(spec)
        if len(parts) < 4 or parts[0].lower() != "anytls":
            continue

        params = {}
        for item in parts[3:]:
            if "=" in item:
                key, value = item.split("=", 1)
                params[key.strip()] = value.strip()

        password = params.get("password")
        if not password:
            raise ValueError(f"AnyTLS proxy {name!r} is missing password=...")

        skip_cert_verify = params.get("skip-cert-verify", "false").lower() == "true"
        tag = unique_tag(name, used_tags)
        proxies.append(
            {
                "type": "anytls",
                "tag": tag,
                "server": parts[1].strip(),
                "server_port": int(parts[2].strip()),
                "password": password,
                "idle_session_check_interval": "30s",
                "idle_session_timeout": "30s",
                "min_idle_session": 0,
                "domain_resolver": "provider-doh",
                "tls": {
                    "enabled": True,
                    "server_name": params.get("sni", ""),
                    "insecure": skip_cert_verify,
                },
            }
        )

    if not proxies:
        raise ValueError(f"no AnyTLS proxy lines found in {path}")
    return proxies


def parse_proxy_groups(path: Path, valid_tags: set[str]) -> list[SurgeGroup]:
    groups: list[SurgeGroup] = []
    for line in read_sections(path).get("Proxy Group", []):
        if "=" not in line:
            continue
        name, spec = line.split("=", 1)
        name = name.strip()
        parts = csv_parts(spec)
        if not parts:
            continue
        kind = parts[0].lower().replace("-", "_")
        members: list[str] = []
        params: dict[str, str] = {}
        for item in parts[1:]:
            if "=" in item:
                k, v = item.split("=", 1)
                params[k.strip().lower()] = v.strip()
                continue
            member = normalize_policy_name(item)
            if is_info_name(member):
                continue
            # Keep group references even if not in valid_tags yet; filter later once all
            # group names are known. Keep direct/block pseudo-outbounds.
            members.append(member)
        groups.append(SurgeGroup(name=name, kind=kind, members=members, params=params))
    return groups


def general_value_list(sections: dict[str, list[str]], key: str) -> list[str]:
    prefix = key.lower()
    values: list[str] = []
    for line in sections.get("General", []):
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip().lower() != prefix:
            continue
        values.extend(item.strip() for item in value.split(",") if item.strip())
    return values


def general_first_value(sections: dict[str, list[str]], key: str) -> str | None:
    values = general_value_list(sections, key)
    return values[0] if values else None


def general_bool(sections: dict[str, list[str]], key: str, default: bool) -> bool:
    value = general_first_value(sections, key)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_https_dns_server(value: str) -> tuple[str, str] | None:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    return parsed.hostname, parsed.path or "/dns-query"


def first_plain_dns_server(values: list[str]) -> str | None:
    for value in values:
        lower = value.lower()
        if lower == "system" or lower.startswith(("https://", "tls://")):
            continue
        return value.split(":", 1)[0].strip()
    return None


def direct_rule_from_general_item(item: str) -> dict | None:
    value = item.strip()
    if not value:
        return None
    if value.lower().startswith("server:"):
        return None
    if "/" in value and not any(ch in value for ch in "*?"):
        return {"action": "route", "outbound": "direct", "ip_cidr": [value]}
    if value in {"localhost", "localhost.localdomain"}:
        return {"action": "route", "outbound": "direct", "domain": [value]}
    if value.startswith("*."):
        suffix = "." + value[2:]
        suffixes = [suffix]
        if suffix == ".local":
            suffixes.append(".local.")
        return {"action": "route", "outbound": "direct", "domain_suffix": suffixes}
    if "*" in value or "?" in value:
        regex = "^" + value.replace(".", r"\.").replace("*", ".*").replace("?", ".") + "$"
        return {"action": "route", "outbound": "direct", "domain_regex": [regex]}
    return {"action": "route", "outbound": "direct", "domain": [value]}


def parse_general_direct_rules(path: Path, warnings: list[str]) -> list[dict]:
    sections = read_sections(path)
    rules: list[dict] = []
    seen: set[str] = set()
    general_items = general_value_list(sections, "skip-proxy") + general_value_list(sections, "tun-excluded-routes")
    if general_bool(sections, "exclude-simple-hostnames", False):
        general_items.append("__SIMPLE_HOSTNAMES__")
    for item in general_items:
        if item == "__SIMPLE_HOSTNAMES__":
            rule = {"action": "route", "outbound": "direct", "domain_regex": [r"^[^.]+$"]}
        else:
            rule = direct_rule_from_general_item(item)
        if not rule:
            continue
        key = json.dumps(rule, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        rules.append(rule)
    if rules:
        warnings.append(f"added {len(rules)} direct route rules from [General] skip-proxy/tun-excluded-routes")
    return rules


def parse_general_dns_rules(path: Path) -> list[dict]:
    sections = read_sections(path)
    rules: list[dict] = []
    skip_items = set(general_value_list(sections, "skip-proxy"))
    if "localhost" in skip_items or "localhost.localdomain" in skip_items:
        rules.append({"action": "route", "server": "local-dns", "domain": ["localhost", "localhost.localdomain"]})
    if "*.local" in skip_items:
        rules.append({"action": "route", "server": "local-dns", "domain_suffix": [".local", ".local."]})
    if general_bool(sections, "exclude-simple-hostnames", False):
        rules.append({"action": "route", "server": "local-dns", "domain_regex": [r"^[^.]+\.?$"]})
    return rules


def parse_general_resolve_rules(path: Path) -> list[dict]:
    sections = read_sections(path)
    rules: list[dict] = []
    skip_items = set(general_value_list(sections, "skip-proxy"))
    if "localhost" in skip_items or "localhost.localdomain" in skip_items:
        rules.append({"action": "resolve", "server": "local-dns", "domain": ["localhost", "localhost.localdomain"]})
    if "*.local" in skip_items:
        rules.append({"action": "resolve", "server": "local-dns", "domain_suffix": [".local", ".local."]})
    if general_bool(sections, "exclude-simple-hostnames", False):
        rules.append({"action": "resolve", "server": "local-dns", "domain_regex": [r"^[^.]+\.?$"]})
    return rules


def surge_interval_to_duration(value: str | None, default: str) -> str:
    if not value:
        return default
    value = value.strip()
    if not value:
        return default
    if value[-1].isalpha():
        return value
    # Surge interval is seconds in this profile; sing-box wants a duration string.
    return f"{value}s"


def urltest_outbound(tag: str, outbounds: list[str], url: str, interval: str) -> dict:
    # sing-box requires interval <= idle_timeout. The provider profile uses a
    # long 43200s url-test interval, while sing-box defaults idle_timeout to
    # 30m, so set it explicitly.
    return {
        "type": "urltest",
        "tag": tag,
        "outbounds": outbounds,
        "url": url,
        "interval": interval,
        "idle_timeout": interval,
        "interrupt_exist_connections": True,
    }


def build_group_outbounds(groups: list[SurgeGroup], proxy_tags: list[str], warnings: list[str]) -> list[dict]:
    outbounds: list[dict] = []
    proxy_set = set(proxy_tags)
    group_names = {g.name for g in groups}
    valid = proxy_set | group_names | {"direct", "block"}

    for group in groups:
        members = [m for m in group.members if m in valid and m != group.name]
        if not members:
            members = proxy_tags[:]
            warnings.append(f"group {group.name!r} had no valid members; using all proxy nodes")

        if group.kind in {"select", "selector"}:
            outbounds.append(
                {
                    "type": "selector",
                    "tag": group.name,
                    "outbounds": members,
                    "default": members[0],
                    "interrupt_exist_connections": True,
                }
            )
        elif group.kind in {"url_test", "urltest"}:
            interval = surge_interval_to_duration(group.params.get("interval"), "12h")
            outbounds.append(
                urltest_outbound(
                    group.name,
                    [m for m in members if m in proxy_set],
                    group.params.get("url", DEFAULT_TEST_URL),
                    interval,
                )
            )
        elif group.kind == "fallback":
            # sing-box has no Surge-style fallback outbound group. For this use case,
            # urltest is the closest controllable group type and avoids custom health logic.
            warnings.append("mapped Surge fallback group 'fallback' to sing-box urltest; sing-box has no native fallback group")
            interval = surge_interval_to_duration(group.params.get("interval"), "12h")
            outbounds.append(
                urltest_outbound(
                    group.name,
                    [m for m in members if m in proxy_set],
                    group.params.get("url", DEFAULT_TEST_URL),
                    interval,
                )
            )
        else:
            warnings.append(f"unsupported Surge group type {group.kind!r} for {group.name!r}; using selector")
            outbounds.append(
                {
                    "type": "selector",
                    "tag": group.name,
                    "outbounds": members,
                    "default": members[0],
                    "interrupt_exist_connections": True,
                }
            )
    return outbounds


def convert_rule(line: str, warnings: list[str], geoip_rule_sets: dict[str, str]) -> tuple[dict | None, str | None]:
    parts = csv_parts(line)
    if not parts:
        return None, None
    rule_type = parts[0].upper()

    if rule_type == "FINAL":
        if len(parts) >= 2:
            return None, normalize_policy_name(parts[1])
        return None, None

    if rule_type in UNSUPPORTED_RULE_TYPES:
        warnings.append(f"skipped unsupported Surge rule: {line}")
        return None, None

    if len(parts) < 3:
        warnings.append(f"skipped malformed Surge rule: {line}")
        return None, None

    value = parts[1].strip()
    outbound = normalize_policy_name(parts[2])
    rule: dict[str, object] = {"action": "route", "outbound": outbound}

    if rule_type == "DOMAIN":
        rule["domain"] = [value]
    elif rule_type == "DOMAIN-SUFFIX":
        rule["domain_suffix"] = [value if value.startswith(".") else f".{value}"]
    elif rule_type == "DOMAIN-KEYWORD":
        rule["domain_keyword"] = [value]
    elif rule_type in {"IP-CIDR", "IP-CIDR6"}:
        rule["ip_cidr"] = [value]
    elif rule_type == "GEOIP":
        rule_set = geoip_rule_sets.get(value.upper())
        if not rule_set:
            warnings.append(f"skipped GEOIP rule without configured sing-box rule-set: {line}")
            return None, None
        rule["rule_set"] = [rule_set]
    elif rule_type == "RULE-SET" and value.upper() == "LAN":
        rule["ip_is_private"] = True
    else:
        warnings.append(f"skipped unsupported Surge rule: {line}")
        return None, None

    return rule, None


def parse_route_rules(path: Path, warnings: list[str], geoip_rule_sets: dict[str, str]) -> tuple[list[dict], str]:
    rules: list[dict] = []
    final = "Proxy"
    for line in read_sections(path).get("Rule", []):
        rule, final_candidate = convert_rule(line, warnings, geoip_rule_sets)
        if final_candidate:
            final = final_candidate
        if rule:
            rules.append(rule)
    return rules, final


def parse_general_runtime_options(path: Path) -> tuple[str, str, str | None, str | None, bool]:
    sections = read_sections(path)
    provider_host = PROVIDER_DOH_HOST
    provider_path = PROVIDER_DOH_PATH
    for value in general_value_list(sections, "encrypted-dns-server"):
        parsed = parse_https_dns_server(value)
        if parsed:
            provider_host, provider_path = parsed
            break
    bootstrap_dns = first_plain_dns_server(general_value_list(sections, "dns-server"))
    proxy_test_url = general_first_value(sections, "proxy-test-url")
    ipv4_only = not general_bool(sections, "ipv6", True)
    return provider_host, provider_path, bootstrap_dns, proxy_test_url, ipv4_only


def parse_profile(path: Path, geoip_rule_sets: dict[str, str] | None = None) -> ParsedProfile:
    warnings: list[str] = []
    proxies = parse_surge_anytls(path)
    proxy_tags = [proxy["tag"] for proxy in proxies]
    groups = parse_proxy_groups(path, set(proxy_tags))
    general_resolve_rules = parse_general_resolve_rules(path)
    general_direct_rules = parse_general_direct_rules(path, warnings)
    dns_rules = parse_general_dns_rules(path)
    route_rules, final_outbound = parse_route_rules(path, warnings, geoip_rule_sets or {})
    provider_host, provider_path, bootstrap_dns, proxy_test_url, ipv4_only = parse_general_runtime_options(path)
    return ParsedProfile(
        proxies,
        proxy_tags,
        groups,
        general_resolve_rules,
        general_direct_rules,
        dns_rules,
        route_rules,
        final_outbound,
        provider_host,
        provider_path,
        bootstrap_dns,
        proxy_test_url,
        ipv4_only,
        warnings,
    )


def build_config(args: argparse.Namespace) -> tuple[dict, list[str]]:
    geoip_rule_sets = {}
    if getattr(args, "geoip_cn_rule_set", ""):
        geoip_rule_sets["CN"] = "geoip-cn"
    profile = parse_profile(Path(args.input), geoip_rule_sets)
    warnings = profile.warnings

    group_outbounds = build_group_outbounds(profile.groups, profile.proxy_tags, warnings)
    group_tags = {outbound["tag"] for outbound in group_outbounds}

    if group_outbounds:
        top_selector = args.selector if args.selector in group_tags else profile.final_outbound
        final_outbound = profile.final_outbound if profile.final_outbound in group_tags else top_selector
    else:
        auto_tag = "auto"
        group_outbounds = [
            urltest_outbound(auto_tag, profile.proxy_tags, profile.proxy_test_url or args.test_url, args.test_interval),
            {
                "type": "selector",
                "tag": args.selector,
                "outbounds": [auto_tag, *profile.proxy_tags],
                "default": auto_tag,
                "interrupt_exist_connections": True,
            },
        ]
        final_outbound = args.selector

    outbounds = [
        *group_outbounds,
        *profile.proxies,
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ]

    route_rules = []
    if not args.no_general:
        route_rules.extend(profile.general_resolve_rules)
        route_rules.extend(profile.general_direct_rules)
    if not args.no_modes:
        route_rules.extend(
            [
                {"clash_mode": "Global", "action": "route", "outbound": final_outbound},
                {"clash_mode": "Direct", "action": "route", "outbound": "direct"},
            ]
        )
    if not args.no_rules:
        route_rules.extend(profile.route_rules)
    local_dns_server = {"type": "local", "tag": "local-dns"}
    if args.local_dns_server:
        local_dns_server = {
            "type": "udp",
            "tag": "local-dns",
            "server": args.local_dns_server,
            "server_port": args.local_dns_port,
        }

    config = {
        "log": {"level": args.log_level},
        "dns": {
            "servers": [
                {
                    "type": "udp",
                    "tag": "bootstrap-dns",
                    "server": profile.bootstrap_dns or args.bootstrap_dns,
                    "server_port": 53,
                },
                {
                    "type": "https",
                    "tag": "provider-doh",
                    "server": profile.provider_doh_host,
                    "server_port": 443,
                    "path": profile.provider_doh_path,
                    "domain_resolver": "bootstrap-dns",
                },
                local_dns_server,
            ],
            "rules": profile.dns_rules,
            "final": "provider-doh",
            "strategy": "ipv4_only" if profile.ipv4_only else "prefer_ipv4",
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "lan-mixed",
                "listen": args.listen,
                "listen_port": args.mixed_port,
            }
        ],
        "outbounds": outbounds,
        "route": {
            "rules": route_rules,
            "final": final_outbound,
            "default_domain_resolver": "provider-doh",
            "auto_detect_interface": True,
        },
        "experimental": {
            "cache_file": {
                "enabled": True,
                "path": args.cache_path,
            },
            "clash_api": {
                "external_controller": args.api_listen,
                "secret": args.secret,
                "default_mode": "Rule",
            },
        },
    }
    if getattr(args, "geoip_cn_rule_set", ""):
        rule_set_ref = args.geoip_cn_rule_set
        if rule_set_ref.startswith(("http://", "https://")):
            cn_rule_set = {
                "type": "remote",
                "tag": "geoip-cn",
                "format": "binary" if rule_set_ref.endswith(".srs") else "source",
                "url": rule_set_ref,
                "update_interval": args.rule_set_update_interval,
            }
        else:
            cn_rule_set = {
                "type": "local",
                "tag": "geoip-cn",
                "format": "binary" if rule_set_ref.endswith(".srs") else "source",
                "path": rule_set_ref,
            }
        config["route"]["rule_set"] = [cn_rule_set]
    return config, warnings


def write_generated_config(args: argparse.Namespace, output_path: str) -> list[str]:
    config, warnings = build_config(args)
    output = json.dumps(config, ensure_ascii=False, indent=2) + "\n"
    if output_path == "-":
        sys.stdout.write(output)
    else:
        Path(output_path).write_text(output, encoding="utf-8")
    return warnings


def print_warnings(warnings: list[str]) -> None:
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)


def command_generate(args: argparse.Namespace) -> None:
    warnings = write_generated_config(args, args.output)
    if args.output != "-":
        print(f"wrote {args.output}", file=sys.stderr)
    print_warnings(warnings)


def load_config(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def node_tags(config: dict) -> list[str]:
    return [outbound["tag"] for outbound in config.get("outbounds", []) if outbound.get("type") == "anytls"]


def command_list(args: argparse.Namespace) -> None:
    config = load_config(Path(args.config))
    for tag in node_tags(config):
        print(tag)


def api_request(controller: str, secret: str, method: str, path: str, body=None):
    url = controller.rstrip("/") + path
    data = None
    headers = {}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    if body is not None:
        data = json.dumps(body).encode()
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
        raise SystemExit(f"{method} {url} failed: HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"{method} {url} failed: {exc.reason}") from exc


def command_current(args: argparse.Namespace) -> None:
    selector = urllib.parse.quote(args.selector, safe="")
    data = api_request(args.controller, args.secret, "GET", f"/proxies/{selector}")
    print(data.get("now", "") if isinstance(data, dict) else "")


def command_switch(args: argparse.Namespace) -> None:
    selector = urllib.parse.quote(args.selector, safe="")
    api_request(args.controller, args.secret, "PUT", f"/proxies/{selector}", {"name": args.node})
    print(args.node)


def command_mode(args: argparse.Namespace) -> None:
    if args.mode:
        api_request(args.controller, args.secret, "PATCH", "/configs", {"mode": args.mode})
    data = api_request(args.controller, args.secret, "GET", "/configs")
    if isinstance(data, dict):
        print(data.get("mode", ""))
        modes = data.get("mode-list")
        if modes:
            print("available: " + ", ".join(modes), file=sys.stderr)


def command_run(args: argparse.Namespace) -> None:
    binary = args.sing_box
    if os.sep not in binary:
        resolved = shutil.which(binary)
        if not resolved:
            raise SystemExit(f"sing-box binary not found in PATH: {binary}")
        binary = resolved

    config_path = args.output
    temporary = False
    if not config_path:
        fd, config_path = tempfile.mkstemp(prefix="sing-box-", suffix=".json")
        os.close(fd)
        temporary = True

    try:
        warnings = write_generated_config(args, config_path)
        print_warnings(warnings)
        if not args.skip_check:
            subprocess.run([binary, "check", "-c", config_path], check=True)
        subprocess.run([binary, "run", "-c", config_path], check=True)
    finally:
        if temporary:
            try:
                os.unlink(config_path)
            except FileNotFoundError:
                pass


def add_api_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--controller", default=DEFAULT_CONTROLLER)
    parser.add_argument("--secret", default="")
    parser.add_argument("--selector", default="Proxy")


def add_generate_args(parser: argparse.ArgumentParser, include_output: bool = True) -> None:
    parser.add_argument("input", help="Surge full profile or proxy-only file")
    if include_output:
        parser.add_argument("-o", "--output", default="config.json")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--mixed-port", type=int, default=7890)
    parser.add_argument("--api-listen", default="0.0.0.0:9090")
    parser.add_argument("--secret", default="change-me")
    parser.add_argument("--selector", default="Proxy")
    parser.add_argument("--test-url", default=DEFAULT_TEST_URL)
    parser.add_argument("--test-interval", default="12h")
    parser.add_argument("--bootstrap-dns", default="223.5.5.5")
    parser.add_argument("--local-dns-server", default="", help="optional UDP DNS server for local names, e.g. 127.0.0.1 with nss_dns.py")
    parser.add_argument("--local-dns-port", type=int, default=1053)
    parser.add_argument("--cache-path", default="cache.db")
    parser.add_argument("--log-level", default="info")
    parser.add_argument("--no-rules", action="store_true", help="ignore Surge [Rule] and route everything to the final group")
    parser.add_argument("--no-general", action="store_true", help="ignore [General] skip-proxy/tun-excluded-routes direct bypass rules")
    parser.add_argument("--no-modes", action="store_true", help="do not add Clash mode override rules for Rule/Global/Direct switching")
    parser.add_argument("--geoip-cn-rule-set", default="", help="local .srs/.json path or remote URL to use for Surge GEOIP,CN rules")
    parser.add_argument("--rule-set-update-interval", default="7d")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate", help="generate sing-box JSON from a Surge profile")
    add_generate_args(gen)
    gen.set_defaults(func=command_generate)

    run = sub.add_parser("run", help="generate config, check it, then run sing-box")
    add_generate_args(run, include_output=False)
    run.add_argument("-o", "--output", default="", help="write generated config here before running; default is a temp file")
    run.add_argument("--sing-box", default="sing-box", help="path/name of sing-box binary on the Pi")
    run.add_argument("--skip-check", action="store_true", help="skip `sing-box check` before `sing-box run`")
    run.set_defaults(func=command_run)

    list_cmd = sub.add_parser("list", help="list generated AnyTLS node tags")
    list_cmd.add_argument("config", help="generated sing-box config.json")
    list_cmd.set_defaults(func=command_list)

    current = sub.add_parser("current", help="print current selector choice via API")
    add_api_args(current)
    current.set_defaults(func=command_current)

    switch = sub.add_parser("switch", help="switch selector choice via API")
    switch.add_argument("node")
    add_api_args(switch)
    switch.set_defaults(func=command_switch)

    mode = sub.add_parser("mode", help="get or set Clash mode via API: Rule, Global, or Direct")
    mode.add_argument("mode", nargs="?", choices=["Rule", "Global", "Direct", "rule", "global", "direct"])
    add_api_args(mode)
    mode.set_defaults(func=command_mode)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
