#!/usr/bin/env python3
"""Refresh a provider Surge profile while preserving local Linux fixes.

This script sanitizes the provider's full Surge config so automatic updates do not
reintroduce the DNS regression.

Usage:
    python3 surge_profile_refresh.py \
        --input surge_full_updated_bug.conf \
        --output surge_full.conf
"""

import argparse
import re
from pathlib import Path

INFO_PREFIXES = ("剩余流量", "距离下次重置剩余", "套餐到期", "官网")
PROVIDER_DOH = "https://dns.maomaovpn.com/dns-query/b21fb37a924bbd327154e3b06635fbde"
FALLBACK_DOH = "https://doh.pub/dns-query"
HOST_RULE = f"*.maomao678.com = server:{PROVIDER_DOH}"
GENERAL_OVERRIDES = {
    "encrypted-dns-server": f"{PROVIDER_DOH}, {FALLBACK_DOH}",
    "dns-server": "system, 223.5.5.5, 119.29.29.29, 114.114.114.114",
    "ipv6": "false",
}
REMOVE_KEYS = {"doh-server"}
SECTION_RE = re.compile(r"^\[[^\]]+\]\s*$")


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
        if stripped.startswith('['):
            out.append(line)
            continue
        if '=' not in line:
            out.append(line)
            continue
        key, _value = [part.strip() for part in line.split('=', 1)]
        if key in REMOVE_KEYS:
            continue
        if key in GENERAL_OVERRIDES:
            if key not in seen:
                out.append(f"{key} = {GENERAL_OVERRIDES[key]}\n")
                seen.add(key)
            continue
        out.append(line)
    insert_at = 1 if out and out[0].strip() == '[General]' else 0
    for key, value in GENERAL_OVERRIDES.items():
        if key not in seen:
            out.insert(insert_at, f"{key} = {value}\n")
            insert_at += 1
    return out


def normalize_proxy(lines):
    out = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('['):
            out.append(line)
            continue
        if '=' not in line:
            out.append(line)
            continue
        name = stripped.split('=', 1)[0]
        if name.startswith(INFO_PREFIXES) or '：' in name:
            continue
        out.append(line)
    return out


def ensure_host_section(sections):
    host_lines = ['[Host]\n', HOST_RULE + '\n']
    out = []
    inserted = False
    for name, lines in sections:
        if name == 'Host':
            out.append((name, host_lines))
            inserted = True
            continue
        out.append((name, lines))
        if name == 'Panel' and not inserted:
            out.append(('Host', host_lines))
            inserted = True
    if not inserted:
        out.append(('Host', host_lines))
    return out


def sanitize(text):
    lines = text.splitlines(keepends=True)
    if lines and lines[0].startswith('#!MANAGED-CONFIG '):
        source = lines[0].strip()[len('#!MANAGED-CONFIG '):]
        lines[0] = f'# Managed source: {source}\n'
    sections = split_sections(lines)
    new_sections = []
    for name, sec_lines in sections:
        if name == 'General':
            sec_lines = normalize_general(sec_lines)
        elif name == 'Proxy':
            sec_lines = normalize_proxy(sec_lines)
        new_sections.append((name, sec_lines))
    new_sections = ensure_host_section(new_sections)

    rendered = []
    for _, sec_lines in new_sections:
        rendered.extend(sec_lines)
    return ''.join(rendered)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()

    src = Path(args.input)
    dst = Path(args.output)
    fixed = sanitize(src.read_text(encoding='utf-8'))
    dst.write_text(fixed, encoding='utf-8')


if __name__ == '__main__':
    main()
