# Pi sing-box LAN Proxy

This directory contains a standalone Python tool for running Maomao/Surge
AnyTLS profiles through sing-box on a Raspberry Pi.

The Python script does two jobs:

1. Convert the Surge profile into a sing-box config.
2. Optionally launch the `sing-box` binary with that generated config.

The checked-in sing-box source tree is only for reference. Use an ARM sing-box
binary on the Raspberry Pi; the local amd64 archive is not the target runtime.

## Why profile-aware conversion matters

The sample Surge profile is not just a list of proxies. It contains:

- 88 AnyTLS nodes
- `[Proxy Group]` entries: `Proxy`, `auto`, `fallback`
- hundreds of `[Rule]` entries
- a long url-test interval: `interval=43200`

So the converter must not flatten everything into one frequently-tested group.
It preserves the Surge group shape:

- `Proxy` -> sing-box `selector`
- `auto` -> sing-box `urltest`
- `fallback` -> sing-box `urltest` approximation, because sing-box has no native
  Surge-style fallback outbound group
- Surge `interval=43200` -> sing-box `43200s`

This avoids constantly probing every node every few minutes.

## Generate Config

Use either a full Surge profile or a proxy-only file:

```bash
python3 surge2singbox.py generate surge_full.conf \
  -o config.json \
  --secret change-this
```

The generated config exposes:

- mixed HTTP/SOCKS proxy on `0.0.0.0:7890`
- sing-box Clash API on `0.0.0.0:9090`
- selector outbound named `Proxy`
- provider `auto` urltest group using the profile interval
- one AnyTLS outbound for every parsed Surge node
- converted route rules where sing-box supports the Surge rule type

Local LAN devices can use:

```text
http://raspberrypi.local:7890
socks5://raspberrypi.local:7890
```

## Run sing-box from Python on the Pi

Install or place the correct ARM `sing-box` binary on the Raspberry Pi first.
Then run:

```bash
python3 surge2singbox.py run surge_full.conf \
  --sing-box /usr/local/bin/sing-box \
  --secret change-this
```

The `run` command:

1. generates a temporary sing-box config,
2. runs `sing-box check -c <config>`,
3. runs `sing-box run -c <config>` if the check passes.

To keep the generated config for inspection or systemd:

```bash
python3 surge2singbox.py run surge_full.conf \
  --sing-box /usr/local/bin/sing-box \
  -o /etc/sing-box/config.json \
  --cache-path /var/lib/sing-box/cache.db \
  --secret change-this
```

For manual testing after generation:

```bash
sing-box check -c config.json
sing-box run -c config.json
```

## GEOIP,CN behavior

sing-box 1.13 removed the old `geoip` route field, so Surge rules like this
cannot be emitted directly:

```text
GEOIP,CN,DIRECT
```

By default the converter skips that rule with a warning rather than generating
an invalid config. To preserve it, provide a sing-box rule-set file or URL:

```bash
python3 surge2singbox.py generate surge_full.conf \
  -o config.json \
  --geoip-cn-rule-set /path/to/geoip-cn.srs \
  --secret change-this
```

Remote URLs are also accepted:

```bash
python3 surge2singbox.py generate surge_full.conf \
  -o config.json \
  --geoip-cn-rule-set https://example.com/geoip-cn.srs \
  --secret change-this
```


## Remote Rule / Global / Direct Mode

The generated config uses Surge rules by default with Clash mode `Rule`. It also
adds mode override rules so the Clash API can switch routing mode remotely:

- `Rule`: use converted Surge `[Rule]` entries
- `Global`: route all traffic to the `Proxy` selector
- `Direct`: route all traffic direct

Check current mode:

```bash
python3 surge2singbox.py mode \
  --controller http://raspberrypi.local:9090 \
  --secret change-this
```

Switch to Global:

```bash
python3 surge2singbox.py mode Global \
  --controller http://raspberrypi.local:9090 \
  --secret change-this
```

Switch back to Rule:

```bash
python3 surge2singbox.py mode Rule \
  --controller http://raspberrypi.local:9090 \
  --secret change-this
```

## CLI Switching

List available nodes from the generated config:

```bash
python3 surge2singbox.py list config.json
```

Check current selector:

```bash
python3 surge2singbox.py current \
  --controller http://127.0.0.1:9090 \
  --secret change-this
```

Switch selector:

```bash
python3 surge2singbox.py switch "1.0x 🇯🇵 日本 JP - 1" \
  --controller http://127.0.0.1:9090 \
  --secret change-this
```

Use `--controller http://raspberrypi.local:9090` from another LAN machine.

## Notes

The converter preserves the Maomao DNS behavior by using the provider DoH
endpoint for resolving upstream AnyTLS server hostnames.

Change `--secret` before exposing the API on your LAN. Also avoid committing or
sharing real subscription tokens and proxy passwords from provider profiles.
