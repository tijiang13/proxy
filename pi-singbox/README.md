# Pi sing-box LAN Proxy

Run a Surge/Maomao AnyTLS profile with sing-box on a Raspberry Pi. The Python tool converts `surge_full.conf`, preserves supported Surge groups/rules, and launches the ARM sing-box binary. Optional Flask UI exposes mode and node switching on LAN while keeping the raw sing-box API local.

```bash
python3 surge2singbox.py run surge_full.conf --sing-box ./sing-box-1.13.13-linux-arm64/sing-box --api-listen 127.0.0.1:9090 --secret change-this --cache-path ./cache.db
SING_BOX_CONTROLLER=http://127.0.0.1:9090 SING_BOX_SECRET=change-this WEB_SECRET=choose-a-web-password python3 web.py
python3 surge2singbox.py mode Global --controller http://127.0.0.1:9090 --secret change-this; python3 surge2singbox.py switch "NODE NAME" --controller http://127.0.0.1:9090 --secret change-this
```
