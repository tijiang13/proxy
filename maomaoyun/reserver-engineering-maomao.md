# Reverse-Engineering Maomao

This note documents the workflow used in this workspace to reverse engineer the Maomao Android app and reproduce the subscription extraction path on Linux. The goal is to make it easy to repeat the process when a new APK is released.

## Scope

The parts we needed were:

- how the app discovers its live API domain
- how login and subscription retrieval work
- how the Surge subscription output is obtained
- what app-specific DNS behavior matters for a working Linux/Surge profile

The current workspace was built around [app/maomao2.3.1.apk](/home/tijiang/Downloads/temp/app/maomao2.3.1.apk).

## Files Used

Relevant helper artifacts in this workspace:

- [extract_bootstrap.py](/home/tijiang/Downloads/temp/extract_bootstrap.py)
- [emulate_seed.py](/home/tijiang/Downloads/temp/emulate_seed.py)
- [disas.py](/home/tijiang/Downloads/temp/disas.py)
- [hook_domain.js](/home/tijiang/Downloads/temp/hook_domain.js)
- [maomao2surge.py](/home/tijiang/Downloads/temp/maomao2surge.py)
- unpacked native libs under [app/lib/arm64-v8a](/home/tijiang/Downloads/temp/app/lib/arm64-v8a)
- unpacked dex/resources under [app](/home/tijiang/Downloads/temp/app)

## High-Level Findings

1. The app does not hardcode a single stable API domain.
2. It first resolves a bootstrap URL hidden behind native decryption logic in `libcore.so`.
3. That bootstrap payload is an Alibaba OSS text file, currently `android.txt`, containing rotating API domains.
4. The app tests those domains and uses a live one.
5. Once authenticated, the app reads `subscribe_url` from `/api/v1/user/getSubscribe`.
6. The provider already exposes native Surge output with `?flag=surge`, so we do not need to rebuild proxies by hand.

## Repeatable Workflow

### 1. Unpack the APK

The APK in this workspace was already unpacked into `app/`, including:

- `classes.dex`, `classes2.dex`, `classes3.dex`
- `lib/arm64-v8a/libcore.so`
- `lib/arm64-v8a/libclash.so`
- resources and assets

For a new APK, extract it first with a normal unzip step or an APK toolchain such as `apktool` or `jadx`.

What to look for first:

- Java class names around networking or bootstrap logic
- native libs, especially `libcore.so`
- strings that look like API tokens, control flags, OSS URLs, or subscription endpoints

### 2. Recover the bootstrap control token from Java side

The Java layer stores StringFog-XOR-obfuscated byte arrays that become base64 tokens at runtime. The important clue, documented in [extract_bootstrap.py](/home/tijiang/Downloads/temp/extract_bootstrap.py:1), was that a control token from `RetrofitHelper` is passed into native code.

For a new APK, inspect the decompiled Java/Kotlin code for:

- `RetrofitHelper`
- `controlFirst`
- calls into `com.mt.Core`
- StringFog decode sites

The token itself is not yet the final domain. It is ciphertext that the native layer decrypts.

### 3. Reverse `com.mt.Core.queryConfiguration()` in `libcore.so`

The key step was understanding the native function behind the bootstrap path.

We used [disas.py](/home/tijiang/Downloads/temp/disas.py:1) to disassemble named symbols from the ELF:

```bash
python3 disas.py app/lib/arm64-v8a/libcore.so Java_com_mt_Core_queryConfiguration
```

What we learned from reversing that function:

- it base64-decodes the Java token
- it decrypts the token with 3DES-EDE3-CBC
- the key and IV are built from a constant seed assembled in native code
- the plaintext is an OSS URL pointing to `android.txt`

### 4. Recover the native 3DES seed

The seed was recovered by emulating the top part of `Java_com_mt_Core_queryConfiguration` with Unicorn using [emulate_seed.py](/home/tijiang/Downloads/temp/emulate_seed.py:1).

Command:

```bash
python3 emulate_seed.py app/lib/arm64-v8a/libcore.so
```

Current v2.3.1 result:

- seed bytes: `NIMAMAIB`
- key: `b"NIMAMAIB" + b"\x00" * 16`
- iv: `b"NIMAMAIB"`

The script emulates just enough of the function to recover the seed buffer without reproducing the entire app runtime. If a future APK changes the function body or offsets, this is the first helper likely to need adjustment.

Key hardcoded offsets in the current version are in [emulate_seed.py](/home/tijiang/Downloads/temp/emulate_seed.py:9):

- `FUNC = 0x1658`
- `STOP = 0x17dc`

If symbols or layouts change, re-find the native function and update those offsets.

### 5. Decrypt the bootstrap URL offline

Once the seed is known, the encrypted Java token can be decrypted offline with [extract_bootstrap.py](/home/tijiang/Downloads/temp/extract_bootstrap.py:1).

Examples:

```bash
python3 extract_bootstrap.py
python3 extract_bootstrap.py <base64-token>
```

Current v2.3.1 finding:

- the decrypted bootstrap target is an Alibaba OSS URL for `android.txt`

That text file contains the current live API domains.

### 6. Validate the runtime behavior with Frida

For runtime confirmation, we used [hook_domain.js](/home/tijiang/Downloads/temp/hook_domain.js:1) to hook the Java wrappers around the native core.

Example:

```bash
frida -U -f com.mt.maomao -l hook_domain.js
```

This prints inputs and outputs for:

- `Core.queryConfiguration`
- `Core.queryDomain`
- `Core.queryPath`

Use this when:

- the static analysis is ambiguous
- the app starts adding runtime transforms
- you want to confirm the exact live domain selected by the current build

### 7. Rebuild the login and subscribe flow outside the app

After the bootstrap was understood, the rest was standard API replay.

The current logic is implemented in [maomao2surge.py](/home/tijiang/Downloads/temp/maomao2surge.py:1):

1. fetch `android.txt` from the bootstrap URL
2. read the candidate API domains
3. probe `/api/v1/guest/comm/config` to find a live base URL
4. log in through `/api/v1/passport/auth/login`
5. fetch `subscribe_url` from `/api/v1/user/getSubscribe`
6. request `subscribe_url + ?flag=surge`

Important point:

- the provider already renders native Surge output, so there is no need to reimplement `vmess`, `trojan`, `anytls`, or other node formats manually if `flag=surge` still works

### 8. Preserve the Linux-specific Surge fixes

The provider's native Surge profile was not directly usable on Linux in our case.

Two issues mattered:

- the provider profile included notice rows inside `[Proxy]`
- the provider-managed update path reverted DNS behavior that was needed for working resolution on Linux

The current sanitizer in [maomao2surge.py](/home/tijiang/Downloads/temp/maomao2surge.py:240) fixes that by:

- removing rows like `剩余流量`, `距离下次重置剩余`, `套餐到期`, `官网`
- forcing `encrypted-dns-server = https://dns.maomaovpn.com/dns-query/... , https://doh.pub/dns-query`
- forcing `dns-server = system, 223.5.5.5, 119.29.29.29, 114.114.114.114`
- forcing `ipv6 = false`
- inserting a `[Host]` rule for `*.maomao678.com`
- disabling managed auto-update by default unless `--enable-autoupgrade` is requested

## What To Re-Check On A New APK

When the APK updates, verify these items in order:

1. Does `com.mt.Core.queryConfiguration` still exist?
2. Is the seed-building logic still in `libcore.so`?
3. Are the current `FUNC` and `STOP` offsets in `emulate_seed.py` still valid?
4. Is the cipher still 3DES-CBC with the same key/IV construction?
5. Is the decrypted bootstrap still an OSS `android.txt`-style URL?
6. Does the app still expose `/api/v1/passport/auth/login` and `/api/v1/user/getSubscribe`?
7. Does `subscribe_url?flag=surge` still return a native Surge config?
8. Has the provider changed the info-row prefixes that need to be filtered out?
9. Has the provider changed the DNS endpoint used for proxy-hostname resolution?

## Minimal Re-Validation Checklist

For a new app version, the shortest reliable path is:

1. Extract APK contents.
2. Inspect Java for the encrypted control token and `com.mt.Core` call sites.
3. Disassemble `libcore.so` around `Java_com_mt_Core_queryConfiguration`.
4. Re-run `emulate_seed.py` or update it until the seed prints cleanly.
5. Re-run `extract_bootstrap.py` on the new token.
6. Confirm the new bootstrap domains respond at `/api/v1/guest/comm/config`.
7. Run `maomao2surge.py` against a real account and verify the full generated `surge_full.conf` works.

## Known Current Values

These are current observations from the v2.3.1 workspace and should not be assumed stable across versions:

- seed: `NIMAMAIB`
- bootstrap filename: `android.txt`
- provider DoH endpoint: `https://dns.maomaovpn.com/dns-query/b21fb37a924bbd327154e3b06635fbde`
- working proxy host pattern: `*.maomao678.com`

Treat these as version-specific findings, not permanent protocol facts.
