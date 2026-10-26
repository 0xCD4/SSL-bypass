# Universal Android Security Bypass Suite (v3)

A universal Frida script for bypassing common security mechanisms in Android applications during **authorized** security testing. Works out-of-the-box across Android versions and applications without app-specific modifications.

> **Note about stability:** Universal bypass scripts can still crash some apps. If the target crashes on first attempt, retry 2-3 times, restart the app, relaunch Frida, or inject with `-f` instead of attaching to a running process.

## Features

### SSL / Certificate Pinning Bypass
- `SSLContext.init` → trust-all TrustManager (single central hook)
- OkHttp 3.x (`CertificatePinner.check`) and OkHttp 4.x (`check$okhttp`)
- Conscrypt `TrustManagerImpl` (`checkTrustedRecursive`, `verifyChain`) — Android 7+
- OpenSSL/BoringSSL variants (conscrypt + Apache Harmony `verifyCertificateChain`)
- WebView / Apache Cordova `onReceivedSslError`
- TrustKit, PhoneGap, IBM MobileFirst/WorkLight, Appcelerator, Appmattus Certificate Transparency, Boye
- `HttpsURLConnection` custom socket factories / hostname verifiers neutralized

### Root Detection Bypass
- `Build` property spoofing (each field individually fault-isolated)
- `SystemProperties.get` (Java) and `__system_property_get` (native) value spoofing
- **Real package hiding**: `PackageManager.getPackageInfo` throws `NameNotFoundException` for root-management packages (`int` and API 33+ `long` flag overloads)
- File checks: `File.exists()` / `UnixFileSystem.checkAccess`, plus native `fopen` / `open` / `openat` / `access` blocking for known root paths
- Command execution: `Runtime.exec`, `ProcessBuilder.start`, and `ProcessImpl.start` with **token-based** blocking (a command like `mkdir` is no longer blocked just because it contains `id`)
- `BufferedReader` output rewriting for `test-keys` checks
- `KeyInfo.isInsideSecureHardware` → true

### Frida Detection Bypass
- `ptrace` → always returns success
- `/proc/self/maps` and `/proc/self/status` redirection: sanitized copies (Frida/gum/Xposed lines filtered, `TracerPid` forced to 0) are written to the app cache dir and served via `open`/`openat`/`fopen` hooks
- `strstr`: only the needle is inspected; Frida-related lookups return NULL
- `connect()`: connections to known Frida ports (27042, 27043, 23946, 27047) fail — with correct network byte-order handling

### Burp Suite Certificate Check
- Detects a pushed CA at common `/data/local/tmp/` locations and prints its subject (Java-level TLS is already trust-all; the pushed certificate matters for native TLS stacks)

## What changed in v3

The v2 script (`root_bypass.js`, removed) contained bugs that silently disabled several bypasses:

| v2 bug | v3 fix |
|---|---|
| `connect()` port check read `sin_family` from the wrong byte offset and the port in host byte order — never matched | correct 2-byte family read + big-endian port decode |
| `/proc/self/maps` filter used a non-existent Frida `File(fd, "r").readAll()` API — threw on every call | working redirect mechanism via sanitized fake files |
| `Runtime.exec` blocking regex (`sh`, `id`, `su` as substrings) broke legitimate app commands | token-based blocking with binary-name resolution |
| `ProcessBuilder.command(["echo"])` passed a JS array where `List<String>` is required | proper `java.util.ArrayList` |
| `pm list` check looked at the wrong argument index | all arguments scanned |
| Package manager code only *queried* root packages without hiding them | `getPackageInfo` now throws `NameNotFoundException` |
| `.implementation` assigned without `.overload()` on multi-overload methods (throws in Frida) | generic `hookAll` covering every overload |
| `global.fridaStatus` (`ReferenceError` in Frida), duplicate `SSLContext.init` / verifier / `SystemProperties` hooks, dead `ProcessManager` branch, `enumerateLoadedClassesSync()` scans | removed / consolidated |
| One failing hook could abort a whole section | every hook individually wrapped in `try/catch` |

## Usage

```bash
# Basic usage (spawn)
frida -U -f com.target.application -l android-bypass-v3.js

# Optional: push a Burp CA for native TLS interception
adb push cacert.der /data/local/tmp/cert-der.crt
```

Set `VERBOSE = true` at the top of the script to log every blocked call.

## Limitations

- Hardware-backed attestation (Play Integrity, SafetyNet hardware) is **not** bypassed
- Heavily obfuscated or custom native implementations may require app-specific hooks
- Frida-server itself must be hidden (e.g., non-default name/port) for strong anti-Frida targets
- No guarantee against sophisticated RASP frameworks

## Security Notice

For **legitimate security research and authorized penetration testing only**. Users are responsible for compliance with applicable laws and regulations. This is not a silver bullet — some protections may remain active; always verify in your specific use case.
