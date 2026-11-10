# LINE Android 26.1.1 — Security Audit

Independent static-analysis security audit of the **LINE** Android application
(`jp.naver.line.android`, version **26.1.1**, build 260110123), covering the
network security configuration, native libraries, and the decompiled Java/Smali
layer, with a suite of proof-of-concept analysis scripts.

> ⚠️ **For educational and authorized security research only.** Do **not** use these
> tools or techniques against any application you do not own or lack **explicit written
> authorization** to test. Findings come from static analysis of a publicly distributed
> APK; nothing here is a working exploit. Unauthorized use may violate the CFAA, the UK
> Computer Misuse Act, GDPR, and equivalent laws. See [DISCLAIMER](DISCLAIMER.md).

---

## Headline

LINE protects its **financial** traffic rigorously but leaves parts of its **core
messaging** traffic exposed. Banking partner domains carry 6–8 certificate pins each,
while the main messaging gateway (`legy.line-apps.com`) has **no pins**, and a token
authentication endpoint (`tauth.line.naver.jp`) is reachable over **cleartext HTTP**.

## Findings at a glance

| ID | Severity | Title | CWE |
|----|----------|-------|-----|
| F-01 | 🔴 CRITICAL | Cleartext HTTP permitted on authentication & core domains (`tauth.line.naver.jp` +10) | CWE-319 |
| F-02 | 🟠 HIGH | Missing certificate pins on core messaging gateway (`legy.line-apps.com`) | CWE-295 |
| F-03 | 🟠 HIGH | Dev/staging/RC endpoints hardcoded in production APK | CWE-798 |
| F-04 | 🟠 HIGH | Hardcoded internal AI infrastructure endpoints (`libDeepLingoKit.so`) | CWE-798 |
| F-05 | 🟠 HIGH | JWT-like token embedded in native library | CWE-321 |
| F-06 | 🟡 MEDIUM | `base-config` permits global cleartext traffic | CWE-319 |
| F-07 | 🟡 MEDIUM | `liblegy.so` strings runtime-assembled (anti-analysis) | CWE-656 |
| F-08 | ⚪ INFO | Security asymmetry: banking pinned, messaging not | CWE-295 |

Six automated native-scan hits were investigated and **documented as false positives**
(SQLite build fingerprints, hex lookup tables, NIST test vectors). Full reasoning in the
[report](report/REPORT.md).

---

## Repository layout

```
report/REPORT.md              Full audit report (findings, evidence, remediation)
report/*.docx                 Same report as a Word document
guides/ANALYSIS_GUIDE.md      Environment + command reference (Kali + macOS/Ghidra)
guides/REPRODUCTION_GUIDE.md  Step-by-step reproduction workflow
poc/                          Proof-of-concept analysis scripts (see poc/README.md)
  ├── analyze_line_natives.py      Native-library secret/entropy scanner (P0/P1 tiers)
  ├── poc_01_hardcoded_secrets.py  Hardcoded secrets in native libs  (F-04, F-05)
  ├── poc_02_insecure_storage.py   SharedPreferences plaintext scan
  ├── poc_03_cert_pinning.py       NSC pinning / cleartext analysis  (F-01, F-02, F-03)
  ├── poc_04_exported_activities.py Exported component / deep-link scan
  ├── poc_05_crypto_webview.py     Weak crypto + WebView JS-interface scan
  └── run_all_pocs.py              Master runner
assets/cover.png              Project cover image
```

## Quick start

```bash
# Native library scan (point at extracted arm64-v8a libs)
python3 poc/analyze_line_natives.py --libs-dir /path/to/lib/arm64-v8a --tier all --out natives.json

# Certificate-pinning / cleartext analysis against the decompiled NSC
python3 poc/poc_03_cert_pinning.py --nsc /path/to/res/xml/network_security_config.xml --smali /path/to/smali

# Everything, demo mode (no APK needed)
python3 poc/run_all_pocs.py --demo
```

Full setup (APKTool, Ghidra, Frida) is in [guides/ANALYSIS_GUIDE.md](guides/ANALYSIS_GUIDE.md).

---

## Methodology

Static analysis only, across three layers:

1. **Network security config** — `res/xml/network_security_config.xml` parsed for cleartext
   permissions, pin-sets, and non-production domains.
2. **Native libraries** — 70+ `.so` files from `split_config.arm64_v8a.apk`; ELF section
   parsing, string extraction, Shannon-entropy screening, and LINE-specific pattern matching.
3. **Java/Smali** — APKTool decompilation (192,737 smali files) for endpoint construction,
   storage, crypto, and WebView usage.

Dynamic analysis (Frida on a rooted test device) is scaffolded in the guides but is not
required to confirm the static findings above.

---

## Author

**deepquest** · <https://deepquest.code511.com/blog>

## License & disclaimer

Released for educational and authorized security-research use only. See
[DISCLAIMER.md](DISCLAIMER.md).
