**LINE ANDROID 26.1.1**

Complete Security Analysis — Environment-Specific Guide

**February 2026 · EDUCATIONAL PURPOSE ONLY**

|                    |                                                          |
|--------------------|----------------------------------------------------------|
| **Target APK**     | jp.naver.line.android_26.1.1-260110123_2arch_6dpi.apkm   |
| **Analysis Host**  | Kali Linux — user: deepquest hostname: deep1trud         |
| **macOS Host**     | Ghidra GUI / Decompiler analysis                         |
| **Working Dir**    | ~/Downloads/Line audit/                                  |
| **APK Bundle**     | ~/Downloads/Line audit/apkm/line.apkm                    |
| **Extracted APKs** | ~/Downloads/Line audit/apkm/extracted/                   |
| **Native Libs**    | ~/Downloads/Line audit/Line 26.1.1/native/lib/arm64-v8a/ |
| **Decompiled**     | ~/Downloads/Line audit/decompiled/                       |
| **PoC Scripts**    | ~/Downloads/Line audit/POC/                              |
| **Frida Version**  | 17.7.3 (pip3 install frida-tools)                        |
| **Shell**          | zsh (~/.zshrc for PATH exports)                          |

**0. Environment Reference & Path Variables**

Set these variables at the start of every session to avoid retyping long
paths.

> \# ── Add to ~/.zshrc for persistence ─────────────────────────────
>
> \$ cat \>\> ~/.zshrc \<\< 'EOF'
>
> \# LINE Audit paths
>
> export AUDIT="\$HOME/Downloads/Line audit"
>
> export LIBS="\$AUDIT/Line 26.1.1/native/lib/arm64-v8a"
>
> export POC="\$AUDIT/POC"
>
> export APKM="\$AUDIT/apkm/extracted"
>
> export DECOMP="\$AUDIT/decompiled"
>
> export GHIDRA_HOME=/opt/ghidra_11.1.2_PUBLIC
>
> export PATH=\$PATH:\$GHIDRA_HOME/support:/home/deepquest/.local/bin
>
> EOF
>
> \$ source ~/.zshrc
>
> \# Verify
>
> \$ echo \$LIBS
>
> =\> /home/deepquest/Downloads/Line audit/Line
> 26.1.1/native/lib/arm64-v8a
>
> \$ frida --version
>
> =\> 17.7.3

**0.1 Confirmed Directory Structure**

> ~/Downloads/Line audit/
>
> ├── apkm/
>
> │ ├── line.apkm \# Original bundle
>
> │ └── extracted/
>
> │ ├── base.apk \# 163MB — main APK
>
> │ ├── split_config.arm64_v8a.apk \# 101MB — arm64 native libs
>
> │ ├── split_config.armeabi_v7a.apk \# 73MB — 32-bit (skip)
>
> │ └── split_config.{hdpi,xhdpi,...} \# density resources
>
> ├── Line 26.1.1/
>
> │ └── native/lib/arm64-v8a/ \# Extracted .so files
>
> │ ├── libsentry.so
>
> │ ├── libsentry-android.so
>
> │ ├── liblegy.so
>
> │ ├── libmm.so
>
> │ ├── libssl3line.so
>
> │ └── ... (60+ libraries)
>
> ├── decompiled/ \# APKTool output (smali + res)
>
> └── POC/ \# All analysis scripts
>
> ├── analyze_line_natives.py
>
> ├── poc_01_hardcoded_secrets.py
>
> ├── poc_02_insecure_storage.py
>
> ├── poc_03_cert_pinning.py
>
> ├── poc_04_exported_activities.py
>
> ├── poc_05_crypto_webview.py
>
> ├── run_all_pocs.py
>
> ├── line_base_secrets.json \# Already generated
>
> └── README.md

**1. Extraction Status & Remaining Steps**

Based on your session so far, here is what is done and what still needs
to run.

|             |                                                    |
|-------------|----------------------------------------------------|
| **✅ DONE** | apkm/line.apkm extracted → apkm/extracted/         |
| **✅ DONE** | split_config.arm64_v8a.apk → native libs extracted |
| **✅ DONE** | Frida 17.7.3 installed via pip3                    |
| **✅ DONE** | analyze_line_natives.py copied to POC/             |
| **✅ DONE** | P0 native scan completed (all false positives)     |
| **⏳ TODO** | APKTool decompile base.apk → decompiled/           |
| **⏳ TODO** | Run P1 native scanner → line_natives_P1.json       |
| **⏳ TODO** | Run full PoC suite → line_audit_summary.json       |
| **⏳ TODO** | Sentry DSN strings extraction                      |
| **⏳ TODO** | Frida server push to test device                   |

**1.1 Check APKTool Status**

> \$ ls "\$DECOMP/AndroidManifest.xml" 2\>/dev/null \\
>
> && echo 'APKTool done ✓' \\
>
> \|\| echo 'Still decompiling or not started'
>
> \# If not started yet:
>
> \$ apktool d "\$APKM/base.apk" -o "\$DECOMP" -f
>
> \# Takes 3-8 minutes for 163MB base.apk — normal

**2. Native Library Analysis**

**2.1 Run P1 Scanner**

> \$ cd "\$POC"
>
> \$ python3 analyze_line_natives.py \\
>
> --libs-dir "\$LIBS" \\
>
> --tier P1 \\
>
> --out line_natives_P1.json
>
> \# Then run all tiers together:
>
> \$ python3 analyze_line_natives.py \\
>
> --libs-dir "\$LIBS" \\
>
> --tier all \\
>
> --out line_natives_all.json

**2.2 Quick Strings — Run These Now (No Tools Needed)**

> **⚠ NOTE:** These commands work immediately against your
> already-extracted libs. Run in a second terminal while other scans are
> running.
>
> \# ── Sentry DSN — almost guaranteed to contain a real secret ──────
>
> \$ strings "\$LIBS/libsentry.so" "\$LIBS/libsentry-android.so" \\
>
> \| grep -E "https://\[0-9a-f\]{32}@"
>
> \# ── GCP API keys ─────────────────────────────────────────────────
>
> \$ strings "\$LIBS/"\*.so \| grep -E "AIza\[0-9A-Za-z\_-\]{35}"
>
> \# ── AWS keys ─────────────────────────────────────────────────────
>
> \$ strings "\$LIBS/"\*.so \| grep -E "AKIA\[0-9A-Z\]{16}"
>
> \# ── Firebase URLs ────────────────────────────────────────────────
>
> \$ strings "\$LIBS/"\*.so \| grep -E
> "https://\[a-z0-9-\]+\\firebaseio\\com"
>
> \# ── All internal LINE/Naver URLs ─────────────────────────────────
>
> \$ strings "\$LIBS/"\*.so \\
>
> \| grep -E "https?://\[a-z0-9-\]+\\(line\|naver)" \\
>
> \| sort -u
>
> \# ── JWT tokens ───────────────────────────────────────────────────
>
> \$ strings "\$LIBS/"\*.so \| grep -E "eyJ\[A-Za-z0-9\_-\]{10,}"
>
> \# ── LINE Edge Gateway (legy) auth strings ────────────────────────
>
> \$ strings "\$LIBS/liblegy.so" \\
>
> \| grep -iE "auth\|token\|endpoint\|secret\|gateway" \| head -30
>
> \# ── SQLCipher passphrase hunt ─────────────────────────────────────
>
> \$ strings "\$LIBS/libsqlcipher.so" \\
>
> \| grep -iE "PRAGMA\|key=\|passphrase" \| head -20
>
> \# ── DeepLingo/translation API keys ──────────────────────────────
>
> \$ strings "\$LIBS/libDeepLingoKit.so" \\
>
> \| grep -iE "key\|api\|token\|secret\|endpoint" \| head -30

**3. Full PoC Suite Execution**

> **⚠ NOTE:** APKTool decompilation must be complete before running the
> full suite. Check with: ls \$DECOMP/AndroidManifest.xml

**3.1 Individual PoC Scripts**

> \$ cd "\$POC"
>
> \# PoC-01: Hardcoded secrets in native libs + APK
>
> \$ python3 poc_01_hardcoded_secrets.py \\
>
> --apk "\$APKM/base.apk" \\
>
> --out poc01_results.json
>
> \# Also scan native libs directly:
>
> \$ python3 poc_01_hardcoded_secrets.py \\
>
> --lib "\$LIBS/liblegy.so" \\
>
> --out poc01_liblegy.json
>
> \# PoC-02: Insecure SharedPreferences (smali scan)
>
> \$ python3 poc_02_insecure_storage.py \\
>
> --smali "\$DECOMP/smali" \\
>
> --out poc02_results.json
>
> \# Scan all smali directories:
>
> \$ for dir in "\$DECOMP"/smali\*/; do
>
> echo "=== \$dir ==="
>
> python3 poc_02_insecure_storage.py --smali "\$dir"
>
> done
>
> \# PoC-03: Certificate pinning
>
> \$ python3 poc_03_cert_pinning.py \\
>
> --nsc "\$DECOMP/res/xml/network_security_config.xml" \\
>
> --smali "\$DECOMP/smali" \\
>
> --gen-frida \\
>
> --out poc03_results.json
>
> \# PoC-04: Exported activities / deep links
>
> \$ python3 poc_04_exported_activities.py \\
>
> --manifest "\$DECOMP/AndroidManifest.xml" \\
>
> --package jp.naver.line.android \\
>
> --out poc04_results.json
>
> \# PoC-05: Weak crypto + WebView JS interface
>
> \$ python3 poc_05_crypto_webview.py \\
>
> --smali "\$DECOMP/smali" \\
>
> --out poc05_results.json

**3.2 Full Suite — One Command**

> \$ cd "\$POC"
>
> \$ python3 run_all_pocs.py \\
>
> --apk "\$APKM/base.apk" \\
>
> --smali "\$DECOMP/smali" \\
>
> --manifest "\$DECOMP/AndroidManifest.xml" \\
>
> --nsc "\$DECOMP/res/xml/network_security_config.xml" \\
>
> --out line_audit_summary.json
>
> \# View summary:
>
> \$ python3 -c "
>
> import json
>
> d = json.load(open('line_audit_summary.json'))
>
> for r in d.get('results', \[\]):
>
> print(f\\\[{r.get('severity','?')}\] {r.get('name','?')}\\)
>
> "

**4. APKTool — Smali Analysis Commands**

Run these after APKTool decompilation completes.

**4.1 Key Smali Grep Commands**

> \# ── SharedPreferences insecure writes ───────────────────────────
>
> \$ grep -rn 'putString\\putInt\\putLong' \\
>
> "\$DECOMP/smali"/ \\
>
> \| grep -v 'EncryptedSharedPreferences' \| head -30
>
> \# ── Check if EncryptedSharedPreferences is used at all ───────────
>
> \$ grep -rn 'EncryptedSharedPreferences\\MasterKey' \\
>
> "\$DECOMP"/smali\*/
>
> \# ── Weak cryptography ────────────────────────────────────────────
>
> \$ grep -rn '"MD5"\\"SHA-1"\\"DES"\\"RC4"\\"AES/ECB"' \\
>
> "\$DECOMP"/smali\*/
>
> \# ── WebView JavaScript interface ─────────────────────────────────
>
> \$ grep -rn 'addJavascriptInterface\\setJavaScriptEnabled' \\
>
> "\$DECOMP"/smali\*/
>
> \# ── Hardcoded strings sweep ──────────────────────────────────────
>
> \$ grep -rn 'const-string' "\$DECOMP"/smali\*/ \\
>
> \| grep -iE 'secret\|password\|token\|apikey\|bearer\|oauth' \\
>
> \| grep -v 'test\\example\\dummy' \| head -40
>
> \# ── Sensitive logging ─────────────────────────────────────────────
>
> \$ grep -rn 'Log\\d\\Log\\v\\Log\\e' "\$DECOMP"/smali\*/ \\
>
> \| grep -iE 'token\|user\|pass\|mid\|session\|auth' \| head -20

**4.2 AndroidManifest.xml Analysis**

> \# ── Exported components ──────────────────────────────────────────
>
> \$ grep -n 'exported="true"' "\$DECOMP/AndroidManifest.xml"
>
> \# ── Deep link URI schemes ────────────────────────────────────────
>
> \$ grep -n 'android:scheme' "\$DECOMP/AndroidManifest.xml"
>
> \# ── Security flags ───────────────────────────────────────────────
>
> \$ grep -E
> 'allowBackup\|debuggable\|networkSecurityConfig\|usesCleartextTraffic'
> \\
>
> "\$DECOMP/AndroidManifest.xml"

**5. Frida — Dynamic Analysis**

**5.1 Frida Already Installed**

> \# Frida 17.7.3 installed at:
>
> \$ which frida
>
> =\> /home/deepquest/.local/bin/frida
>
> \# Verify all tools available:
>
> \$ frida --version \# 17.7.3
>
> \$ frida-ps --version
>
> \$ frida-ls-devices

**5.2 Push Frida Server to Test Device**

> **⚠ NOTE:** Use a dedicated test device. Never perform dynamic
> analysis on a personal phone.
>
> \# Check device connected
>
> \$ adb devices
>
> \# Get architecture
>
> \$ adb shell getprop ro.product.cpu.abi
>
> =\> arm64-v8a
>
> \# Download matching frida-server (must match frida-tools version
> 17.7.3)
>
> \$ wget
> https://github.com/frida/frida/releases/download/17.7.3/frida-server-17.7.3-android-arm64.xz
>
> \$ unxz frida-server-17.7.3-android-arm64.xz
>
> \# Push to device (requires root)
>
> \$ adb push frida-server-17.7.3-android-arm64
> /data/local/tmp/frida-server
>
> \$ adb shell chmod 755 /data/local/tmp/frida-server
>
> \$ adb shell su -c '/data/local/tmp/frida-server &'
>
> \# Verify
>
> \$ frida-ps -U \| grep -i line
>
> =\> 12345 jp.naver.line.android

**5.3 Apply Certificate Pinning Bypass**

> \# ssl_bypass.js is generated by poc_03_cert_pinning.py
>
> \# after running PoC-03, the file will be at:
>
> \$ ls "\$POC/ssl_bypass.js"
>
> \# Spawn LINE with pinning bypass:
>
> \$ frida -U \\
>
> -f jp.naver.line.android \\
>
> -l "\$POC/ssl_bypass.js" \\
>
> --no-pause
>
> \# Or attach to running process:
>
> \$ frida -U \\
>
> --attach-name jp.naver.line.android \\
>
> -l "\$POC/ssl_bypass.js"
>
> \# Alternative — objection (install if needed):
>
> \$ pip3 install objection --break-system-packages
>
> \$ objection -g jp.naver.line.android explore
>
> objection\> android sslpinning disable

**6. Ghidra — macOS GUI Analysis**

After fixing permissions on macOS (chmod +x + xattr -cr), the decompiler
is working. Use macOS Ghidra for all decompiler work.

**6.1 Fixed Permission Commands (Already Applied)**

> \# Commands already run on macOS to fix Ghidra:
>
> \$ find "/Users/adf/Downloads/GhidraMacOS/ghidra_install/Ghidra.app"
> \\
>
> -type f -perm -u=r ! -perm -u=x -print0 \| xargs -0 chmod +x
>
> \$ xattr -cr
> "/Users/adf/Downloads/GhidraMacOS/ghidra_install/Ghidra.app"
>
> \# Decompiler binary confirmed executable:
>
> \# -rwxr-xr-x decompile (3,172,616 bytes)

**6.2 Priority Libraries for Ghidra Analysis**

> \# macOS native libs path:
>
> \# /Users/adf/Documents/cod3z/Line audit/Line
> 26.1.1/native/lib/arm64-v8a/
>
> \# Priority order for Ghidra import:
>
> \# 1. liblegy.so (249KB) — LINE Edge Gateway, auth logic
>
> \# 2. libmm.so (1.8MB) — Message Manager, E2E crypto
>
> \# 3. libssl3line.so (587KB) — Custom TLS, cert pinning
>
> \# 4. libsentry.so — Crash reporting, DSN secret
>
> \# 5. liblinejnihelper.so — JNI bridge to Java layer
>
> \# After importing each lib in Ghidra GUI:
>
> \# Window → Symbol Table → filter: Java\_
>
> \# Window → Symbol Table → filter: JNI_OnLoad
>
> \# Search → For Strings → filter: auth, token, key, secret
>
> \# Search → For Strings → filter: sentry.io, https://

**7. Results So Far & Next Actions**

**7.1 P0 Native Scan Results — Completed**

All 6 findings from the P0 scan were false positives:

|                                        |                                                                    |
|----------------------------------------|--------------------------------------------------------------------|
| **libsqlcipher.so — build hash**       | FALSE POSITIVE — SQLite/FTS5 compilation fingerprint (date + hash) |
| **libsqlcipher.so — 0123456789ABCDEF** | FALSE POSITIVE — Hex encoding lookup table / test vector           |
| **libsqlcipher.so — REINDEXESCAPE...** | FALSE POSITIVE — SQLite packed keyword trie (parser table)         |
| **libmm.so — 000102030405...**         | FALSE POSITIVE — NIST sequential byte test vector (entropy 3.3)    |
| **libssl3line.so**                     | CLEAN — No secrets found in .rodata                                |
| **liblegy.so**                         | CLEAN — Strings may be runtime-assembled (check in Ghidra)         |

**7.2 Immediate Next Actions**

> \# 1. Sentry DSN — run this RIGHT NOW (30 seconds):
>
> \$ strings "\$LIBS/libsentry.so" "\$LIBS/libsentry-android.so" \\
>
> \| grep -E "https://\[0-9a-f\]{32}@"
>
> \# 2. All internal URLs sweep:
>
> \$ strings "\$LIBS/"\*.so \\
>
> \| grep -E "https?://\[a-z0-9-\]+\\(line\|naver)" \| sort -u
>
> \# 3. Once APKTool done — run full suite:
>
> \$ python3 "\$POC/run_all_pocs.py" \\
>
> --apk "\$APKM/base.apk" \\
>
> --smali "\$DECOMP/smali" \\
>
> --manifest "\$DECOMP/AndroidManifest.xml" \\
>
> --nsc "\$DECOMP/res/xml/network_security_config.xml" \\
>
> --out "\$POC/line_audit_summary.json"
>
> \# 4. P1 native scan:
>
> \$ python3 "\$POC/analyze_line_natives.py" \\
>
> --libs-dir "\$LIBS" --tier P1 --out "\$POC/line_natives_P1.json"
>
> \# 5. In Ghidra (macOS) — import liblegy.so
>
> \# Symbol Table → JNI_OnLoad → decompile → look for
>
> \# XOR loops or char-by-char string construction

*EDUCATIONAL PURPOSE ONLY — For authorized security research only.
Unauthorized analysis may violate applicable computer crime laws.*
