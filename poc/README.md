# LINE Android — Security Audit PoC Suite
## For Educational Purposes Only

This suite provides proof-of-concept scripts for the **Critical** and **High** severity
vulnerabilities identified during the LINE Android app (jp.naver.line.android) static
security audit.

---

## ⚠️ Legal & Ethical Notice

> These scripts are provided **strictly for educational and authorized security research
> purposes only**. Use only on applications you own or have **explicit written authorization**
> to test. Unauthorized use against third-party applications may violate the Computer Fraud
> and Abuse Act (CFAA), GDPR, and equivalent laws in your jurisdiction.

---

## Vulnerability Coverage

| PoC    | Severity   | CVSS | Vulnerability                           | CWE     |
|--------|------------|------|-----------------------------------------|---------|
| PoC-01 | 🔴 CRITICAL | 9.1  | Hardcoded secrets in native libraries   | CWE-798 |
| PoC-02 | 🟠 HIGH     | 7.5  | Insecure SharedPreferences storage      | CWE-312 |
| PoC-03 | 🟠 HIGH     | 7.4  | Insufficient certificate pinning        | CWE-295 |
| PoC-04 | 🟠 HIGH     | 7.3  | Exported activity / deep link hijacking | CWE-926 |
| PoC-05 | 🟠 HIGH     | 7.0  | Weak cryptography (MD5/AES-ECB)         | CWE-327 |
| PoC-05 | 🟠 HIGH     | 6.8  | WebView JS interface exposure           | CWE-749 |

---

## Quick Start — Demo Mode (No APK Required)

```bash
# Run all PoCs in demo mode (simulated output)
python run_all_pocs.py --demo

# Run a specific PoC in demo mode
python run_all_pocs.py --demo --poc 1
python run_all_pocs.py --demo --poc 3

# Run each PoC individually
python poc_01_hardcoded_secrets.py --demo
python poc_02_insecure_storage.py --demo
python poc_03_cert_pinning.py --demo
python poc_04_exported_activities.py --demo
python poc_05_crypto_webview.py --demo
```

---

## Full Analysis (Real APK)

### Prerequisites

```bash
# Python dependencies
pip3 install frida-tools  # Optional — for dynamic analysis

# External tools needed on your system
# - apktool: https://apktool.org
# - jadx: https://github.com/skylot/jadx (optional, improves decompilation)
# - Ghidra: https://ghidra-sre.org (for native lib analysis)
# - Frida: https://frida.re (for dynamic testing)
```

### Step 1 — Acquire the APK

```bash
# From a connected Android device (USB debugging enabled)
adb shell pm path jp.naver.line.android
# Returns: package:/data/app/jp.naver.line.android-XXXXX/base.apk
adb pull /data/app/jp.naver.line.android-XXXXX/base.apk line.apk
```

### Step 2 — Decompile with APKTool

```bash
apktool d line.apk -o line_decompiled/
```

### Step 3 — Run the Full PoC Suite

```bash
python run_all_pocs.py \
  --apk      line.apk \
  --smali    line_decompiled/smali \
  --manifest line_decompiled/AndroidManifest.xml \
  --nsc      line_decompiled/res/xml/network_security_config.xml
```

### Step 4 — Individual PoC Usage

```bash
# PoC-01: Scan native libraries for hardcoded secrets
python poc_01_hardcoded_secrets.py --apk line.apk --out secrets.json

# Scan a single .so file
python poc_01_hardcoded_secrets.py --lib lib/arm64-v8a/libline.so

# PoC-02: Scan Smali + parse extracted SharedPreferences XMLs
python poc_02_insecure_storage.py --smali line_decompiled/smali
python poc_02_insecure_storage.py --xml auth_prefs.xml

# PoC-03: Analyze pinning config + generate Frida bypass script
python poc_03_cert_pinning.py \
  --nsc   line_decompiled/res/xml/network_security_config.xml \
  --smali line_decompiled/smali \
  --gen-frida
# Output: ssl_bypass.js ready for Frida

# PoC-04: Analyze exported components
python poc_04_exported_activities.py --manifest line_decompiled/AndroidManifest.xml

# PoC-05: Scan for weak crypto + WebView issues
python poc_05_crypto_webview.py --smali line_decompiled/smali
```

---

## Dynamic Testing (After Certificate Pinning Bypass)

```bash
# 1. Install Frida server on test device
adb push frida-server-16.x.x-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c "/data/local/tmp/frida-server &"

# 2. Apply SSL pinning bypass
frida -U -f jp.naver.line.android -l ssl_bypass.js --no-pause

# 3. Configure Burp Suite
#    Proxy > Options > Add listener: 0.0.0.0:8080
#    On device: WiFi Settings > Proxy: <your-machine-ip>:8080

# 4. Intercept and analyze LINE API traffic
```

---

## Output Files

| File                           | Contents                                 |
|-------------------------------|------------------------------------------|
| `secrets_report.json`         | Hardcoded secrets from native libraries  |
| `sharedprefs_report.json`     | Insecure SharedPreferences findings      |
| `pinning_report.json`         | Certificate pinning analysis results     |
| `exported_components_report.json` | Exported component vulnerabilities  |
| `crypto_webview_report.json`  | Weak crypto + WebView findings           |
| `ssl_bypass.js`               | Frida certificate pinning bypass script  |
| `audit_summary.json`          | Master summary from run_all_pocs.py      |
