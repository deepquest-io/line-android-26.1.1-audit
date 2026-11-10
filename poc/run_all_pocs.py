#!/usr/bin/env python3
"""
================================================================================
LINE Android App — Security Audit PoC Suite
================================================================================
Master runner that orchestrates all 5 proof-of-concept scripts.

PoC-01 | CRITICAL | Hardcoded API Keys & Secrets in Native Libraries
PoC-02 | HIGH     | Insecure SharedPreferences Plaintext Storage
PoC-03 | HIGH     | Insufficient Certificate Pinning
PoC-04 | HIGH     | Exported Activity / Deep Link Hijacking
PoC-05 | HIGH     | Weak Cryptography + WebView JS Interface Exposure

Usage:
  # Demo mode (no APK required — shows simulated findings):
  python run_all_pocs.py --demo

  # Full analysis against a real APK:
  python run_all_pocs.py --apk /path/to/line.apk --smali /path/to/line_decompiled

  # Individual PoCs:
  python run_all_pocs.py --demo --poc 1
  python run_all_pocs.py --demo --poc 3

EDUCATIONAL PURPOSE ONLY — Use only on applications you own or have
explicit written authorization to test.
Version       : 1.1  (March 2026)
Author        : deepquest
Blog          : https://deepquest.code511.com/blog/
Target App    : jp.naver.line.android v26.1.1 (260110123)
Note          : Master runner for all 5 PoC scripts — updated paths for LINE 26.1.1 bundle
================================================================================
"""

import sys
import os
import json
import time
import argparse
import subprocess
from pathlib import Path
from datetime import datetime

BANNER = r"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    LINE Android — Security Audit PoC Suite                                   ║
║    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━                                     ║
║                                                                              ║
║    PoC-01 CRITICAL  Hardcoded Secrets in Native Libraries     CVSS 9.1       ║
║    PoC-02 HIGH      Insecure SharedPreferences Storage        CVSS 7.5       ║
║    PoC-03 HIGH      Certificate Pinning Bypass                CVSS 7.4       ║
║    PoC-04 HIGH      Exported Activity / Deep Link Hijack      CVSS 7.3       ║
║    PoC-05 HIGH      Weak Crypto + WebView JS Interface        CVSS 7.0       ║
║                                                                              ║
║    EDUCATIONAL PURPOSE ONLY                                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

POC_SCRIPTS = {
    1: {"file": "poc_01_hardcoded_secrets.py", "name": "Hardcoded Secrets",          "severity": "CRITICAL"},
    2: {"file": "poc_02_insecure_storage.py",  "name": "Insecure SharedPreferences", "severity": "HIGH"},
    3: {"file": "poc_03_cert_pinning.py",       "name": "Certificate Pinning",        "severity": "HIGH"},
    4: {"file": "poc_04_exported_activities.py","name": "Exported Activities",        "severity": "HIGH"},
    5: {"file": "poc_05_crypto_webview.py",     "name": "Weak Crypto + WebView",      "severity": "HIGH"},
}

SEV_COLORS = {
    "CRITICAL": "\033[91m",  # Red
    "HIGH":     "\033[93m",  # Yellow
    "MEDIUM":   "\033[94m",  # Blue
    "LOW":      "\033[92m",  # Green
    "RESET":    "\033[0m",
}


def color(text: str, sev: str) -> str:
    return f"{SEV_COLORS.get(sev, '')}{text}{SEV_COLORS['RESET']}"


def run_poc(poc_num: int, args: argparse.Namespace) -> dict:
    """Run a single PoC script and return its result summary."""
    poc = POC_SCRIPTS[poc_num]
    script_path = Path(__file__).parent / poc["file"]

    if not script_path.exists():
        return {"poc": poc_num, "name": poc["name"], "severity": poc["severity"],
                "status": "MISSING", "elapsed": 0.0, "error": f"Script not found: {script_path}"}

    print(f"\n{'═'*72}")
    print(f"  Running PoC-{poc_num:02d} | {color(poc['severity'], poc['severity'])} | {poc['name']}")
    print(f"{'═'*72}")

    cmd = [sys.executable, str(script_path)]

    if args.demo:
        cmd.append("--demo")
    else:
        if poc_num == 1 and args.apk:
            cmd += ["--apk", args.apk]
        elif poc_num == 2 and args.smali:
            cmd += ["--smali", args.smali]
        elif poc_num == 3:
            if args.nsc:
                cmd += ["--nsc", args.nsc]
            if args.smali:
                cmd += ["--smali", args.smali]
            if args.verify_certs:
                cmd += ["--verify"]
            cmd += ["--gen-frida"]
        elif poc_num == 4:
            if args.manifest:
                cmd += ["--manifest", args.manifest]
            else:
                cmd += ["--demo"]
        elif poc_num == 5:
            if args.smali:
                cmd += ["--smali", args.smali]
            else:
                cmd += ["--demo"]

    start = time.time()
    try:
        result = subprocess.run(cmd, capture_output=False, text=True, timeout=120)
        elapsed = time.time() - start
        status = "COMPLETED" if result.returncode == 0 else "ERROR"
    except subprocess.TimeoutExpired:
        elapsed = 120
        status = "TIMEOUT"
    except Exception:
        elapsed = time.time() - start
        status = "EXCEPTION"

    return {
        "poc":      poc_num,
        "name":     poc["name"],
        "severity": poc["severity"],
        "status":   status,
        "elapsed":  round(elapsed, 2),
    }


def print_final_summary(results: list[dict], start_time: float):
    """Print a formatted summary table of all PoC results."""
    total_time = round(time.time() - start_time, 2)

    print(f"\n\n{'═'*72}")
    print("  FINAL AUDIT SUMMARY")
    print(f"{'═'*72}")
    print(f"  {'PoC':<8} {'Severity':<12} {'Name':<35} {'Status':<12} {'Time':>6}")
    print(f"  {'─'*8} {'─'*12} {'─'*35} {'─'*12} {'─'*6}")

    for r in results:
        status_color = "\033[92m" if r["status"] == "COMPLETED" else "\033[91m"
        sev_str = color(r["severity"], r["severity"])
        print(f"  PoC-{r['poc']:02d}   {sev_str:<22} {r['name']:<35} "
              f"{status_color}{r['status']:<12}\033[0m {r['elapsed']:>5}s")

    print(f"\n  Total runtime  : {total_time}s")
    print(f"  PoCs run       : {len(results)}")
    print(f"  Completed      : {sum(1 for r in results if r['status'] == 'COMPLETED')}")
    print()

    print("─" * 72)
    print("  VULNERABILITY MATRIX")
    print("─" * 72)
    matrix = [
        ("F-01", "CRITICAL", "9.1", "Hardcoded API keys in libline.so .rodata",            "PoC-01"),
        ("F-02", "HIGH",     "7.5", "SharedPreferences tokens in plaintext XML",           "PoC-02"),
        ("F-03", "HIGH",     "7.4", "Missing cert pins for 6/8 LINE API domains",          "PoC-03"),
        ("F-04", "HIGH",     "7.3", "DeepLinkHandlerActivity + OAuthCallback unprotected", "PoC-04"),
        ("F-05", "HIGH",     "7.0", "MD5 + AES-ECB + static IV in EncryptionUtil",         "PoC-05"),
        ("F-06", "HIGH",     "6.8", "addJavascriptInterface exposes bridge to MiniApps",   "PoC-05"),
    ]
    print(f"  {'ID':<6} {'Sev':<10} {'CVSS':<6} {'Description':<44} {'PoC':<6}")
    print(f"  {'─'*6} {'─'*10} {'─'*6} {'─'*44} {'─'*6}")
    for row in matrix:
        fid, sev, cvss, desc, poc = row
        print(f"  {fid:<6} {color(sev, sev):<22} {cvss:<6} {desc:<44} {poc:<6}")

    print("\n" + "─" * 72)
    print("  NEXT STEPS")
    print("─" * 72)
    print("""
  1. Acquire the LINE APK:
       adb shell pm path jp.naver.line.android
       adb pull /data/app/jp.naver.line.android-<hash>/base.apk line.apk

  2. Decompile with APKTool:
       apktool d line.apk -o line_decompiled/

  3. Run full suite against real APK:
       python run_all_pocs.py \\
         --apk     line.apk \\
         --smali   line_decompiled/smali \\
         --manifest line_decompiled/AndroidManifest.xml \\
         --nsc     line_decompiled/res/xml/network_security_config.xml

  4. For dynamic analysis — install Frida server on test device:
       adb push frida-server /data/local/tmp/
       adb shell chmod 755 /data/local/tmp/frida-server
       adb shell /data/local/tmp/frida-server &
       frida -U -f jp.naver.line.android -l ssl_bypass.js --no-pause

  5. Route device traffic through Burp Suite (port 8080) to capture 
     decrypted API calls after pinning bypass.
""")


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="LINE Android App — Security Audit PoC Suite Master Runner"
    )
    parser.add_argument("--apk",          help="Path to LINE APK file")
    parser.add_argument("--smali",        help="Path to decompiled Smali directory")
    parser.add_argument("--manifest",     help="Path to AndroidManifest.xml")
    parser.add_argument("--nsc",          help="Path to network_security_config.xml")
    parser.add_argument("--prefs-dir",    help="Directory with extracted SharedPreferences XMLs")
    parser.add_argument("--verify-certs", action="store_true", help="Live-verify LINE domain certificates")
    parser.add_argument("--poc",          type=int, choices=[1,2,3,4,5], help="Run only a specific PoC")
    parser.add_argument("--demo",         action="store_true", help="Run in demo mode (no APK required)")
    parser.add_argument("--out",          default="audit_summary.json", help="Output JSON summary")
    args = parser.parse_args()

    if not args.demo and not any([args.apk, args.smali, args.manifest]):
        print("  [*] No APK or Smali path provided — running in DEMO mode.\n")
        args.demo = True

    poc_list = [args.poc] if args.poc else list(POC_SCRIPTS.keys())
    results  = []
    start    = time.time()

    for poc_num in poc_list:
        result = run_poc(poc_num, args)
        results.append(result)

    print_final_summary(results, start)

    with open(args.out, "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "target":    "jp.naver.line.android",
            "mode":      "demo" if args.demo else "live",
            "results":   results,
        }, f, indent=2)
    print(f"  Summary saved: {args.out}\n")


if __name__ == "__main__":
    main()
