#!/usr/bin/env python3
"""
================================================================================
PoC-01 | Hardcoded API Keys & Secrets in Native Libraries
================================================================================
Vulnerability : CWE-798 — Use of Hard-coded Credentials
Severity      : CRITICAL | CVSS 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
Target        : lib/arm64-v8a/*.so — confirmed: libDeepLingoKit.so (F-04), native libs (F-05)
                split_config.arm64_v8a.apk from LINE 26.1.1 .apkm bundle
                Note: LINE 26.1.1 has NO libline.so — key libs are liblegy.so,
                libmm.so, libssl3line.so, libsentry.so, libDeepLingoKit.so
Tools chain   : Python zipfile + struct + regex (mirrors what Ghidra/strings does)

EDUCATIONAL PURPOSE ONLY — Do not use against apps you do not own or have
explicit written authorization to test.
Version       : 1.1  (March 2026)
Author        : deepquest
Blog          : https://deepquest.code511.com/blog/
Target App    : jp.naver.line.android v26.1.1 (260110123)
Note          : Updated: real lib names, 8 LINE-specific patterns, real demo data (F-04, F-05)
================================================================================
"""

import sys
import os
import re
import math
import zipfile
import struct
import json
import argparse
from pathlib import Path
from collections import defaultdict

BANNER = r"""
 ____  ___   ____      ___  _
|  _ \/ _ \ / ___|    / _ \/ |
| |_) | | | | |      | | | | |
|  __/| |_| | |___   | |_| | |
|_|    \___/ \____|   \___/|_|

  Hardcoded Secrets Extractor — Native Library Scanner
  CWE-798 | CVSS 9.1 | CRITICAL
"""

# ─── Regex patterns for common secret formats ────────────────────────────────
SECRET_PATTERNS = {
    "AWS_Access_Key":        r"AKIA[0-9A-Z]{16}",
    "AWS_Secret_Key":        r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "GCP_API_Key":           r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase_URL":          r"https://[a-z0-9-]+\.firebaseio\.com",
    "Firebase_Key":          r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "JWT_Token":             r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+",
    "Generic_OAuth_Token":   r"(?i)(oauth|access)[_-]?token[\s\"']*[:=][\s\"']*([A-Za-z0-9_\-\.]{20,})",
    "Bearer_Token":          r"[Bb]earer\s+[A-Za-z0-9\-_\.=]{20,}",
    "Private_Key_Header":    r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "Generic_API_Key":       r"(?i)api[_-]?key[\s\"']*[:=][\s\"']*['\"]?([A-Za-z0-9_\-]{16,})['\"]?",
    "Generic_Secret":        r"(?i)secret[\s\"']*[:=][\s\"']*['\"]?([A-Za-z0-9_\-\/\+]{16,})['\"]?",
    "Password_String":       r"(?i)password[\s\"']*[:=][\s\"']*['\"]?([^\s'\"]{8,})['\"]?",
    "IP_Address_Internal":   r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
    "URL_HTTP":              r"https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s\"'<>]*)?",
    "Base64_High_Entropy":   r"(?:[A-Za-z0-9+/]{40,}={0,2})",
    "Hex_Key_32bytes":       r"\b[0-9a-fA-F]{64}\b",
    "SQLCipher_Key":         r"(?i)PRAGMA\s+key\s*=\s*['\"]([^'\"]+)['\"]",
    # ── LINE-specific patterns (from LINE 26.1.1 static analysis) ────────────
    "Sentry_DSN":            r"https://[0-9a-f]{32}@[a-z0-9.]+/\d+",
    "LINE_Channel_Token":    r"(?i)(channel.?access.?token|DLK_.*token)['\"\s:=]+([A-Za-z0-9+/=]{32,})",
    "LINE_Legy_Endpoint":    r"https?://legy[a-z0-9._-]*\.line[a-z0-9._-]*\.(?:com|net|jp)",
    "LINE_AST_Gateway":      r"https://ast[a-z0-9._-]*\.line-apps\.com",
    "LINE_Internal_URL":     r"https?://[a-z0-9._-]+\.line-apps(?:-(?:alpha|beta|rc|dev))?\.com",
    "LINE_Staging_Domain":   r"legy-(?:beta|rc|rc2)[a-z0-9._-]*\.line-apps-(?:beta|rc|alpha)\.com",
    "JWT_Prefixed":          r"[A-Za-z0-9+/]{20,}eyJ[A-Za-z0-9_-]{10,}",  # obfuscated JWT (F-05)
    "GCP_Project_ID":        r"projects/[a-z][a-z0-9_-]+-(?:dev|staging|prod|beta|rc)\b",
}

# Known MD5 init constants (detect weak crypto in .text section)
MD5_INIT_BYTES  = bytes([0x01, 0x23, 0x45, 0x67])  # 0x67452301 little-endian
SHA1_INIT_BYTES = bytes([0x67, 0x45, 0x23, 0x01])   # SHA-1 first constant


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def extract_printable_strings(data: bytes, min_len: int = 6) -> list[tuple[int, str]]:
    """
    Extract ASCII printable strings from binary data (like 'strings' command).
    Returns list of (offset, string) tuples.
    """
    results = []
    pattern = re.compile(rb"[ -~]{" + str(min_len).encode() + rb",}")
    for match in pattern.finditer(data):
        results.append((match.start(), match.group().decode("ascii", errors="replace")))
    return results


def scan_strings_for_secrets(strings: list[tuple[int, str]]) -> list[dict]:
    """Apply regex patterns to extracted strings and return matches."""
    findings = []
    for offset, s in strings:
        for pattern_name, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, s)
            if matches:
                findings.append({
                    "offset":   hex(offset),
                    "pattern":  pattern_name,
                    "match":    matches[0] if isinstance(matches[0], str) else matches[0][0],
                    "context":  s[:120],
                    "entropy":  round(shannon_entropy(s.encode()), 3),
                })
    return findings


def detect_weak_crypto_constants(data: bytes) -> list[dict]:
    """
    Detect known initialisation constants for broken hash algorithms
    embedded in native binary code sections.
    """
    results = []
    # MD5: init state A = 0x67452301
    md5_const = struct.pack("<I", 0x67452301)
    offset = 0
    while True:
        idx = data.find(md5_const, offset)
        if idx == -1:
            break
        results.append({"algorithm": "MD5", "constant": "0x67452301", "offset": hex(idx)})
        offset = idx + 1

    # SHA-1: init H0 = 0x67452301 (same constant — report both)
    sha1_const = struct.pack("<I", 0x98BADCFE)  # SHA-1 H1
    offset = 0
    while True:
        idx = data.find(sha1_const, offset)
        if idx == -1:
            break
        results.append({"algorithm": "SHA-1", "constant": "0x98BADCFE", "offset": hex(idx)})
        offset = idx + 1

    return results


def parse_elf_sections(data: bytes) -> dict:
    """
    Minimal ELF parser to identify section names and boundaries.
    Supports 32-bit and 64-bit ELF (ARM/ARM64).
    """
    sections = {}
    if len(data) < 16 or data[:4] != b"\x7fELF":
        return sections
    ei_class = data[4]  # 1=32bit, 2=64bit
    try:
        if ei_class == 2:  # 64-bit ELF
            e_shoff   = struct.unpack_from("<Q", data, 0x28)[0]
            e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
            e_shnum     = struct.unpack_from("<H", data, 0x3C)[0]
            e_shstrndx  = struct.unpack_from("<H", data, 0x3E)[0]
            # Get section name string table
            shstr_offset = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]
            for i in range(e_shnum):
                sh_base = e_shoff + i * e_shentsize
                sh_name_off = struct.unpack_from("<I", data, sh_base)[0]
                sh_offset   = struct.unpack_from("<Q", data, sh_base + 0x18)[0]
                sh_size     = struct.unpack_from("<Q", data, sh_base + 0x20)[0]
                # Read name from string table
                name_start = shstr_offset + sh_name_off
                name_end   = data.find(b"\x00", name_start)
                name = data[name_start:name_end].decode("ascii", errors="replace") if name_end != -1 else "?"
                sections[name] = {"offset": sh_offset, "size": sh_size}
    except (struct.error, IndexError):
        pass
    return sections


def analyze_library(lib_data: bytes, lib_name: str) -> dict:
    """Full analysis pipeline for a single .so library."""
    print(f"\n  [*] Analyzing: {lib_name} ({len(lib_data):,} bytes)")

    result = {
        "library":      lib_name,
        "size":         len(lib_data),
        "is_elf":       lib_data[:4] == b"\x7fELF",
        "sections":     {},
        "secrets":      [],
        "weak_crypto":  [],
        "high_entropy_blobs": [],
    }

    # Parse ELF sections
    sections = parse_elf_sections(lib_data)
    result["sections"] = {k: v for k, v in sections.items() if v["size"] > 0}
    print(f"  [*] ELF sections found: {list(result['sections'].keys())}")

    # Extract strings and scan for secrets (focus on .rodata if available)
    if ".rodata" in sections and sections[".rodata"]["size"] > 0:
        off = sections[".rodata"]["offset"]
        sz  = sections[".rodata"]["size"]
        rodata = lib_data[off:off+sz]
        print(f"  [*] Scanning .rodata section ({sz:,} bytes) for secrets...")
        strings = extract_printable_strings(rodata, min_len=8)
    else:
        print(f"  [*] No .rodata section — scanning full binary...")
        strings = extract_printable_strings(lib_data, min_len=10)

    result["secrets"] = scan_strings_for_secrets(strings)

    # Detect weak crypto constants in .text section
    if ".text" in sections and sections[".text"]["size"] > 0:
        off = sections[".text"]["offset"]
        sz  = sections[".text"]["size"]
        text_data = lib_data[off:off+sz]
        result["weak_crypto"] = detect_weak_crypto_constants(text_data)

    # Find high-entropy 32-byte blobs (possible hardcoded keys)
    chunk_size = 32
    for i in range(0, min(len(lib_data), 2_000_000), chunk_size):
        chunk = lib_data[i:i+chunk_size]
        if len(chunk) == chunk_size:
            entropy = shannon_entropy(chunk)
            if entropy > 7.2:  # High entropy threshold — likely encrypted/key material
                result["high_entropy_blobs"].append({
                    "offset":  hex(i),
                    "entropy": round(entropy, 3),
                    "hex":     chunk.hex()[:64] + "...",
                })
    # Keep only top 10 highest entropy blobs
    result["high_entropy_blobs"] = sorted(
        result["high_entropy_blobs"], key=lambda x: x["entropy"], reverse=True
    )[:10]

    return result


def scan_apk(apk_path: str) -> dict:
    """Extract and analyze all native libraries from an APK file."""
    report = {
        "apk": apk_path,
        "libraries_analyzed": [],
        "total_secrets": 0,
        "total_weak_crypto": 0,
    }

    print(f"\n[+] Opening APK: {apk_path}")
    with zipfile.ZipFile(apk_path, "r") as zf:
        native_libs = [
            name for name in zf.namelist()
            if name.startswith("lib/") and name.endswith(".so")
        ]
        print(f"[+] Found {len(native_libs)} native library/libraries:")
        for lib in native_libs:
            print(f"    - {lib}")

        for lib_path in native_libs:
            lib_data = zf.read(lib_path)
            lib_result = analyze_library(lib_data, lib_path)
            report["libraries_analyzed"].append(lib_result)
            report["total_secrets"]     += len(lib_result["secrets"])
            report["total_weak_crypto"] += len(lib_result["weak_crypto"])

    return report


def print_report(report: dict):
    """Pretty-print the analysis report to stdout."""
    print("\n" + "=" * 72)
    print("  SCAN RESULTS SUMMARY")
    print("=" * 72)
    print(f"  APK              : {report['apk']}")
    print(f"  Libraries scanned: {len(report['libraries_analyzed'])}")
    print(f"  Secrets found    : {report['total_secrets']}")
    print(f"  Weak crypto hits : {report['total_weak_crypto']}")
    print("=" * 72)

    for lib in report["libraries_analyzed"]:
        print(f"\n  {'─'*66}")
        print(f"  LIBRARY: {lib['library']}")
        print(f"  {'─'*66}")

        if lib["secrets"]:
            print(f"\n  [!] SECRETS ({len(lib['secrets'])} found):")
            for s in lib["secrets"]:
                print(f"      Pattern  : {s['pattern']}")
                print(f"      Offset   : {s['offset']}")
                print(f"      Match    : {s['match'][:80]}{'...' if len(s['match']) > 80 else ''}")
                print(f"      Entropy  : {s['entropy']}")
                print(f"      Context  : {s['context'][:80]}")
                print()
        else:
            print("  [✓] No secrets pattern matches found.")

        if lib["weak_crypto"]:
            print(f"\n  [!] WEAK CRYPTO CONSTANTS ({len(lib['weak_crypto'])} found):")
            for wc in lib["weak_crypto"]:
                print(f"      Algorithm: {wc['algorithm']}  Constant: {wc['constant']}  Offset: {wc['offset']}")

        if lib["high_entropy_blobs"]:
            print(f"\n  [!] HIGH-ENTROPY BLOBS (top {len(lib['high_entropy_blobs'])}, potential key material):")
            for blob in lib["high_entropy_blobs"][:3]:
                print(f"      Offset: {blob['offset']}  Entropy: {blob['entropy']}  Bytes: {blob['hex']}")


def demo_mode():
    """
    Demo mode: simulate analysis results when no APK is provided.
    Shows exactly what real output would look like.
    """
    print("\n[DEMO MODE] — Simulating scan of jp.naver.line.android APK")
    print("           Run with --apk <path_to_line.apk> for real analysis.\n")

    # Demo data reflects REAL findings from LINE 26.1.1 static analysis (Feb-Mar 2026)
    demo_report = {
        "apk": "jp.naver.line.android_26.1.1 — split_config.arm64_v8a.apk (DEMO/REAL DATA)",
        "libraries_analyzed": [
            {
                # ── F-04: Hardcoded AI endpoints ────────────────────────────
                "library": "lib/arm64-v8a/libDeepLingoKit.so",
                "size": 2_847_392,
                "is_elf": True,
                "finding": "F-04 (HIGH) — Hardcoded internal AI infrastructure endpoints",
                "sections": {
                    ".text":   {"offset": 0x1000,   "size": 1_200_000},
                    ".rodata": {"offset": 0x140000,  "size": 480_000},
                    ".data":   {"offset": 0x1C0000,  "size": 92_000},
                },
                "secrets": [
                    {
                        "offset":  "0x14a230",
                        "pattern": "LINE_AST_Gateway",
                        "match":   "https://ast.line-apps.com/v1/projects/yj-scoutbeta2-dev/locations/global/publishers/google/models",
                        "context": "\"gemini.vertex.gateway.baseURL\": \"https://ast.line-apps.com/v1/projects/yj-scoutbeta2-dev/...\"",
                        "entropy": 4.312,
                        "severity": "HIGH",
                        "notes": "Internal Vertex AI/Gemini gateway. Exposes GCP project ID 'yj-scoutbeta2-dev' (dev environment). See F-04.",
                    },
                    {
                        "offset":  "0x14a890",
                        "pattern": "LINE_Internal_URL",
                        "match":   "https://ast-tts.line-apps.com",
                        "context": "\"openai.baseURL\": \"https://ast-tts.line-apps.com\"",
                        "entropy": 3.814,
                        "severity": "HIGH",
                        "notes": "Internal OpenAI-compatible TTS endpoint hardcoded. Paired with DLK_SetChannelAccessToken function. See F-04.",
                    },
                    {
                        "offset":  "0x14c100",
                        "pattern": "GCP_Project_ID",
                        "match":   "projects/yj-scoutbeta2-dev",
                        "context": "https://ast.line-apps.com/v1/projects/yj-scoutbeta2-dev/locations/global/...",
                        "entropy": 3.521,
                        "severity": "MEDIUM",
                        "notes": "GCP project name 'yj-scoutbeta2-dev' indicates dev/beta project in production binary. See F-04.",
                    },
                ],
                "weak_crypto": [],
                "high_entropy_blobs": [],
            },
            {
                # ── F-05: JWT-like token ─────────────────────────────────────
                "library": "lib/arm64-v8a/ (multiple libs — source TBD)",
                "size": 0,
                "is_elf": True,
                "finding": "F-05 (HIGH) — JWT-like prefixed token found in native library",
                "sections": {},
                "secrets": [
                    {
                        "offset":  "TBD",
                        "pattern": "JWT_Prefixed",
                        "match":   "DpFrdRbhIfzYJsdHt6bPWHJxfrrhTZVHO8mvbaG0weyJ9rQPOLXiZNwlz6bb65pc",
                        "context": "Found via: strings $LIBS/*.so | grep -E \"eyJ[A-Za-z0-9_-]{10,}\"",
                        "entropy": 5.821,
                        "severity": "HIGH",
                        "notes": "Contains 'eyJ9' = base64url '{\"' — JWT payload boundary. Appears in 2 libraries. Requires further decode. See F-05.",
                    },
                ],
                "weak_crypto": [],
                "high_entropy_blobs": [],
            },
            {
                # ── P0 False Positives documented ────────────────────────────
                "library": "lib/arm64-v8a/libsqlcipher.so",
                "size": 4_218_104,
                "is_elf": True,
                "finding": "FALSE POSITIVE — All hits are SQLite build metadata",
                "sections": {
                    ".text":   {"offset": 0x1000,  "size": 2_800_000},
                    ".rodata": {"offset": 0x2C0000, "size": 620_000},
                },
                "secrets": [
                    {
                        "offset":  "0x2d1a40",
                        "pattern": "Hex_Key_32bytes",
                        "match":   "281fc0e9afc38674...",
                        "context": "2025-11-28 17:28:25 281fc0e9afc38674... (SQLite FTS5 build hash)",
                        "entropy": 4.102,
                        "severity": "FALSE_POSITIVE",
                        "notes": "SQLite/FTS5 compilation fingerprint (timestamp + source tree hash). Not a secret.",
                    },
                    {
                        "offset":  "0x2d2200",
                        "pattern": "Hex_Key_32bytes",
                        "match":   "0123456789ABCDEF0123456789abcdef",
                        "context": "Hex encoding lookup table — sequential characters",
                        "entropy": 4.375,
                        "severity": "FALSE_POSITIVE",
                        "notes": "Hex encoding lookup table. Entropy 4.375, real AES-256 keys score 7.9+.",
                    },
                ],
                "weak_crypto": [],
                "high_entropy_blobs": [],
            },
        ],
        "total_secrets": 3,  # Confirmed findings only (excl. false positives)
        "total_weak_crypto": 0,
        "confirmed_findings": ["F-04", "F-05"],
        "false_positives": 4,
        "pending_analysis": ["Sentry DSN (libsentry.so — not found in native, check Java layer)",
                             "liblegy.so — zero readable strings, requires Ghidra decompiler",
                             "P1 tier scan (libsentry-android.so, libanna_jni.so, libE2EInferenceJNI.so)"],
    }
    print_report(demo_report)
    print("\n[+] Simulated JSON output saved to: line_secrets_demo.json")
    with open("line_secrets_demo.json", "w") as f:
        json.dump(demo_report, f, indent=2)


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="PoC-01: Extract hardcoded secrets from APK native libraries"
    )
    parser.add_argument("--apk",  help="Path to target APK file")
    parser.add_argument("--lib",  help="Path to a single .so library file")
    parser.add_argument("--out",  help="Output JSON report path", default="secrets_report.json")
    parser.add_argument("--demo", action="store_true", help="Run demo mode (no APK required)")
    args = parser.parse_args()

    if args.demo or (not args.apk and not args.lib):
        demo_mode()
        return

    if args.lib:
        lib_data = Path(args.lib).read_bytes()
        result   = analyze_library(lib_data, args.lib)
        report   = {"apk": "N/A", "libraries_analyzed": [result],
                    "total_secrets": len(result["secrets"]),
                    "total_weak_crypto": len(result["weak_crypto"])}
    else:
        report = scan_apk(args.apk)

    print_report(report)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Full JSON report saved to: {args.out}")


if __name__ == "__main__":
    main()
