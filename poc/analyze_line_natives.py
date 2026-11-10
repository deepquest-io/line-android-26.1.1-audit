#!/usr/bin/env python3
"""
================================================================================
LINE Native Library Targeted Analyzer
================================================================================
Tailored for the real LINE 26.1.1 arm64-v8a library set.
Prioritizes high-value targets identified from the library listing.

Usage:
  python3 analyze_line_natives.py --libs-dir /path/to/native/lib/arm64-v8a/
Version       : 1.1  (March 2026)
Author        : deepquest
Blog          : https://deepquest.code511.com/blog/
Target App    : jp.naver.line.android v26.1.1 (260110123)
Note          : LINE-specific native library scanner — P0/P1 tiers, entropy analysis, Ghidra cmd gen
================================================================================
"""

import os, re, sys, math, json, struct, argparse
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from typing import Optional

BANNER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║   LINE 26.1.1 — Targeted Native Library Analyzer                            ║
║   Covers: ssl3line · crypto3line · sqlcipher · legy · mm · linejnihelper    ║
║   + sentry · anna · E2E · cardio (LINE Pay) · Elsa framework                ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# ── Priority tiers ────────────────────────────────────────────────────────────
LIBRARY_TIERS = {
    "P0_CRITICAL": {
        "libs": ["libssl3line.so", "libcrypto3line.so", "libsqlcipher.so",
                 "liblegy.so", "libmm.so"],
        "rationale": {
            "libssl3line.so":    "Custom OpenSSL fork — certificate pinning implementation, TLS stack",
            "libcrypto3line.so": "Custom crypto library — AES/RSA key material, weak algo constants",
            "libsqlcipher.so":   "SQLCipher — database encryption passphrase may be hardcoded",
            "liblegy.so":        "LINE Edge Gateway — auth tokens, API keys, server endpoints",
            "libmm.so":          "Message Manager — message encryption keys, E2E crypto logic",
        }
    },
    "P1_HIGH": {
        "libs": ["liblinejnihelper.so", "libanna_jni.so", "libsentry.so",
                 "libsentry-android.so", "libE2EInferenceJNI.so",
                 "libcardioRecognizer.so", "libDeepLingoKit.so"],
        "rationale": {
            "liblinejnihelper.so":  "JNI bridge — Java↔Native interface, access to SharedPreferences",
            "libanna_jni.so":       "Internal service (Anna) — possible hardcoded service credentials",
            "libsentry.so":         "Sentry crash reporting — DSN URL contains secret token",
            "libsentry-android.so": "Sentry Android SDK — same DSN exposure risk",
            "libE2EInferenceJNI.so":"End-to-end encryption inference — key derivation material",
            "libcardioRecognizer.so":"LINE Pay card scanner — financial component, payment API keys",
            "libDeepLingoKit.so":   "Translation/NLP service — external API keys (DeepL, Google NLP?)",
        }
    },
    "P2_MEDIUM": {
        "libs": ["libElsaEngine.so", "libElsaService.so", "libElsaWeb.so",
                 "libElsaFile.so", "libYFLKit-jni.so", "libOlafKit.so",
                 "libaesgcmsiv_jni.so", "libllvmliveness.so", "libssid_liveness_jni.so"],
        "rationale": {
            "libElsaEngine.so":     "Core Elsa framework — central orchestration, possible config secrets",
            "libElsaService.so":    "Elsa service layer — inter-service auth tokens",
            "libElsaWeb.so":        "Elsa web component — internal API endpoints",
            "libElsaFile.so":       "Elsa file handling — encryption keys for file storage",
            "libYFLKit-jni.so":     "Unknown component (YFL) — worth scanning for secrets",
            "libOlafKit.so":        "Unknown component (Olaf) — worth scanning for secrets",
            "libaesgcmsiv_jni.so":  "AES-GCM-SIV JNI — check for hardcoded IVs or keys",
            "libllvmliveness.so":   "Liveness detection — biometric API keys",
            "libssid_liveness_jni.so": "SSID liveness JNI — network-based liveness check",
        }
    },
}

# ── Secret patterns tuned for LINE's ecosystem ───────────────────────────────
PATTERNS = {
    # LINE-specific
    "LINE_Channel_Token":   r"[A-Za-z0-9+/]{100,}={0,2}",          # Long b64 = LINE channel token
    "LINE_Channel_Secret":  r"[a-f0-9]{32}",                         # 32-char hex = channel secret
    "LINE_Legy_Key":        r"(?i)legy[_\-]?key\s*[:=]\s*([^\s]{16,})",
    "SQLCipher_Passphrase": r"(?i)PRAGMA\s+key\s*=\s*['\"]([^'\"]+)['\"]",
    "SQLCipher_Raw_Key":    r"x'[0-9a-fA-F]{64}'",                   # Raw hex key for SQLCipher
    # Sentry DSN — contains secret
    "Sentry_DSN":           r"https://[0-9a-f]{32}@[a-z0-9.]+/\d+",
    # Generic secrets
    "GCP_API_Key":          r"AIza[0-9A-Za-z\-_]{35}",
    "AWS_Access_Key":       r"AKIA[0-9A-Z]{16}",
    "Firebase_URL":         r"https://[a-z0-9\-]+\.firebaseio\.com",
    "Firebase_Key":         r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "JWT_Token":            r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]{10,}",
    "Bearer_Token":         r"[Bb]earer\s+[A-Za-z0-9\-_\.=]{20,}",
    "Private_Key_PEM":      r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "Generic_Secret":       r"(?i)(?:secret|api.?key|auth.?token|client.?secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\/\+\.]{16,})['\"]?",
    "Generic_Password":     r"(?i)(?:password|passwd|passphrase)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?",
    "Internal_URL":         r"https?://[a-z0-9\-]+\.(?:line-apps|line\.me|naver\.com|line\.naver\.jp)[^\s'\"<>]*",
    "Staging_URL":          r"https?://(?:stg|dev|staging|internal|test)[a-z0-9\-\.]+\.[a-z]{2,}[^\s'\"<>]*",
    "IP_Internal":          r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
    "Hex_Key_128bit":       r"\b[0-9a-fA-F]{32}\b",
    "Hex_Key_256bit":       r"\b[0-9a-fA-F]{64}\b",
}

# Weak crypto init constants (search in .text)
CRYPTO_CONSTANTS = {
    "MD5_A":   (0x67452301, "MD5 init constant A — MD5 implementation detected"),
    "MD5_B":   (0xEFCDAB89, "MD5 init constant B"),
    "SHA1_H0": (0x67452301, "SHA-1 H0 constant (same as MD5 A — context matters)"),
    "SHA1_H4": (0xC3D2E1F0, "SHA-1 H4 constant — SHA-1 implementation detected"),
    "DES_S1":  (0x01010400, "DES S-box constant — DES implementation detected"),
    "RC4_ID":  (0x00000100, "RC4 key schedule size — possible RC4 implementation"),
}


def shannon_entropy(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    ln = len(data)
    return -sum((c/ln) * math.log2(c/ln) for c in freq.values() if c)


def extract_strings(data: bytes, min_len: int = 8) -> list[tuple[int, str]]:
    results = []
    pat = re.compile(rb"[ -~]{" + str(min_len).encode() + rb",}")
    for m in pat.finditer(data):
        results.append((m.start(), m.group().decode("ascii", errors="replace")))
    return results


def parse_elf_sections(data: bytes) -> dict:
    sections = {}
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return sections
    ei_class = data[4]
    try:
        if ei_class == 2:  # 64-bit
            e_shoff     = struct.unpack_from("<Q", data, 0x28)[0]
            e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
            e_shnum     = struct.unpack_from("<H", data, 0x3C)[0]
            e_shstrndx  = struct.unpack_from("<H", data, 0x3E)[0]
            if e_shoff == 0 or e_shnum == 0:
                return sections
            shstr_hdr = e_shoff + e_shstrndx * e_shentsize
            shstr_off = struct.unpack_from("<Q", data, shstr_hdr + 0x18)[0]
            for i in range(min(e_shnum, 512)):
                sh = e_shoff + i * e_shentsize
                if sh + e_shentsize > len(data):
                    break
                nm_off  = struct.unpack_from("<I", data, sh)[0]
                sh_off  = struct.unpack_from("<Q", data, sh + 0x18)[0]
                sh_size = struct.unpack_from("<Q", data, sh + 0x20)[0]
                if shstr_off + nm_off < len(data):
                    ne = data.find(b"\x00", shstr_off + nm_off)
                    name = data[shstr_off + nm_off: ne].decode("ascii", errors="replace") if ne != -1 else "?"
                    if sh_off + sh_size <= len(data):
                        sections[name] = {"offset": sh_off, "size": sh_size}
    except (struct.error, IndexError):
        pass
    return sections


@dataclass
class SecretHit:
    library:  str
    pattern:  str
    offset:   str
    match:    str
    context:  str
    entropy:  float
    severity: str = "HIGH"


@dataclass
class CryptoHit:
    library:   str
    algorithm: str
    constant:  str
    offset:    str
    note:      str


@dataclass
class EntropyBlob:
    library:  str
    offset:   str
    size:     int
    entropy:  float
    preview:  str


@dataclass
class LibraryReport:
    name:        str
    size:        int
    tier:        str
    rationale:   str
    is_elf:      bool
    sections:    dict
    secrets:     list = field(default_factory=list)
    crypto_hits: list = field(default_factory=list)
    entropy_blobs: list = field(default_factory=list)
    error:       Optional[str] = None


def analyze_library(lib_path: Path, tier: str, rationale: str) -> LibraryReport:
    name = lib_path.name
    try:
        data = lib_path.read_bytes()
    except IOError as e:
        return LibraryReport(name=name, size=0, tier=tier, rationale=rationale,
                             is_elf=False, sections={}, error=str(e))

    report = LibraryReport(
        name=name, size=len(data), tier=tier, rationale=rationale,
        is_elf=data[:4] == b"\x7fELF", sections={}
    )

    if not report.is_elf:
        report.error = "Not a valid ELF binary"
        return report

    sections = parse_elf_sections(data)
    report.sections = {k: v for k, v in sections.items() if v["size"] > 0}

    # ── Secret scanning ──────────────────────────────────────────────────────
    # Focus on .rodata first, fall back to full binary
    scan_regions = []
    for sec_name in [".rodata", ".data.rel.ro", ".data", "__const"]:
        if sec_name in sections and sections[sec_name]["size"] > 0:
            s = sections[sec_name]
            scan_regions.append((sec_name, data[s["offset"]: s["offset"] + s["size"]], s["offset"]))

    if not scan_regions:
        scan_regions = [("(full binary)", data, 0)]

    seen_matches = set()
    for sec_name, region, base_offset in scan_regions:
        strings = extract_strings(region, min_len=8)
        for rel_offset, s in strings:
            for pat_name, pattern in PATTERNS.items():
                hits = re.findall(pattern, s)
                if not hits:
                    continue
                hit_val = hits[0] if isinstance(hits[0], str) else hits[0][0] if hits[0] else ""
                if not hit_val or len(hit_val) < 8:
                    continue
                dedup_key = (pat_name, hit_val[:32])
                if dedup_key in seen_matches:
                    continue
                seen_matches.add(dedup_key)

                abs_offset = base_offset + rel_offset
                entropy    = shannon_entropy(hit_val.encode())

                # Determine severity
                severity = "CRITICAL" if pat_name in (
                    "SQLCipher_Passphrase", "SQLCipher_Raw_Key",
                    "Private_Key_PEM", "LINE_Channel_Token",
                    "Sentry_DSN", "AWS_Access_Key", "GCP_API_Key",
                ) else "HIGH"

                report.secrets.append(SecretHit(
                    library  = name,
                    pattern  = pat_name,
                    offset   = hex(abs_offset),
                    match    = hit_val[:80],
                    context  = s[:100],
                    entropy  = round(entropy, 3),
                    severity = severity,
                ))

    # ── Weak crypto constant detection (.text section) ───────────────────────
    text_data = b""
    text_base = 0
    for sec_name in [".text", ".plt"]:
        if sec_name in sections and sections[sec_name]["size"] > 0:
            s = sections[sec_name]
            text_data = data[s["offset"]: s["offset"] + s["size"]]
            text_base = s["offset"]
            break
    if not text_data:
        text_data = data
        text_base = 0

    for algo, (const_val, note) in CRYPTO_CONSTANTS.items():
        needle = struct.pack("<I", const_val)
        off = 0
        count = 0
        while count < 3:  # max 3 occurrences per constant
            idx = text_data.find(needle, off)
            if idx == -1:
                break
            report.crypto_hits.append(CryptoHit(
                library   = name,
                algorithm = algo,
                constant  = hex(const_val),
                offset    = hex(text_base + idx),
                note      = note,
            ))
            off = idx + 1
            count += 1

    # ── High-entropy blob detection ──────────────────────────────────────────
    # Check .data section for 32-byte aligned high-entropy blocks
    for sec_name in [".data", ".rodata"]:
        if sec_name not in sections:
            continue
        s   = sections[sec_name]
        sec = data[s["offset"]: s["offset"] + min(s["size"], 524288)]  # cap at 512KB
        for chunk_size in [16, 32, 64]:
            for i in range(0, len(sec) - chunk_size, chunk_size):
                chunk = sec[i: i + chunk_size]
                ent   = shannon_entropy(chunk)
                if ent > 7.3:
                    # Skip if it looks like printable strings
                    printable = sum(1 for b in chunk if 0x20 <= b <= 0x7E)
                    if printable / chunk_size < 0.6:
                        report.entropy_blobs.append(EntropyBlob(
                            library = name,
                            offset  = hex(s["offset"] + i),
                            size    = chunk_size,
                            entropy = round(ent, 3),
                            preview = chunk.hex()[:48] + "...",
                        ))
    # Keep top 5 per library
    report.entropy_blobs = sorted(report.entropy_blobs, key=lambda x: x.entropy, reverse=True)[:5]

    return report


def print_report(reports: list[LibraryReport]):
    total_secrets = sum(len(r.secrets) for r in reports)
    total_crypto  = sum(len(r.crypto_hits) for r in reports)
    total_blobs   = sum(len(r.entropy_blobs) for r in reports)

    sev_colors = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "RESET": "\033[0m"}

    print("\n" + "═" * 76)
    print("  ANALYSIS COMPLETE — SUMMARY")
    print("═" * 76)
    print(f"  Libraries analyzed : {len(reports)}")
    print(f"  Secret matches     : {total_secrets}")
    print(f"  Weak crypto hits   : {total_crypto}")
    print(f"  High-entropy blobs : {total_blobs}")
    print("═" * 76)

    # Group by tier
    for tier_name in ["P0_CRITICAL", "P1_HIGH", "P2_MEDIUM"]:
        tier_reports = [r for r in reports if r.tier == tier_name]
        if not tier_reports:
            continue
        print(f"\n  ── {tier_name} ──────────────────────────────────────────────────")
        for r in tier_reports:
            if r.error:
                print(f"  [-] {r.name}: {r.error}")
                continue

            has_findings = r.secrets or r.crypto_hits or r.entropy_blobs
            status = "⚠ FINDINGS" if has_findings else "✓ clean"
            print(f"\n  {'●' if has_findings else '○'} {r.name}  ({r.size/1024/1024:.1f} MB)  [{status}]")
            print(f"    {r.rationale}")

            if r.secrets:
                print(f"\n    SECRETS ({len(r.secrets)}):")
                for s in r.secrets[:10]:
                    col = sev_colors.get(s.severity, "")
                    rst = sev_colors["RESET"]
                    val = s.match[:60] + ("..." if len(s.match) > 60 else "")
                    print(f"      {col}[{s.severity}]{rst} {s.pattern}")
                    print(f"             offset  : {s.offset}")
                    print(f"             value   : {val}")
                    print(f"             entropy : {s.entropy}")
                    print(f"             context : {s.context[:70]}")
                    print()

            if r.crypto_hits:
                # Deduplicate by algorithm
                seen_algos = set()
                unique = []
                for c in r.crypto_hits:
                    base = c.algorithm.split("_")[0]
                    if base not in seen_algos:
                        unique.append(c)
                        seen_algos.add(base)
                print(f"    WEAK CRYPTO ({len(unique)} unique algorithms):")
                for c in unique:
                    print(f"      \033[93m[HIGH]\033[0m {c.algorithm}  const={c.constant}  @ {c.offset}")
                    print(f"             {c.note}")
                print()

            if r.entropy_blobs:
                print(f"    HIGH-ENTROPY BLOBS ({len(r.entropy_blobs)}) — possible key material:")
                for b in r.entropy_blobs[:3]:
                    print(f"      entropy={b.entropy}  offset={b.offset}  size={b.size}B  {b.preview}")
                print()


def print_ghidra_commands(reports: list[LibraryReport], libs_dir: str):
    """Print targeted Ghidra analysis commands for the most interesting libs."""
    interesting = [r for r in reports if r.secrets or r.crypto_hits or r.entropy_blobs]
    if not interesting:
        interesting = [r for r in reports if r.tier in ("P0_CRITICAL", "P1_HIGH")][:5]

    print("\n" + "═" * 76)
    print("  GHIDRA — TARGETED ANALYSIS COMMANDS")
    print("═" * 76)
    print("""
  Run these in order of priority. Substitute $GHIDRA_HOME with your path.
  Example: export GHIDRA_HOME=~/tools/ghidra_11.1.2_PUBLIC
""")

    for r in interesting[:8]:
        lib_path = os.path.join(libs_dir, r.name)
        print(f"  # ── {r.name} ──")
        print(f"  # {r.rationale}")
        print(f"  $GHIDRA_HOME/support/analyzeHeadless \\")
        print(f"      ~/line_audit/ghidra_work LINE_Project \\")
        print(f"      -import {lib_path} \\")
        print(f"      -overwrite \\")
        print(f"      -postScript ExtractSecrets.java \\")
        print(f"      -scriptPath ~/line_audit/ghidra_scripts/")
        print()

        # Targeted Ghidra GUI hints based on what was found
        if any(s.pattern == "SQLCipher_Passphrase" for s in r.secrets) or r.name == "libsqlcipher.so":
            print(f"  # GUI tip: Search → For Strings → filter 'PRAGMA key'")
            print(f"  #          Then trace callers of sqlite3_key() via Window → References")
        if r.name in ("libssl3line.so", "libcrypto3line.so"):
            print(f"  # GUI tip: Window → Symbol Table → filter 'SSL_CTX_set_verify'")
            print(f"  #          Decompile SSL_CTX_new() to find TrustManager bypass patterns")
            print(f"  #          Search → For Scalars → 0x67452301 (MD5), 0xC3D2E1F0 (SHA-1)")
        if r.name == "liblegy.so":
            print(f"  # GUI tip: Window → Symbol Table → filter 'auth' and 'token'")
            print(f"  #          Look for JNI_OnLoad — secrets often initialised there")
        if r.name == "libsentry.so" or r.name == "libsentry-android.so":
            print(f"  # GUI tip: Search → For Strings → filter 'sentry.io' and 'https://'")
            print(f"  #          The Sentry DSN format is: https://<key>@<host>/<project-id>")
        print()


def print_strings_commands(libs_dir: str):
    """Quick shell commands the user can run right now with just 'strings'."""
    priority_libs = [
        "liblegy.so", "libmm.so", "liblinejnihelper.so", "libssl3line.so",
        "libcrypto3line.so", "libsqlcipher.so", "libsentry.so", "libanna_jni.so",
        "libcardioRecognizer.so", "libDeepLingoKit.so",
    ]
    print("\n" + "═" * 76)
    print("  QUICK STRINGS COMMANDS (run these right now, no tools needed)")
    print("═" * 76)
    print(f'\n  LIBS="{libs_dir}"\n')

    print("  # ── SQLCipher passphrase hunt ───────────────────────────────────────")
    print(f'  strings "$LIBS/libsqlcipher.so" | grep -iE "PRAGMA|key=|passphrase|x\'"')
    print()
    print("  # ── Sentry DSN (contains secret token) ─────────────────────────────")
    print(f'  strings "$LIBS/libsentry.so" "$LIBS/libsentry-android.so" \\')
    print(f'    | grep -E "https://[0-9a-f]{{32}}@"')
    print()
    print("  # ── API keys and tokens across all P0 libs ─────────────────────────")
    for lib in priority_libs[:6]:
        print(f'  echo "=== {lib} ===" && strings "$LIBS/{lib}" \\')
        print(f'    | grep -iE "key|secret|token|bearer|api|auth|password" \\')
        print(f'    | grep -v "^[A-Z_]{{2,}}$" | head -20')
        print()
    print("  # ── Internal URLs across all libs ──────────────────────────────────")
    print(f'  strings "$LIBS/"*.so | grep -E "https?://[a-z0-9-]+\\.(line|naver)" | sort -u')
    print()
    print("  # ── GCP API keys ────────────────────────────────────────────────────")
    print(f'  strings "$LIBS/"*.so | grep -E "AIza[0-9A-Za-z_-]{{35}}"')
    print()
    print("  # ── AWS keys ────────────────────────────────────────────────────────")
    print(f'  strings "$LIBS/"*.so | grep -E "AKIA[0-9A-Z]{{16}}"')
    print()
    print("  # ── JWT tokens ──────────────────────────────────────────────────────")
    print(f'  strings "$LIBS/"*.so | grep -E "eyJ[A-Za-z0-9_-]{{10,}}"')
    print()
    print("  # ── legy gateway (auth endpoints + tokens) ─────────────────────────")
    print(f'  strings "$LIBS/liblegy.so" | grep -iE "auth|token|endpoint|gateway|secret"')


def main():
    print(BANNER)
    ap = argparse.ArgumentParser(description="LINE 26.1.1 native library targeted analyzer")
    ap.add_argument("--libs-dir", required=True, help="Path to arm64-v8a/ directory")
    ap.add_argument("--tier",     choices=["P0","P1","P2","all"], default="all",
                    help="Which priority tier to scan (default: all)")
    ap.add_argument("--out",      default="line_natives_report.json")
    ap.add_argument("--strings-only", action="store_true",
                    help="Only print quick strings commands, don't run analysis")
    args = ap.parse_args()

    libs_dir = Path(args.libs_dir)
    if not libs_dir.exists():
        print(f"[!] Directory not found: {libs_dir}")
        sys.exit(1)

    if args.strings_only:
        print_strings_commands(str(libs_dir))
        return

    # Build target list
    targets = []
    tier_filter = {"P0": ["P0_CRITICAL"], "P1": ["P1_HIGH"],
                   "P2": ["P2_MEDIUM"], "all": ["P0_CRITICAL","P1_HIGH","P2_MEDIUM"]}
    for tier_name in tier_filter[args.tier]:
        tier = LIBRARY_TIERS[tier_name]
        for lib_name in tier["libs"]:
            lib_path = libs_dir / lib_name
            if lib_path.exists():
                targets.append((lib_path, tier_name, tier["rationale"].get(lib_name, "")))
            else:
                print(f"  [skip] {lib_name} — not found in {libs_dir}")

    print(f"\n[+] Analyzing {len(targets)} libraries (tier filter: {args.tier})...\n")

    reports = []
    for lib_path, tier, rationale in targets:
        print(f"  [*] {lib_path.name} ({lib_path.stat().st_size/1024/1024:.1f} MB)...")
        r = analyze_library(lib_path, tier, rationale)
        reports.append(r)
        status = f"{len(r.secrets)} secrets, {len(r.crypto_hits)} crypto hits, {len(r.entropy_blobs)} blobs"
        print(f"      → {status}")

    print_report(reports)
    print_ghidra_commands(reports, str(libs_dir))
    print_strings_commands(str(libs_dir))

    # Save JSON report
    out_data = {
        "tool":      "LINE Native Library Analyzer",
        "version":   "LINE 26.1.1",
        "libs_dir":  str(libs_dir),
        "libraries": [asdict(r) for r in reports],
        "summary": {
            "total_secrets":      sum(len(r.secrets) for r in reports),
            "total_crypto_hits":  sum(len(r.crypto_hits) for r in reports),
            "total_entropy_blobs":sum(len(r.entropy_blobs) for r in reports),
            "libraries_with_findings": len([r for r in reports if r.secrets or r.crypto_hits]),
        }
    }
    with open(args.out, "w") as f:
        json.dump(out_data, f, indent=2)
    print(f"\n[+] Full JSON report saved: {args.out}")


if __name__ == "__main__":
    main()
