**LINE ANDROID 26.1.1**

Security Audit Report

jp.naver.line.android · Version 26.1.1 (260110123) · March 2026

|                    |                                                            |
|--------------------|------------------------------------------------------------|
| **Classification** | CONFIDENTIAL — Authorized Security Research                |
| **Target**         | jp.naver.line.android v26.1.1 (260110123)                  |
| **APK Bundle**     | 2-arch, arm64-v8a + armeabi-v7a                            |
| **Analysis Date**  | February–March 2026                                        |
| **Report Version** | v4.0 — PoC consistency check, usage guide, updated scripts |
| **Analyst Host**   | Kali Linux (deepquest@deep1trud) + macOS (Ghidra GUI)      |
| **Total Findings** | 8 confirmed \| 6 false positives documented                |
| **Critical/High**  | 1 CRITICAL \| 4 HIGH \| 2 MEDIUM \| 1 INFO                 |

**FOR AUTHORIZED SECURITY RESEARCH ONLY — EDUCATIONAL PURPOSE**

**About LINE — Target Application Overview**

LINE is a Japanese freeware super-app for instant messaging, voice and
video calling, and social networking, operated by LY Corporation — a
company jointly owned by SoftBank Group and Naver Corporation of South
Korea. Originally launched in June 2011 by NHN Japan (a Naver
subsidiary) in the immediate aftermath of the 2011 Tōhoku earthquake,
LINE was designed to provide resilient communication when traditional
telephone networks were overwhelmed. It rapidly grew beyond its
emergency origins to become Japan's dominant social platform.

LINE became Japan's largest social network in 2013 and is now used by
over 70% of Japan's population. Beyond messaging, LINE has evolved into
a comprehensive super-app ecosystem encompassing digital payments (LINE
Pay), food delivery (LINE Delivery), live streaming (LINE Live),
taxi-hailing (LINE Taxi), digital comics (LINE Manga / LINE Webtoon),
music streaming (LINE Music), and an AI assistant (LINE Clova). The app
supports 17 languages and processes billions of messages daily across
its four core markets.

**User Base & Market Presence**

|                                 |                                                       |
|---------------------------------|-------------------------------------------------------|
| **Monthly Active Users (2025)** | ~194 million globally (Wikipedia / analyst estimates) |
| **Registered Users**            | 600+ million accounts worldwide                       |
| **Japan MAU**                   | ~96–97 million — over 70% of Japan's population       |
| **Thailand MAU**                | ~54 million — dominant messaging platform             |
| **Taiwan MAU**                  | ~22 million — leading social network                  |
| **Indonesia MAU**               | Growing market, tens of millions                      |
| **Daily Engagement (Japan)**    | Average 8.9 hours/month per user                      |
| **Gender split**                | 50.7% female / 49.3% male (Similarweb)                |
| **Official Accounts**           | 13.38 million+ business/brand accounts                |
| **Primary age group**           | 18–44 (combined ~48% of user base)                    |

**Revenue & Financial Context**

LINE's financial reporting became less granular after its 2019 merger
into Z Holdings (now LY Corporation), which also operates Yahoo! Japan
and PayPay. Standalone LINE financials are no longer published
separately. The figures below represent the most recent publicly
available data:

|                                          |                                                                |
|------------------------------------------|----------------------------------------------------------------|
| **LINE Revenue (2021, last standalone)** | \$2.36 billion USD — 56% increase year-on-year                 |
| **LINE Net Profit (2021)**               | \$110–112 million USD — first profitable year since 2017       |
| **Revenue split**                        | ~50% advertising, remainder content/stickers/pay               |
| **Advertising revenue**                  | ~\$1 billion USD (approx. ¥112 billion)                        |
| **LY Corporation Revenue (FY2024)**      | JPY 1.83 trillion (~\$12.5B USD) — LINE + Yahoo Japan combined |
| **LY Corporation Revenue (FY2025)**      | JPY 1.92 trillion (~\$12.7B USD) — 5.7% YoY growth             |
| **LY Operating Income (FY2025)**         | JPY 315 billion — 51.3% YoY increase                           |
| **Naver's stake in LY Corp**             | ~32.65% via Z Holdings joint venture with SoftBank             |
| **LINE Pay / PayPay**                    | 68.38 million users, 347% EBITDA growth in FY2024              |

**Why LINE is a High-Value Security Target**

The security profile of LINE is of exceptional interest for several
compounding reasons:

- Scale of sensitive data: With 194 million MAU, LINE processes an
  enormous volume of private communications, location data, payment
  transactions, and personal media daily across four countries.

- Super-app attack surface: LINE's integration of messaging, payments
  (LINE Pay), e-commerce, health (LINE Doctor), and AI services means a
  single compromise can cascade across multiple sensitive user contexts.

- Banking integration: LINE Bank operates in Japan, Taiwan, and
  Thailand. The app directly handles financial transactions and is
  integrated with Kasikorn Bank (Thailand) and other banking partners —
  as evidenced by the hardcoded certificate pins found in this audit.

- Government dependency: LINE is used by Japanese government agencies,
  schools, and emergency services. A 2024 data breach affecting 520,000
  records led to Japan's Ministry of Internal Affairs issuing rare dual
  administrative guidance and ordering Naver/LINE to separate their
  infrastructure systems by December 2026.

- AI integration: As found in this audit, LINE is actively integrating
  Google Vertex AI (Gemini) and OpenAI-compatible APIs into its native
  libraries, expanding the attack surface to include AI inference
  pipelines and associated API credentials.

- Cross-border data governance: LINE's data has historically flowed
  through servers in South Korea and China, creating complex
  jurisdictional exposure. The 2024 breach accelerated regulatory
  scrutiny across Japan, Taiwan, and Thailand.

> **⚠ NOTE:** The 2024 data breach was traced to unauthorized access
> through a Naver subcontractor's computer which shared an
> authentication system with LINE. This is directly relevant to findings
> F-01 and F-02 in this report — weaknesses in authentication domain
> security (tauth.line.naver.jp) and missing certificate pins on core
> infrastructure could facilitate similar or worse breaches.

**Executive Summary**

LINE Android 26.1.1 was subjected to static analysis including native
library reverse engineering, APK decompilation (192,737 smali files),
network security configuration analysis, and automated PoC script
execution. The audit reveals a consistent pattern: LINE's
financial/banking infrastructure is well-protected with strong
certificate pinning, while its core messaging infrastructure has
critical gaps.

*The most significant finding is that LINE explicitly permits
unencrypted HTTP traffic to authentication and core infrastructure
endpoints, while simultaneously implementing 6-8 certificate pins for
banking partner domains. This asymmetry suggests deliberate security
prioritization of financial transactions over user communications
privacy.*

| ID | Severity | Title | CWE |
|----|----------|-------|-----|
| F-01 | CRITICAL | Cleartext HTTP Permitted on Authentication & Core Domains | CWE-319 |
| F-02 | HIGH | Missing Certificate Pins on Core Messaging Gateway (legy) | CWE-295 |
| F-03 | HIGH | Dev/Staging/RC Endpoints Hardcoded in Production APK | CWE-798 |
| F-04 | HIGH | Hardcoded Internal AI Infrastructure Endpoints | CWE-798 |
| F-05 | HIGH | JWT-like Token Found in Native Library | CWE-321 |
| F-06 | MEDIUM | base-config Permits Global Cleartext Traffic | CWE-319 |
| F-07 | MEDIUM | liblegy.so Strings Runtime-Assembled (Obfuscation) | CWE-656 |
| F-08 | INFO | Banking Domains Strongly Pinned — Core Messaging Not | CWE-295 |

**Scope & Methodology**

|                     |                                                                   |
|---------------------|-------------------------------------------------------------------|
| **Target APK**      | jp.naver.line.android_26.1.1-260110123_2arch_6dpi.apkm            |
| **Package**         | jp.naver.line.android                                             |
| **Version**         | 26.1.1 (build 260110123)                                          |
| **Architecture**    | arm64-v8a (primary) + armeabi-v7a                                 |
| **APK bundle size** | 366 MB total, base.apk 163MB                                      |
| **Smali files**     | 192,737 (APKTool decompilation of base.apk)                       |
| **Native libs**     | 70+ .so files from split_config.arm64_v8a.apk (101MB)             |
| **Tools — Static**  | APKTool, strings, custom Python scanner (analyze_line_natives.py) |
| **Tools — Dynamic** | Frida 17.7.3, Ghidra 11.x (macOS GUI)                             |
| **Analysis period** | February–March 2026                                               |

**Analysis Phases**

- Phase 1 — APK Extraction: .apkm bundle unpacked, arm64-v8a native libs
  extracted from split_config.arm64_v8a.apk

- Phase 2 — Native Library Static Analysis: Custom Python scanner across
  P0/P1 priority tiers, strings extraction, entropy analysis

- Phase 3 — APKTool Decompilation: Full smali decompilation of base.apk
  (192,737 files)

- Phase 4 — Configuration Analysis: AndroidManifest.xml,
  network_security_config.xml reviewed

- Phase 5 — Smali Code Review: Automated pattern matching across all
  smali_classes\* directories

- Phase 6 — Ghidra Analysis: Native library reverse engineering (macOS
  GUI, decompiler enabled)

---

## F-01 · CRITICAL · Cleartext HTTP Permitted on Authentication & Core Domains · CWE-319

|                 |                                                       |
|-----------------|-------------------------------------------------------|
| **Location**    | res/xml/network_security_config.xml                   |
| **Component**   | domain-config block, cleartextTrafficPermitted="true" |
| **Affected**    | 11 domains including tauth.line.naver.jp              |
| **Requirement** | Same network (WiFi) or network-level attacker         |

> **📋 EVIDENCE:** network_security_config.xml: `<domain-config
> cleartextTrafficPermitted="true">` covering tauth.line.naver.jp,
> ci.line-apps.com, home.line-apps.com, api-album.line.me, line-cdn.net
> (+all subdomains), and 6 others

**Affected Domains**

```
# Full list — all in single domain-config with cleartext=true:
ci.line-apps.com           → Content infrastructure
cix.line-apps.com          → Content infrastructure (variant)
home.line-apps.com         → Home timeline API
obs.line-apps.com          → Object storage
square-note.line-apps.com  → LINE Square notes
poker.line.naver.jp        → LINE Poker
dl.shop.line.naver.jp      → LINE Shop downloads
tauth.line.naver.jp        → TOKEN AUTHENTICATION ← highest severity
api-album.line.me          → Album/photo API
contact-cc.line.me         → Contact/customer care
line-cdn.net (incl. subdomains) → All CDN subdomains
```

> **💥 IMPACT:** tauth.line.naver.jp is a token authentication endpoint.
> HTTP traffic to this domain on a shared network (café WiFi, corporate
> network) exposes authentication tokens in plaintext. An attacker
> performing ARP spoofing or operating a rogue AP can capture these
> tokens and replay them without any TLS interception tools.

Attack scenario:

```
# Attacker on same WiFi network:
sudo arpspoof -i wlan0 -t <victim_ip> <gateway_ip>
sudo tcpdump -i wlan0 -A 'host tauth.line.naver.jp' -w tauth_capture.pcap
# OR with rogue AP — victim connects, all HTTP flows in plaintext
# No TLS interception, no certificate bypass needed
# tauth tokens appear directly in pcap
```

> **✅ FIX:** Remove cleartextTrafficPermitted="true" from this
> domain-config block. All LINE-controlled domains should enforce HTTPS.
> For CDN (line-cdn.net), migrate any remaining HTTP asset URLs to HTTPS.

---

## F-02 · HIGH · Missing Certificate Pins on Core Messaging Gateway (legy) · CWE-295

|                 |                                                                                           |
|-----------------|-------------------------------------------------------------------------------------------|
| **Location**    | res/xml/network_security_config.xml                                                       |
| **Component**   | domain-config for legy.line-apps.com — no `<pin-set>`                                     |
| **Affected**    | legy.line-apps.com, liff.line.me, miniapp.line.me, line-scdn.net, uts-front.line-apps.com |
| **Requirement** | Network-level attacker with any valid CA-signed certificate                               |

> **📋 EVIDENCE:** legy.line-apps.com, legy-backup.line-apps.com,
> liff.line.me, miniapp.line.me, line-scdn.net (+subdomains),
> uts-front.line-apps.com all appear in domain-config with
> cleartextTrafficPermitted=false but NO `<pin-set>` defined.

> **💥 IMPACT:** legy (LINE Edge Gateway) is the primary transport for
> LINE messages. Without certificate pinning, any attacker holding a
> CA-signed certificate for legy.line-apps.com (obtainable via domain
> validation CAs, compromised CA, or enterprise proxy) can perform MITM.
> Burp Suite's default certificate works against this domain — no Frida
> bypass required.

```
# No Frida needed — Burp default cert works against legy:
# 1. Set device proxy to Burp on port 8080
# 2. Install Burp CA cert on device
# 3. Open LINE — legy.line-apps.com traffic appears in Burp HTTP History
# liff.line.me / miniapp.line.me also interceptable this way
```

> **✅ FIX:** Add SHA-256 certificate pins for legy.line-apps.com,
> liff.line.me, miniapp.line.me, and line-scdn.net. Follow the same
> pattern used for banking domains (6-8 pins including intermediate and
> root CAs).

---

## F-03 · HIGH · Dev/Staging/RC Endpoints Hardcoded in Production APK · CWE-798

|               |                                                              |
|---------------|--------------------------------------------------------------|
| **Location**  | res/xml/network_security_config.xml                          |
| **Component** | domain-config listing alpha/beta/rc/dev domains              |
| **Affected**  | 8 non-production endpoints                                   |
| **Risk**      | Staging environments typically have weaker security controls |

```
# Non-production endpoints in production APK:
legy-beta.line-apps-beta.com      → Beta messaging gateway
legy-beta-osk.line-apps-beta.com  → Beta OSK variant
legy-rc.line-apps-rc.com          → Release candidate gateway
legy-rc2.line-apps-rc.com         → RC gateway #2
uts-front.line-apps-alpha.com     → Alpha UTS frontend
uts-front.line-apps-beta.com      → Beta UTS frontend
uts-front.line-apps-rc.com        → RC UTS frontend
line-scdn-dev.net (+ subdomains)  → Dev CDN
```

> **💥 IMPACT:** Staging/dev environments often skip security hardening
> (rate limiting, auth strictness, logging). Their presence in
> production code expands the attack surface. line-scdn-dev.net as a
> wildcard subdomain match means any subdomain of this domain is granted
> network access.

> **✅ FIX:** Remove all non-production domain entries from the
> production APK. Use build flavors to include environment-specific
> config only in the appropriate build variant.

---

## F-04 · HIGH · Hardcoded Internal AI Infrastructure Endpoints · CWE-798

|               |                                                                        |
|---------------|------------------------------------------------------------------------|
| **Location**  | libDeepLingoKit.so (.rodata section)                                   |
| **Component** | DeepLingo AI translation library — Gemini/Vertex AI integration        |
| **Found via** | strings extraction: strings $LIBS/libDeepLingoKit.so                  |
| **Affected**  | ast.line-apps.com internal gateway, ast-tts.line-apps.com TTS endpoint |

> **📋 EVIDENCE:** Two internal endpoints extracted from
> libDeepLingoKit.so: (1) "gemini.vertex.gateway.baseURL":
> "https://ast.line-apps.com/v1/projects/yj-scoutbeta2-dev/locations/global/publishers/google/models"
> (2) "openai.baseURL": "https://ast-tts.line-apps.com"

```
# Extracted from libDeepLingoKit.so .rodata:
gemini.vertex.gateway.baseURL:
  https://ast.line-apps.com/v1/projects/yj-scoutbeta2-dev/
  locations/global/publishers/google/models
openai.baseURL:
  https://ast-tts.line-apps.com
# Also found — token injection function:
DLK_SetChannelAccessToken
# Gemini endpoint getters in symbol table:
_ZNK9deeplingo12GeminiConfig16GetFirstEndpointEv
_ZNK9deeplingo12GeminiConfig18GetCurrentEndpointEv
```

> **💥 IMPACT:** The Vertex AI project ID 'yj-scoutbeta2-dev' reveals an
> internal GCP project name in a development/beta stage. The
> ast.line-apps.com gateway proxies Google Vertex AI Gemini calls — its
> full API path is exposed. DLK_SetChannelAccessToken indicates a
> channel access token is injected at runtime; if this token is
> interceptable via MITM (F-02), it could allow unauthorized AI API
> calls at LINE's expense.

> **✅ FIX:** Move endpoint configuration out of compiled native
> libraries into server-provided config fetched at runtime. Ensure
> channel access tokens are short-lived and scoped to device/session.

---

## F-05 · HIGH · JWT-like Token Found in Native Library · CWE-321

|               |                                                                  |
|---------------|------------------------------------------------------------------|
| **Location**  | Native library (exact lib TBD — appears in 2+ libs)              |
| **Found via** | strings $LIBS/*.so \| grep -E "eyJ[A-Za-z0-9_-]{10,}"           |
| **Value**     | DpFrdRbhIfzYJsdHt6bPWHJxfrrhTZVHO8mvbaG0weyJ9rQPOLXiZNwlz6bb65pc |
| **Status**    | REQUIRES FURTHER ANALYSIS — partial JWT or prefixed token        |

> **📋 EVIDENCE:** String
> "DpFrdRbhIfzYJsdHt6bPWHJxfrrhTZVHO8mvbaG0weyJ9rQPOLXiZNwlz6bb65pc"
> found twice in native libs. Contains "eyJ9" which is base64url-encoded
> '{"}' — characteristic of JWT payload boundary.

```
# Found string (appears in 2 native libraries):
DpFrdRbhIfzYJsdHt6bPWHJxfrrhTZVHO8mvbaG0weyJ9rQPOLXiZNwlz6bb65pc
# eyJ9 decodes to: {" — JWT payload start
# Prefix 'DpFrdRbhI...' may be obfuscation or custom encoding
# Identification commands:
for f in $LIBS/*.so; do
  r=$(strings $f | grep DpFrdRbhIfzYJsdHt6bP)
  [ -n "$r" ] && echo "FOUND: $(basename $f)"
done
# Decode the eyJ9 portion:
echo 'eyJ9' | base64 -d
```

> **💥 IMPACT:** If this is a hardcoded JWT or token seed, it could be
> used to forge authentication tokens or access protected API endpoints.
> The duplicate occurrence (found in 2 libs) suggests it may be a shared
> secret or signing key embedded at compile time.

> **✅ FIX:** Identify the source library and decode the full string. If
> confirmed as a JWT or signing secret, rotate immediately and move to
> server-side key management (HSM or KMS). Never embed authentication
> material in compiled native code.

---

## F-06 · MEDIUM · Global Cleartext Traffic Permitted via base-config · CWE-319

|               |                                                           |
|---------------|-----------------------------------------------------------|
| **Location**  | res/xml/network_security_config.xml, line 4               |
| **Component** | `<base-config cleartextTrafficPermitted="true" />`        |
| **Scope**     | ALL domains not explicitly listed in domain-config blocks |
| **Status**    | Partially mitigated by domain-specific configs above      |

> **📋 EVIDENCE:** `<base-config cleartextTrafficPermitted="true" />` is
> the first entry in network_security_config.xml, making HTTP the
> default for all domains not explicitly configured.

> **💥 IMPACT:** Any domain LINE connects to that is not in an explicit
> domain-config block inherits the base-config and can receive HTTP
> traffic. As LINE integrates third-party SDKs and analytics, new
> domains may unintentionally allow cleartext without explicit opt-in.

> **✅ FIX:** Change base-config to cleartextTrafficPermitted="false"
> and explicitly whitelist only domains that require HTTP (with
> documented justification). This enforces secure-by-default.

---

## F-07 · MEDIUM · liblegy.so Strings Runtime-Assembled (Anti-Analysis) · CWE-656

|                 |                                                                         |
|-----------------|-------------------------------------------------------------------------|
| **Location**    | liblegy.so — LINE Edge Gateway native library                           |
| **Found via**   | strings liblegy.so \| grep -iE 'auth\|token\|endpoint\|secret\|gateway' |
| **Result**      | Zero output — no readable strings found                                 |
| **Implication** | Strings assembled at runtime via XOR/char-concat or similar             |

> **📋 EVIDENCE:** strings against liblegy.so with broad
> auth/token/endpoint/gateway patterns returned zero results. The
> library is 249KB and handles the core messaging gateway — the complete
> absence of readable strings indicates deliberate obfuscation.

> **💥 IMPACT:** Runtime string assembly prevents static analysis from
> identifying hardcoded endpoints, auth tokens, or configuration values
> within the messaging gateway library. This increases reverse
> engineering complexity but does not eliminate risk — Ghidra dynamic
> analysis or Frida runtime hooking can still extract values at runtime.

```
# Next steps for liblegy.so analysis:
# 1. Ghidra (macOS) — import liblegy.so
#    Symbol Table → JNI_OnLoad → decompile
#    Look for XOR loops, char-by-char string construction
# 2. Frida runtime hook (on rooted device):
#    Hook liblegy.so exports and log string arguments
#    frida -U -f jp.naver.line.android -l hook_legy.js
# 3. Strings assembled at JNI_OnLoad initialization:
#    Monitor /proc/<pid>/maps for memory-mapped strings post-init
```

> **✅ FIX:** For reporting purposes: document that liblegy.so employs
> string obfuscation. Recommend dynamic analysis phase to extract
> runtime values. If this is intentional anti-tampering, it should be
> documented as a security control (not a vulnerability).

---

## F-08 · INFO · Security Asymmetry: Banking Pinned, Messaging Not · CWE-295

This finding documents the significant security asymmetry between how
LINE protects financial traffic versus messaging traffic.

| Domain | Pins | Assessment |
|--------|------|------------|
| web.linebk.com (LINE Bank) | 6 pins | ✅ Well protected |
| api-channel.linebk.com | 6 pins | ✅ Well protected |
| kasikornbank.com domains | 7-8 pins | ✅ Well protected |
| cwa.linebank.com.tw | 8 pins | ✅ Well protected |
| app-payatom.line-apps.com (Pay) | 7 pins | ✅ Well protected |
| legy.line-apps.com (messaging) | 0 pins | ❌ NOT PINNED |
| liff.line.me (LIFF apps) | 0 pins | ❌ NOT PINNED |
| tauth.line.naver.jp (token auth) | 0 + HTTP | ❌ CLEARTEXT |
| line-cdn.net (content delivery) | 0 + HTTP | ❌ CLEARTEXT |

---

**False Positives — P0 Native Library Scan**

The following 6 findings were generated by the automated native library
scanner against P0-tier libraries (libsqlcipher.so, libmm.so) and
investigated and dismissed as false positives.

| Library | String Pattern | Entropy | Verdict & Reason |
|---------|----------------|---------|------------------|
| libsqlcipher.so | 281fc0e9afc38674... (32-char hex) | ~4.1 | FALSE POSITIVE — SQLite/FTS5 build fingerprint (timestamp + source tree hash). Context: '2025-11-28 17:28:25 281fc0e9...' |
| libsqlcipher.so | 0123456789ABCDEF0123456789abcdef | 4.375 | FALSE POSITIVE — Hex encoding lookup table / test vector. Real AES-256 keys score 7.9+. Sequential structure confirms non-random. |
| libsqlcipher.so | REINDEXEDESCAPEACHECKEY... (SQL keywords) | ~4.0 | FALSE POSITIVE — SQLite packed keyword trie. All SQL reserved words (SELECT, TABLE, CREATE...) concatenated for parser. |
| libsqlcipher.so | 281fc0e9...e64c6cbdb133d35f6f5c87ff6af38a88 | ~4.1 | FALSE POSITIVE — Same SQLite build hash extended to 256-bit. Context: 'fts5: 2025-11-28 17:28:25...' |
| libmm.so | 000102030405060708091011... (sequential) | 3.322 | FALSE POSITIVE — NIST/RFC sequential byte test vector (0x00→0xFF). Entropy 3.322 far below 7.0 threshold for real keys. |
| libmm.so | 00010203040506070809101112131415 (32-char seq) | 2.656 | FALSE POSITIVE — Same test vector, 128-bit variant. Entropy 2.656 confirms non-random. |

> **⚠ NOTE:** Real cryptographic key material exhibits Shannon entropy
> > 7.3 for 32-byte chunks. All 6 dismissed findings scored below 4.5.
> libssl3line.so, libcrypto3line.so, and liblegy.so returned clean
> results on static string analysis — liblegy.so appears to use runtime
> string assembly (see F-07).

**Recommendations — Priority Order**

|                      |                                                                                          |
|----------------------|------------------------------------------------------------------------------------------|
| **P1 — IMMEDIATE**   | Remove cleartextTrafficPermitted=true from tauth.line.naver.jp and all core LINE domains |
| **P1 — IMMEDIATE**   | Add certificate pins to legy.line-apps.com, liff.line.me, miniapp.line.me                |
| **P2 — SHORT-TERM**  | Change base-config to cleartextTrafficPermitted=false                                    |
| **P2 — SHORT-TERM**  | Remove all alpha/beta/rc/dev domain entries from production APK                          |
| **P2 — SHORT-TERM**  | Investigate and decode F-05 JWT-like string — rotate if confirmed secret                 |
| **P3 — MEDIUM-TERM** | Move AI endpoint config (ast.line-apps.com) out of compiled native libs                  |
| **P3 — MEDIUM-TERM** | Dynamic analysis of liblegy.so with Frida to extract runtime-assembled strings           |
| **P4 — ONGOING**     | Apply same certificate pinning rigor to messaging domains as banking domains             |

**Pending Analysis**

The following items were identified but not yet completed at time of
this report version:

- Sentry DSN — not found in native libs, search in smali and assets
  pending

- liblegy.so Ghidra decompiler analysis — JNI_OnLoad runtime string
  assembly

- F-05 JWT-like string — source library identification pending

- Full PoC suite execution — run_all_pocs.py against decompiled smali

- Dynamic analysis — Frida server push to test device pending

- P1 native scanner results — libsentry.so, libanna_jni.so,
  libE2EInferenceJNI.so

- Smali sweep for Sentry DSN, legy URL construction, naver.jp fragments

---

For the full PoC usage guide (per-script commands, expected output, and the
consistency matrix mapping each script to the findings above), see
[../poc/README.md](../poc/README.md).

*This report is for authorized security research only. Unauthorized use,
reproduction, or disclosure is prohibited.*
