#!/usr/bin/env python3
"""
Run this script from inside the repo root to patch PanelClient.kt
so it shows the real security check reason instead of a generic message.

Usage (in Termux):
  cd ~/alvsia-pro-550
  python3 PANEL_SHOWREASON.py
"""
import os, re, glob, sys

# Find PanelClient.kt
matches = glob.glob("app/src/main/java/**/PanelClient.kt", recursive=True)
if not matches:
    print("ERROR: PanelClient.kt not found. Run from repo root.")
    sys.exit(1)

panel = matches[0]
print(f"Found: {panel}")

with open(panel, "r") as f:
    src = f.read()

# Check if already patched
if "BLOCKED:" in src or "SecurityException" in src:
    print("Already patched or has SecurityException handling.")
    print(src[:200])
    sys.exit(0)

# Replace the generic error message constant/string
# Common patterns in PanelClient:
patterns = [
    # "Security check blocked login. Restart the app and try again."
    (r'"Security check blocked login[^"]*"',
     '"Security check blocked: " + (secReason ?: "unknown")'),
]

for old_pat, new_val in patterns:
    if re.search(old_pat, src):
        print(f"Replacing pattern: {old_pat}")
        src = re.sub(old_pat, new_val, src)

# Add secReason var near top of class if not present
if "secReason" not in src and "Security check blocked:" in src:
    # inject after class declaration
    src = re.sub(
        r'(class PanelClient[^{]*\{)',
        r'\1\n    private var secReason: String? = null',
        src, count=1
    )

# Find allowTools call and wrap to capture reason
# Pattern: SessionGate.allowTools(...)  (not already in try)
old_call = r'([ \t]+)(SessionGate\.allowTools\([^)]*\))'
def wrap_call(m):
    indent = m.group(1)
    call = m.group(2)
    return f"""{indent}try {{
{indent}    {call}
{indent}}} catch (e: SecurityException) {{
{indent}    secReason = e.message?.removePrefix("BLOCKED:") ?: "check_failed"
{indent}    showError("Security check blocked: ${{secReason}}\\nRestart and try again.")
{indent}    return
{indent}}}"""

if "SessionGate.allowTools" in src and "SecurityException" not in src:
    src = re.sub(old_call, wrap_call, src)
    print("Wrapped SessionGate.allowTools with try/catch")

with open(panel, "w") as f:
    f.write(src)

print("Done. Check the file and push to GitHub.")
