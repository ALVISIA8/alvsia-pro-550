# ALVISIA PRO — 50-control evidence matrix (2026-10-13)

This matrix is a verification plan, not a claim that all controls are implemented. Mark a control PASS only with CI, artifact inspection, or device-test evidence.

1. Sealed payload generator — IMPLEMENTED IN PR; CI PENDING
2. Loader installed before protected imports — SOURCE WIRED; CI/DEVICE TEST PENDING
3. AES-GCM authentication tests — UNIT TESTS ADDED; CI PENDING
4. Build ID authenticated with payload — NEEDS TEST
5. Release rejects plaintext protected modules — RELEASE GATE IN PR #17; CI PENDING
6. Release validates exact .alv inventory/header — RELEASE GATE IN PR #17; CI PENDING
7. Remove exposed license salts from shipped bytecode — NEEDS IMPLEMENTATION
8. Rotate license derivation safely — NEEDS IMPLEMENTATION
9. Audit suspicious session marker usage — NEEDS IMPLEMENTATION
10. Identify and rotate unknown hardcoded credential if valid — NEEDS IMPLEMENTATION
11. No reusable privileged secret in APK — SERVER-SIDE CONTROL
12. Server validates licenses — SERVER-SIDE CONTROL
13. Session token entropy and expiry — NEEDS TEST
14. Reject forged environment-only session — NEEDS TEST
15. License-only login regression tests; client OTP flow removed — NEEDS TEST
16. Operation grant enforced at each dispatch — NEEDS TEST
17. Native library loaded in release — NEEDS TEST
18. Missing native library cannot authorize protected tools — NEEDS IMPLEMENTATION
19. RASP not solely based on visible names — NEEDS IMPLEMENTATION
20. Validate embedded hash format and comparison — NEEDS IMPLEMENTATION
21. Verify app.imy integrity before dispatch — NEEDS IMPLEMENTATION
22. Native integrity check tested against tampering — NEEDS TEST
23. Anti-dump false-positive tests — NEEDS TEST
24. Portable timing probe and architecture assumptions — NEEDS REVIEW
25. Android-stack TLS pin tested with backup pin — NEEDS TEST
26. Python requests TLS pinning — NEEDS IMPLEMENTATION
27. Cleartext traffic disabled — SOURCE PRESENT, VERIFY MERGED MANIFEST
28. Invalid certificate always rejected — NEEDS TEST
29. Download URLs pinned to immutable commits — NEEDS REVIEW
30. SHA-256 check for SKIN_TOOL.zip — NEEDS IMPLEMENTATION
31. SHA-256 check for BGMI.csv — NEEDS IMPLEMENTATION
32. SHA-256 check for PUBG.csv — NEEDS IMPLEMENTATION
33. Pin unluac.jar version and digest — NEEDS IMPLEMENTATION
34. Pin ljd.jar version and digest — NEEDS IMPLEMENTATION
35. ZIP path traversal defense — NEEDS TEST
36. Download size and timeout limits — NEEDS IMPLEMENTATION
37. Restrictive temporary file handling — NEEDS TEST
38. Minimize sensitive buffer lifetime — NEEDS REVIEW
39. Android backup disabled — SOURCE PRESENT, VERIFY MERGED MANIFEST
40. Permissions mapped to actual features — NEEDS IMPLEMENTATION
41. All-files access is optional and consented — NEEDS IMPLEMENTATION
42. Graceful behavior when permissions denied — NEEDS TEST
43. Prefer Storage Access Framework where possible — NEEDS IMPLEMENTATION
44. Signing certificate SHA-256 verified — NEEDS TEST
45. APK v2/v3 signatures verified — NEEDS TEST
46. Build provenance includes source SHA and toolchain — NEEDS IMPLEMENTATION
47. Tested artifact hash matches released artifact — NEEDS IMPLEMENTATION
48. LUA/PAK/OBB/game-patch regression suite — NEEDS TEST
49. RASP false-positive and recovery tests — NEEDS TEST
50. Final independent audit of signed APK — NEEDS TEST

## Constraints
- Android permissions cannot be silently bypassed or made universally unrestricted. Request only required access, use SAF where feasible, and explain any special all-files access setting.
- Client-side encryption/obfuscation raises extraction cost but cannot guarantee plaintext stays secret while code executes on a device controlled by an attacker.
- A seed compiled into native code is not a server-side secret; never use it as the sole license authorization mechanism.
- Keep the release gate failing until sealed payload generation and imports are actually integrated. Preserve license login, session grants and tool dispatch with regression tests before merging; do not reintroduce the removed client OTP flow.