#!/usr/bin/env python3
"""Generate a signed manifest fixture for the Kotlin cross-test.

Uses the exact canonicalization + signing of scripts/publish-release.py
(sorted keys, compact separators, signature field excluded, openssl
SHA256withRSA with the real release key) and writes:
  <outdir>/manifest.json   — the signed manifest
  <outdir>/canonical.txt   — the canonical bytes that were signed
"""
import base64
import json
import subprocess
import sys
import os

KEY_PEM = os.path.expanduser("~/.config/deskguest/key.pem")


def canonical_bytes(manifest):
    payload = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def main():
    outdir = sys.argv[1]
    os.makedirs(outdir, exist_ok=True)
    manifest = {
        "product": "deskguest-platform",
        "versionName": "0.3.0",
        "versionCode": 3,
        "apk": {
            "fileName": "DeskGuest-0.3.0.apk",
            "sizeBytes": 812345,
            "sha256": "ab12cd34" * 8,
            "url": "https://github.com/DeskGuest-App/DeskGuest-control-releases/releases/download/v0.3.0/DeskGuest-0.3.0.apk",
        },
        "notes": "Cross-test fixture — not a real release.",
        "publishedAt": "2026-11-11T13:00:00Z",
    }
    canonical = canonical_bytes(manifest)
    proc = subprocess.run(["openssl", "dgst", "-sha256", "-sign", KEY_PEM],
                          input=canonical, capture_output=True)
    if proc.returncode != 0:
        sys.exit(f"signing failed: {proc.stderr.decode(errors='replace')}")
    manifest["signature"] = base64.b64encode(proc.stdout).decode()
    with open(os.path.join(outdir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    with open(os.path.join(outdir, "canonical.txt"), "wb") as f:
        f.write(canonical)
    print("fixture written to", outdir)


if __name__ == "__main__":
    main()
