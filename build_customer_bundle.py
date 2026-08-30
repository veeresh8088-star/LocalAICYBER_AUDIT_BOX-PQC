# -*- coding: utf-8 -*-
"""Builds the customer handover bundle.

Replaces create_docker_app_delta.py, which was pinned to v3.16 while the compose
files had moved to 3.21 -- running it would have shipped a four-version-old image.
The version is read from docker-compose.yml here so the two cannot drift again.

What ships, and why it is not simply "all the images":

  app image        (~6.5GB)  Rebuilt. Carries every Python and frontend change.
  llm entrypoint   (~8KB)    Shipped as a FILE plus Dockerfile.llm.rebase, not a
                             12.5GB image. The only change is one shell script;
                             the customer relayers it onto the LLM image they
                             already have, which keeps the model weights and the
                             pinned llama.cpp engine build exactly as they are.
  compose files    (~10KB)   Carry MIN_CTX_PER_REQUEST / LLM_NUM_CTX.
  QUICKSTART       (~6KB)    Install steps and the settings that must be applied.

Usage:  python build_customer_bundle.py [--version 3.22] [--skip-build]
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import date

PROJECT = os.path.dirname(os.path.abspath(__file__))
OUT_ROOT = os.path.join(os.path.dirname(PROJECT), "customer_deployment_package")


def detect_version():
    """Reads the app image tag from docker-compose.yml -- single source of truth."""
    with open(os.path.join(PROJECT, "docker-compose.yml"), encoding="utf-8") as f:
        m = re.search(r"image:\s*aicyberauditbox-app:([\d.]+)", f.read())
    return m.group(1) if m else None


def bump(v):
    parts = v.split(".")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


def run(cmd, cwd=PROJECT, check=True):
    print(f"  $ {cmd}")
    r = subprocess.run(cmd, shell=True, cwd=cwd)
    if check and r.returncode != 0:
        print(f"  !! failed (exit {r.returncode})")
        return False
    return r.returncode == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", help="target version, e.g. 3.22 (default: current + 1)")
    ap.add_argument("--skip-build", action="store_true", help="package only; reuse existing images")
    args = ap.parse_args()

    current = detect_version()
    if not current:
        print("Could not read the app image tag from docker-compose.yml."); return 1
    version = args.version or bump(current)
    print("=" * 74)
    print(f"  AICyberAuditBox customer bundle   current={current}  ->  building {version}")
    print("=" * 74)

    out = os.path.join(OUT_ROOT, f"v{version}")
    os.makedirs(out, exist_ok=True)

    app_tag = f"aicyberauditbox-app:{version}"
    llm_tag = f"aicyberauditbox-llm:{version}"
    emb_tag = f"aicyberauditbox-llm-embed:{version}"

    if not args.skip_build:
        print("\n---> 1/4  Building the app image (all Python + frontend changes)")
        if not run(f"docker build -f Dockerfile.app -t {app_tag} ."):
            print("     Docker must be running. Aborting."); return 1

        print("\n---> 2/4  Relayering the LLM images (entrypoint only, no weight copy)")
        for tag, base in ((llm_tag, f"aicyberauditbox-llm:{current}"),
                          (emb_tag, f"aicyberauditbox-llm-embed:{current}")):
            run(f'docker build -f Dockerfile.llm.rebase --build-arg LLM_BASE_IMAGE={base} -t {tag} .',
                check=False)
    else:
        print("\n---> 1-2/4  --skip-build: reusing existing images")

    print("\n---> 3/4  Exporting the app image")
    tar = os.path.join(out, f"aicyberauditbox-app-{version}.tar")
    if not run(f'docker save -o "{tar}" {app_tag}', check=False):
        print("     Export failed -- is the image built?"); return 1
    size_gb = os.path.getsize(tar) / 1024 ** 3 if os.path.exists(tar) else 0
    print(f"     {tar}  ({size_gb:.2f} GB)")

    print("\n---> 4/4  Packaging config, entrypoint and docs")
    companion = os.path.join(out, f"aicyberauditbox-{version}-companion.zip")
    files = [
        ("docker-compose.yml", "docker-compose.yml"),
        ("docker-compose.customer.yml", "docker-compose.customer.yml"),
        ("docker/llm-entrypoint.sh", "docker/llm-entrypoint.sh"),
        ("Dockerfile.llm.rebase", "Dockerfile.llm.rebase"),
        (f"QUICKSTART_v{version}.md", f"QUICKSTART_v{version}.md"),
    ]
    with zipfile.ZipFile(companion, "w", zipfile.ZIP_DEFLATED) as z:
        for src, arc in files:
            p = os.path.join(PROJECT, src)
            if os.path.exists(p):
                z.write(p, arc)
                print(f"     + {arc}")
            else:
                print(f"     - {arc}  (missing, skipped)")

    print("\n" + "=" * 74)
    print(f"  Bundle ready: {out}")
    print(f"    aicyberauditbox-app-{version}.tar        {size_gb:.2f} GB")
    print(f"    aicyberauditbox-{version}-companion.zip  {os.path.getsize(companion)/1024:.0f} KB")
    print("=" * 74)
    return 0


if __name__ == "__main__":
    sys.exit(main())
