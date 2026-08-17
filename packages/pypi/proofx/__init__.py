# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
"""ProofX — Evidence Infrastructure for Software."""

__version__ = "0.2.0"

import os
import platform
import subprocess
import sys
from pathlib import Path

ASSET_MAP = {
    ("Darwin", "x86_64"): "proofx-darwin-amd64",
    ("Darwin", "arm64"): "proofx-darwin-arm64",
    ("Linux", "x86_64"): "proofx-linux-amd64",
    ("Linux", "aarch64"): "proofx-linux-arm64",
    ("Windows", "AMD64"): "proofx-windows-amd64.exe",
    ("Windows", "ARM64"): "proofx-windows-arm64.exe",
}


def _binary_path() -> Path:
    return Path(__file__).parent / "bin" / ("proofx.exe" if sys.platform == "win32" else "proofx")


def _download(url: str, dest: Path) -> None:
    """Download a URL to a file path."""
    import urllib.request

    dest.parent.mkdir(parents=True, exist_ok=True)
    urllib.request.urlretrieve(url, dest)
    if sys.platform != "win32":
        os.chmod(dest, 0o755)


def _ensure_binary() -> Path:
    """Return the path to the proofx binary, downloading if necessary."""
    bin_path = _binary_path()
    if bin_path.exists():
        return bin_path

    key = (platform.system(), platform.machine())
    asset = ASSET_MAP.get(key)
    if not asset:
        supported = ", ".join(f"{p}/{a}" for p, a in sorted(ASSET_MAP.keys()))
        print(f"proofx: unsupported platform {'/'.join(key)} — supported: {supported}", file=sys.stderr)
        sys.exit(1)

    url = f"https://github.com/EslaM-X/proofx/releases/download/v{__version__}/{asset}"
    print(f"proofx: downloading {url}")
    _download(url, bin_path)
    return bin_path


def main() -> None:
    """Run the proofx CLI."""
    binary = _ensure_binary()
    args = [str(binary)] + sys.argv[1:]
    raise SystemExit(subprocess.call(args))


if __name__ == "__main__":
    main()
