// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
//
// postinstall script — downloads the correct proofx binary from GitHub
// releases for the current platform and architecture.

"use strict";

const { https } = require("https");
const { createWriteStream, chmodSync, mkdirSync, existsSync } = require("fs");
const { join } = require("path");
const { execSync } = require("child_process");
const { arch: osArch, platform: osPlat } = require("os");

const VERSION = require("./package.json").version;

const ASSET_MAP = {
  "darwin-x64": "proofx-darwin-amd64",
  "darwin-arm64": "proofx-darwin-arm64",
  "linux-x64": "proofx-linux-amd64",
  "linux-arm64": "proofx-linux-arm64",
  "win32-x64": "proofx-windows-amd64.exe",
  "win32-arm64": "proofx-windows-arm64.exe",
};

function getAssetName() {
  const plat = osPlat();
  const arch = osArch();
  const key = `${plat}-${arch}`;
  const name = ASSET_MAP[key];
  if (!name) {
    throw new Error(`proofx: unsupported platform ${key} — supported: ${Object.keys(ASSET_MAP).join(", ")}`);
  }
  return name;
}

function download(url) {
  return new Promise((resolve, reject) => {
    const follow = (u) => {
      https.get(u, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return follow(res.headers.location);
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`proofx: download failed — HTTP ${res.statusCode}`));
        }
        resolve(res);
      }).on("error", reject);
    };
    follow(url);
  });
}

async function main() {
  const asset = getAssetName();
  const binDir = join(__dirname, "bin");
  if (!existsSync(binDir)) {
    mkdirSync(binDir, { recursive: 0o755 });
  }

  const isWin = osPlat() === "win32";
  const outName = isWin ? "proofx.exe" : "proofx";
  const outPath = join(binDir, outName);

  const url = `https://github.com/EslaM-X/proofx/releases/download/v${VERSION}/${asset}`;
  console.log(`proofx: downloading ${url}`);

  const res = await download(url);
  const file = createWriteStream(outPath);
  await new Promise((resolve, reject) => {
    res.pipe(file);
    file.on("finish", () => file.close(resolve));
    file.on("error", reject);
  });

  if (!isWin) {
    chmodSync(outPath, 0o755);
  }

  // Verify the binary works
  try {
    execSync(`"${outPath}" --version`, { stdio: "pipe" });
    console.log(`proofx: v${VERSION} installed successfully`);
  } catch {
    console.warn(`proofx: warning — binary downloaded but could not verify (this is expected on some CI environments)`);
  }
}

main().catch((err) => {
  console.error(`proofx: install failed — ${err.message}`);
  console.error("proofx: you can install manually from https://github.com/EslaM-X/proofx/releases");
  process.exit(1);
});
