#!/usr/bin/env node
// conformance/diff.js — Compares native and WASM result.json files.
// Exits 0 if all match, 1 if any differ.
//
// Usage: node conformance/diff.js

const fs = require('fs');
const path = require('path');

const nativeDir = path.join(__dirname, 'native');
const wasmDir = path.join(__dirname, 'wasm');

const nativeFiles = fs.readdirSync(nativeDir).filter(f => f.endsWith('.result.json'));
const wasmFiles = new Set(fs.readdirSync(wasmDir).filter(f => f.endsWith('.result.json')));

let pass = 0;
let fail = 0;

for (const file of nativeFiles) {
  const name = path.basename(file, '.result.json');
  if (!wasmFiles.has(file)) {
    console.log(`  [FAIL] ${name} — missing WASM result`);
    fail++;
    continue;
  }

  const native = JSON.parse(fs.readFileSync(path.join(nativeDir, file), 'utf8'));
  const wasm = JSON.parse(fs.readFileSync(path.join(wasmDir, file), 'utf8'));

  const match = native.result.valid === wasm.result.valid &&
    native.result.checks.length === wasm.result.checks.length;

  if (match) {
    console.log(`  [PASS] ${name} — native.valid=${native.result.valid} wasm.valid=${wasm.result.valid}`);
    pass++;
  } else {
    console.log(`  [FAIL] ${name} — native.valid=${native.result.valid} wasm.valid=${wasm.result.valid}`);
    console.log(`         native checks: ${JSON.stringify(native.result.checks.map(c => c.name + ':' + c.status))}`);
    console.log(`         wasm checks:   ${JSON.stringify(wasm.result.checks.map(c => c.name + ':' + c.status))}`);
    fail++;
  }
}

console.log(`\nDifferential: ${pass} match, ${fail} differ`);
if (fail > 0) process.exit(1);
