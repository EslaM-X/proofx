#!/usr/bin/env node
// conformance/diff.js — Compares native and WASM result.json files.
// Exits 0 if all match, 1 if any differ.
//
// Compares: valid, checks (name+status), coverage (normalized), claims, version
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

function deepEqual(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (typeof a !== typeof b) return false;
  if (typeof a !== 'object') return false;

  const keysA = Object.keys(a).sort();
  const keysB = Object.keys(b).sort();
  if (keysA.length !== keysB.length) return false;
  for (let i = 0; i < keysA.length; i++) {
    if (keysA[i] !== keysB[i]) return false;
    if (!deepEqual(a[keysA[i]], b[keysB[i]])) return false;
  }
  return true;
}

// Normalize coverage to flat {total, verified, score} for comparison.
// Native uses V4Coverage: {evidence:{total,verified}, relations:{total,verified}, claims:{total,verified}, score}
// WASM v0.3 uses flat: {total, verified, score} (plus extra V4 fields from the native wrapper)
// WASM v0.4 uses V4Coverage same as native.
function normalizeCoverage(c) {
  if (!c) return { total: 0, verified: 0, score: 0 };

  // If it has evidence/relations/claims sub-objects, it's V4 format
  if (c.evidence && typeof c.evidence === 'object') {
    const total = (c.evidence.total || 0) + (c.relations.total || 0) + (c.claims.total || 0);
    const verified = (c.evidence.verified || 0) + (c.relations.verified || 0) + (c.claims.verified || 0);
    return { total, verified, score: c.score || 0 };
  }

  // Flat format
  return { total: c.total || 0, verified: c.verified || 0, score: c.score || 0 };
}

for (const file of nativeFiles) {
  const name = path.basename(file, '.result.json');
  if (!wasmFiles.has(file)) {
    console.log(`  [FAIL] ${name} — missing WASM result`);
    fail++;
    continue;
  }

  const native = JSON.parse(fs.readFileSync(path.join(nativeDir, file), 'utf8'));
  const wasm = JSON.parse(fs.readFileSync(path.join(wasmDir, file), 'utf8'));

  const diffs = [];

  // Compare valid
  if (native.result.valid !== wasm.result.valid) {
    diffs.push(`valid: native=${native.result.valid} wasm=${wasm.result.valid}`);
  }

  // Compare version
  if (native.version !== wasm.version) {
    diffs.push(`version: native=${native.version} wasm=${wasm.version}`);
  }

  // Compare checks (name + status)
  const nativeChecks = (native.result.checks || []).map(c => `${c.name}:${c.status}`);
  const wasmChecks = (wasm.result.checks || []).map(c => `${c.name}:${c.status}`);
  if (!deepEqual(nativeChecks, wasmChecks)) {
    diffs.push(`checks: native=${JSON.stringify(nativeChecks)} wasm=${JSON.stringify(wasmChecks)}`);
  }

  // Compare coverage (normalized to flat)
  const nativeCov = normalizeCoverage(native.result.coverage);
  const wasmCov = normalizeCoverage(wasm.result.coverage);
  if (!deepEqual(nativeCov, wasmCov)) {
    diffs.push(`coverage: native=${JSON.stringify(nativeCov)} wasm=${JSON.stringify(wasmCov)}`);
  }

  // Compare claims (id + valid + status)
  const nativeClaims = (native.result.claims || []).map(c => ({ id: c.id, valid: c.valid, status: c.status }));
  const wasmClaims = (wasm.result.claims || []).map(c => ({ id: c.id, valid: c.valid, status: c.status }));
  if (!deepEqual(nativeClaims, wasmClaims)) {
    diffs.push(`claims: native=${JSON.stringify(nativeClaims)} wasm=${JSON.stringify(wasmClaims)}`);
  }

  if (diffs.length === 0) {
    console.log(`  [PASS] ${name} — native.valid=${native.result.valid} wasm.valid=${wasm.result.valid}`);
    pass++;
  } else {
    console.log(`  [FAIL] ${name}`);
    for (const d of diffs) {
      console.log(`         ${d}`);
    }
    fail++;
  }
}

// Check for WASM results with no native counterpart
for (const file of wasmFiles) {
  const name = path.basename(file, '.result.json');
  if (!nativeFiles.includes(file)) {
    console.log(`  [FAIL] ${name} — missing native result`);
    fail++;
  }
}

console.log(`\nDifferential: ${pass} match, ${fail} differ`);
if (fail > 0) process.exit(1);
