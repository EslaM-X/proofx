#!/usr/bin/env node
// conformance/wasm/run.js — Runs proofx.wasm verification against the corpus
// and writes result.json files for comparison with native results.
//
// Usage: node conformance/wasm/run.js
// Requires: Node.js 18+, proofx.wasm in static/

const fs = require('fs');
const path = require('path');

// Load Go WASM support
const goPath = path.join(__dirname, '..', '..', 'static', 'wasm_exec.js');
if (!fs.existsSync(goPath)) {
  console.error('wasm_exec.js not found at', goPath);
  process.exit(1);
}
require(goPath);

const wasmPath = path.join(__dirname, '..', '..', 'static', 'proofx.wasm');
if (!fs.existsSync(wasmPath)) {
  console.error('proofx.wasm not found at', wasmPath);
  process.exit(1);
}

const corpusDir = path.join(__dirname, '..', 'corpus');
const expectedDir = path.join(__dirname, '..', 'expected');
const outputDir = path.join(__dirname);

async function main() {
  const go = new Go();
  const wasmBuffer = fs.readFileSync(wasmPath);
  const result = await WebAssembly.instantiate(wasmBuffer, go.importObject);
  go.run(result.instance);

  const verifyFn = globalThis.verifyProof;
  if (!verifyFn) {
    console.error('verifyProof not available after WASM init');
    process.exit(1);
  }

  const results = [];
  const subdirs = ['valid', 'invalid', 'malformed'];

  for (const subdir of subdirs) {
    const dir = path.join(corpusDir, subdir);
    if (!fs.existsSync(dir)) continue;
    const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
    for (const file of files) {
      const name = path.basename(file, '.json');
      const proofPath = path.join(dir, file);
      const expectedPath = path.join(expectedDir, file);

      const proofBytes = fs.readFileSync(proofPath);
      let res;
      try {
        const resultStr = verifyFn(proofBytes.toString());
        res = JSON.parse(resultStr);
      } catch (e) {
        res = { valid: false, version: 'error', checks: [{ name: 'wasm-error', status: 'fail', detail: e.message }], coverage: { evidence: { total: 0, verified: 0 }, relations: { total: 0, verified: 0 }, claims: { total: 0, verified: 0 }, score: 0 } };
      }

      // Normalize: WASM output may not have coverage dimensions — add defaults
      if (!res.coverage) res.coverage = { evidence: { total: 0, verified: 0 }, relations: { total: 0, verified: 0 }, claims: { total: 0, verified: 0 }, score: 0 };
      if (!res.coverage.evidence) res.coverage.evidence = { total: 0, verified: 0 };
      if (!res.coverage.relations) res.coverage.relations = { total: 0, verified: 0 };
      if (!res.coverage.claims) res.coverage.claims = { total: 0, verified: 0 };

      // Compare with expected
      let success = false;
      if (fs.existsSync(expectedPath)) {
        const expected = JSON.parse(fs.readFileSync(expectedPath, 'utf8'));
        success = (res.valid === expected.valid);
      }

      // Detect version from WASM output
      const version = res.version || 'unknown';

      const nr = { name, result: res, version, success };
      results.push(nr);

      const outPath = path.join(outputDir, name + '.result.json');
      fs.writeFileSync(outPath, JSON.stringify(nr, null, 2));

      const status = success ? 'PASS' : 'FAIL';
      console.log(`  [${status}] ${name} (valid=${res.valid}, version=${version})`);
    }
  }

  console.log(`WASM runner: ${results.length} cases`);
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
