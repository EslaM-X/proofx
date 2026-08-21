// verify.js — WASM bridge for proofx.dev
// Loads proofx.wasm and exposes window.verifyProofDocument(jsonString)
// → Promise<{valid, checks, coverage}>

let wasmReady = false;
let wasmError = null;
let wasmVerifyFn = null;

async function initWasm() {
  try {
    if (typeof Go === 'undefined') {
      throw new Error('wasm_exec.js not loaded');
    }
    const go = new Go();
    const result = await WebAssembly.instantiateStreaming(
      fetch('proofx.wasm'),
      go.importObject
    );
    go.run(result.instance);
    // The WASM module sets window.verifyProof via js.Global().Set()
    wasmVerifyFn = window.verifyProof;
    wasmReady = true;
    window.wasmReady = true;
    document.dispatchEvent(new Event('wasm-ready'));
  } catch (e) {
    wasmError = e.message;
    console.error('ProofX WASM init failed:', e);
    document.dispatchEvent(new Event('wasm-error'));
  }
}

// Public API: verifyProofDocument(jsonString) → Promise<{valid, checks, coverage}>
window.verifyProofDocument = function (input) {
  return new Promise((resolve, reject) => {
    if (!wasmReady) {
      if (wasmError) {
        reject(new Error('WASM failed to load: ' + wasmError));
      } else {
        reject(new Error('WASM not initialized yet'));
      }
      return;
    }
    if (!wasmVerifyFn) {
      reject(new Error('verifyProof function not available'));
      return;
    }
    try {
      const result = wasmVerifyFn(input);
      resolve(JSON.parse(result));
    } catch (e) {
      reject(e);
    }
  });
};

// Auto-initialize when script loads
initWasm();
