// vault-bridge.js — JavaScript Security Bridge
// Handles: WASM loading, IndexedDB attempt tracking, lockout timer, UI wiring

'use strict';

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────
const DB_NAME        = 'VaultSecurity';
const DB_VERSION     = 1;
const STORE_NAME     = 'attempts';
const RECORD_KEY     = 'lockState';
const SELF_DESTRUCT_ATTEMPT = 16;

// Lockout schedule in seconds (index = attempt number, 0-based)
// Attempts 1-5 (index 0-4): 0s wait
// Attempt 6 (index 5): 30s, 7: 60s, 8: 120s, then doubles each time
function getLockoutSeconds(attemptNumber) {
  if (attemptNumber <= 5)  return 0;
  if (attemptNumber === 6)  return 30;
  const extra = attemptNumber - 6; // 1, 2, 3...
  return 30 * Math.pow(2, extra - 1) * 2; // 30→60→120→240→...
}

// ─────────────────────────────────────────────
// IndexedDB helpers
// ─────────────────────────────────────────────
function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = e => {
      e.target.result.createObjectStore(STORE_NAME, { keyPath: 'id' });
    };
    req.onsuccess = e => resolve(e.target.result);
    req.onerror   = e => reject(e.target.error);
  });
}

async function getRecord() {
  const db = await openDB();
  return new Promise((resolve) => {
    const tx  = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(RECORD_KEY);
    req.onsuccess = e => resolve(e.target.result || { id: RECORD_KEY, attempts: 0, lockedUntil: 0 });
    req.onerror   = () => resolve({ id: RECORD_KEY, attempts: 0, lockedUntil: 0 });
  });
}

async function setRecord(data) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx  = db.transaction(STORE_NAME, 'readwrite');
    const req = tx.objectStore(STORE_NAME).put({ id: RECORD_KEY, ...data });
    req.onsuccess = () => resolve();
    req.onerror   = e => reject(e.target.error);
  });
}

async function deleteRecord() {
  const db = await openDB();
  return new Promise((resolve) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).delete(RECORD_KEY);
    tx.oncomplete = resolve;
  });
}

// ─────────────────────────────────────────────
// Vault State (in-memory only — NEVER persisted)
// ─────────────────────────────────────────────
window.VaultState = {
  isUnlocked:  false,
  masterPass:  null,   // cleared on lock
  saltB64:     null,
  authHash:    null,
  entries:     [],     // array of VaultEntry objects

  clear() {
    this.isUnlocked = false;
    this.masterPass = null;
    this.saltB64    = null;
    this.authHash   = null;
    this.entries    = [];
  }
};

// ─────────────────────────────────────────────
// Lockout Timer (UI)
// ─────────────────────────────────────────────
let countdownInterval = null;

function startCountdown(remainingMs, onExpire) {
  clearInterval(countdownInterval);
  UI.showLockScreen(true);

  const update = () => {
    const now  = Date.now();
    const rec  = window._lockUntil || 0;
    const left = Math.max(0, rec - now);

    if (left <= 0) {
      clearInterval(countdownInterval);
      UI.setCountdown('');
      UI.setLockBtnDisabled(false);
      UI.showLockScreen(false);
      onExpire && onExpire();
      return;
    }

    const secs = Math.ceil(left / 1000);
    const m    = Math.floor(secs / 60);
    const s    = secs % 60;
    const txt  = m > 0 ? `${m}m ${String(s).padStart(2,'0')}s` : `${s}s`;
    UI.setCountdown(txt);
    UI.setLockBtnDisabled(true);
  };

  update();
  countdownInterval = setInterval(update, 500);
}

// ─────────────────────────────────────────────
// Core: Attempt Login
// ─────────────────────────────────────────────
window.attemptUnlock = async function(password, vaultJSON) {
  const rec = await getRecord();
  const now = Date.now();

  // Check if currently locked out
  if (rec.lockedUntil > now) {
    window._lockUntil = rec.lockedUntil;
    startCountdown(rec.lockedUntil - now, null);
    return { success: false, status: 'LOCKED', lockedUntil: rec.lockedUntil };
  }

  // Self-destruct check
  if (rec.attempts >= SELF_DESTRUCT_ATTEMPT) {
    await triggerSelfDestruct();
    return { success: false, status: 'SELF_DESTRUCT' };
  }

  // Try to decrypt
  let result;
  try {
    const raw = window.vaultUnlock(password, vaultJSON);
    result = JSON.parse(raw);
  } catch(e) {
    result = { error: 'WASM_ERROR' };
  }

  if (result.error === 'WRONG_PASSWORD') {
    const newAttempts = rec.attempts + 1;

    if (newAttempts >= SELF_DESTRUCT_ATTEMPT) {
      await triggerSelfDestruct();
      return { success: false, status: 'SELF_DESTRUCT' };
    }

    const waitSecs    = getLockoutSeconds(newAttempts);
    const lockedUntil = waitSecs > 0 ? (now + waitSecs * 1000) : 0;

    await setRecord({ attempts: newAttempts, lockedUntil });

    if (waitSecs > 0) {
      window._lockUntil = lockedUntil;
      startCountdown(waitSecs * 1000, null);
      return { success: false, status: 'LOCKED', waitSecs, attemptsLeft: SELF_DESTRUCT_ATTEMPT - newAttempts };
    }

    return {
      success:      false,
      status:       'WRONG_PASSWORD',
      attempts:     newAttempts,
      attemptsLeft: SELF_DESTRUCT_ATTEMPT - newAttempts,
      waitSecs:     getLockoutSeconds(newAttempts + 1) // show what NEXT failure costs
    };
  }

  if (result.error) {
    return { success: false, status: 'ERROR', message: result.error };
  }

  // ✅ SUCCESS — reset counter
  await setRecord({ attempts: 0, lockedUntil: 0 });
  clearInterval(countdownInterval);
  return { success: true, entries: result };
};

// ─────────────────────────────────────────────
// Self-Destruct
// ─────────────────────────────────────────────
async function triggerSelfDestruct() {
  // 1. Wipe IndexedDB
  await deleteRecord();

  // 2. Zero out in-memory vault
  VaultState.clear();

  // 3. Clear all localStorage keys related to vault
  Object.keys(localStorage).forEach(k => {
    if (k.startsWith('vault_')) localStorage.removeItem(k);
  });

  // 4. Show self-destruct screen
  UI.showSelfDestruct();

  console.warn('[VAULT] Self-destruct triggered. In-app vault wiped.');
}

// ─────────────────────────────────────────────
// Core: Create New Vault
// ─────────────────────────────────────────────
window.createNewVault = async function(masterPassword) {
  const raw    = window.vaultCreateNew(masterPassword);
  const result = JSON.parse(raw);
  if (result.error) throw new Error(result.error);

  VaultState.masterPass = masterPassword;
  VaultState.saltB64    = result.salt;
  VaultState.authHash   = result.authHash;
  VaultState.entries    = [];
  VaultState.isUnlocked = true;

  await setRecord({ attempts: 0, lockedUntil: 0 });
  return result;
};

// ─────────────────────────────────────────────
// Core: Export .vault file
// ─────────────────────────────────────────────
window.exportVault = async function() {
  if (!VaultState.isUnlocked) throw new Error('Vault locked');

  const entriesJSON = JSON.stringify(VaultState.entries);
  const raw = window.vaultSave(
    VaultState.masterPass,
    VaultState.saltB64,
    VaultState.authHash,
    entriesJSON
  );
  const result = JSON.parse(raw);
  if (result.error) throw new Error(result.error);

  const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `vault-${new Date().toISOString().slice(0,10)}.vault`;
  a.click();
  URL.revokeObjectURL(url);
};

// ─────────────────────────────────────────────
// Core: Import .vault file
// ─────────────────────────────────────────────
window.importVaultFile = function(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload  = e => resolve(e.target.result);
    reader.onerror = () => reject(new Error('File read failed'));
    reader.readAsText(file);
  });
};

// ─────────────────────────────────────────────
// Core: Generate Password (calls WASM)
// ─────────────────────────────────────────────
window.generateSecurePassword = function(length = 20, useSymbols = true) {
  return window.vaultGenPassword(length, useSymbols);
};

// ─────────────────────────────────────────────
// Restore lockout on page load
// ─────────────────────────────────────────────
async function checkLockoutOnLoad() {
  const rec = await getRecord();
  const now = Date.now();
  if (rec.lockedUntil > now) {
    window._lockUntil = rec.lockedUntil;
    startCountdown(rec.lockedUntil - now, null);
  }
  if (rec.attempts >= SELF_DESTRUCT_ATTEMPT) {
    await triggerSelfDestruct();
  }
}

// ─────────────────────────────────────────────
// WASM Loader
// ─────────────────────────────────────────────
window.onVaultWasmReady = function() {
  console.log('[vault-bridge] WASM ready');
  checkLockoutOnLoad().then(() => {
    document.dispatchEvent(new CustomEvent('vaultReady'));
  });
};

async function loadWasm() {
  const go = new Go();
  const result = await WebAssembly.instantiateStreaming(fetch('vault.wasm'), go.importObject);
  go.run(result.instance);
}

// Load wasm_exec.js shim first, then our wasm
// (wasm_exec.js is provided by the Go SDK — see build guide)
loadWasm().catch(e => {
  console.error('[vault-bridge] WASM load failed:', e);
  document.dispatchEvent(new CustomEvent('vaultWasmError', { detail: e.message }));
});
