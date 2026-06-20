# 🔐 Zero-Knowledge Vault — Build & Run Guide

## What You're Building

A fully offline, encrypted password manager that:
- Runs 100% in your browser (no server needed)
- Uses **Argon2id** to derive your key (never stored)
- Encrypts everything with **AES-256-GCM**
- Locks you out after repeated failures (brute-force protection)
- Self-destructs after 16 attempts
- Installs as a **PWA** on Android / ChromeOS

---

## Prerequisites

### 1. Install Go (≥ 1.21)

**Windows:** Download from https://go.dev/dl/ → run installer

**macOS:**
```bash
brew install go
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt install golang-go
```

**Verify:**
```bash
go version
# Should print: go version go1.21.x ...
```

---

## Step 1: Set Up Your Project Folder

```bash
mkdir my-vault
cd my-vault
```

Copy these files into `my-vault/`:
```
my-vault/
├── main.go
├── go.mod
├── index.html
├── vault-bridge.js
├── sw.js
├── manifest.json
```

---

## Step 2: Install the Go Dependency (Argon2)

```bash
go mod tidy
```

This downloads `golang.org/x/crypto` (the Argon2 package).
You'll see something like:
```
go: downloading golang.org/x/crypto v0.17.0
```

---

## Step 3: Copy the WASM Runtime Shim

Go ships a JavaScript helper file called `wasm_exec.js`. You **must** copy it next to your `index.html`:

```bash
# Find your Go installation root:
go env GOROOT

# Copy wasm_exec.js (replace /usr/local/go with your GOROOT):
cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .
```

**Windows (PowerShell):**
```powershell
$goroot = go env GOROOT
Copy-Item "$goroot\misc\wasm\wasm_exec.js" .
```

---

## Step 4: Compile Go → WebAssembly

```bash
GOOS=js GOARCH=wasm go build -o vault.wasm main.go
```

**Windows (PowerShell):**
```powershell
$env:GOOS="js"
$env:GOARCH="wasm"
go build -o vault.wasm main.go
```

**What this does:** Cross-compiles your Go code to run inside the browser's WebAssembly engine.

After this, your folder should look like:
```
my-vault/
├── main.go
├── go.mod
├── go.sum
├── index.html
├── vault-bridge.js
├── sw.js
├── manifest.json
├── vault.wasm       ← NEW
└── wasm_exec.js     ← NEW (copied from Go SDK)
```

---

## Step 5: Run Locally (HTTP Server Required)

**IMPORTANT:** You cannot open `index.html` directly from the filesystem (`file://`).
WebAssembly and Service Workers require an HTTP server.

### Option A — Python (simplest, no install needed)

```bash
# Python 3 (built into macOS and most Linux)
python3 -m http.server 8080
```

Open: http://localhost:8080

### Option B — Go (if you have Go installed)

```bash
go run -v -exec "$(go env GOROOT)/misc/wasm/go_js_wasm_exec" .
```

Or a simple static server:
```bash
# Install once:
go install golang.org/x/tools/cmd/staticcheck@latest

# Or use this one-liner:
go run golang.org/x/net/http2/h2c@latest
```

### Option C — Node.js

```bash
npx serve .
```

Open: http://localhost:3000

### Option D — VS Code Extension

Install "Live Server" by Ritwick Dey → right-click `index.html` → "Open with Live Server"

---

## Step 6: First Use

1. Open http://localhost:8080
2. Click the **"New Vault"** tab
3. Create a strong master password (the strength meter guides you)
4. Click **"CREATE VAULT"** — Argon2id will run (takes ~1 second, that's intentional)
5. Add your first password entry with **+ ADD**
6. Click **↓ EXPORT** to save your `vault-YYYY-MM-DD.vault` file

**To unlock later:**
1. Click **"Unlock Vault"**
2. Select your `.vault` file
3. Enter master password → **UNLOCK**

---

## Step 7: Install as PWA (Android / ChromeOS)

### Android (Chrome):
1. Open http://localhost:8080 in Chrome
2. Tap the **⋮ menu** → "Add to Home screen"
3. The app installs and works fully offline

### ChromeOS:
1. Open in Chrome
2. Look for the **install icon** (⊕) in the address bar
3. Click "Install"

### Desktop (Chrome/Edge):
- Same install icon in the address bar → "Install Zero-Knowledge Vault"

---

## Security Architecture — What's Happening

```
Your Password
     │
     ▼
Argon2id (3 iterations, 64MB RAM, 4 threads)
     │  ← This intentionally takes ~1 second
     ▼
 32-byte Derived Key
     │
     ├── SHA-256(key) → authHash  (saved in .vault, used for verification)
     │                            ← The key itself is NEVER stored
     │
     └── AES-256-GCM encrypt/decrypt
              │
              ▼
         vault.nonce + vault.ciphertext  (saved in .vault file)
```

### The Lockout Schedule Explained

| Attempt # | Wait Time | Why |
|-----------|-----------|-----|
| 1–5       | 0 seconds | Normal use |
| 6         | 30 seconds | First slowdown |
| 7         | 1 minute | Doubling begins |
| 8         | 2 minutes | |
| 9         | 4 minutes | |
| 10        | 8 minutes | |
| 11        | 16 minutes | |
| ...       | doubles each time | |
| 16        | **SELF-DESTRUCT** | Wipes in-app vault |

### Why the Timer Survives Page Refresh

The attempt counter is stored in **IndexedDB** (a browser database that persists across refreshes). Clearing cookies won't reset it — you'd need to clear site data.

But even if someone clears site data and resets the counter:
> They still don't have your **Master Password**, and the `.vault` file is still encrypted with AES-256-GCM. The timer only protects physical access (someone holding your phone).

---

## Troubleshooting

### "WASM LOAD FAILED"
→ You're opening the file directly. Use `python3 -m http.server 8080` instead.

### "TypeError: WebAssembly.instantiateStreaming"
→ Missing `wasm_exec.js`. Re-run the copy command in Step 3.

### "go: module not found" on go mod tidy
→ Make sure you have internet access for the first `go mod tidy`. After that, everything is cached.

### Argon2id taking too long (>5 seconds)
→ Your machine may be slow. You can reduce `argonMemory` in `main.go` from `64*1024` to `32*1024`. This is less secure but more responsive.

### Build fails on Windows "GOOS/GOARCH not recognized"
→ Use the PowerShell method shown in Step 4 (set env vars separately).

---

## File Reference

| File | Purpose |
|------|---------|
| `main.go` | Go/WASM: Argon2id, AES-256-GCM, key derivation |
| `vault-bridge.js` | JS: IndexedDB lockout, timer, WASM loader |
| `index.html` | UI: Lock screen, vault manager, countdown |
| `sw.js` | Service Worker: PWA offline caching |
| `manifest.json` | PWA metadata (name, icons, display mode) |
| `vault.wasm` | *Compiled* — generated by `go build` |
| `wasm_exec.js` | *Copied* — Go's JS runtime shim |

---

## For the Aspiring Developer: Key Concepts Used

- **WebAssembly (WASM):** Compiled binary format that runs in browsers at near-native speed. Go compiles to it with `GOOS=js GOARCH=wasm`.
- **Argon2id:** Memory-hard password hashing. The "memory-hard" part means an attacker needs lots of RAM to brute-force it — GPUs (used for cracking) have limited RAM per core.
- **AES-256-GCM:** Authenticated encryption. "Authenticated" means if anyone tampers with the ciphertext, decryption fails — not just wrong output, but a hard error.
- **Zero-Knowledge:** The server (or in this case, any storage) never sees your key. Only you can derive it from your password.
- **IndexedDB:** Browser key-value database. Survives page refresh, unlike `localStorage` (well, both survive, but IndexedDB handles large structured data better).
- **Service Worker:** A background script that intercepts network requests. Here it serves cached files when offline — making the app fully functional without internet.
