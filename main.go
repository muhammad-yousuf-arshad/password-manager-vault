// main.go — Zero-Knowledge Password Vault (WebAssembly)
// Compile: GOOS=js GOARCH=wasm go build -o vault.wasm main.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"syscall/js"
	"time"

	"golang.org/x/crypto/argon2"
)

// ─────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────

type VaultEntry struct {
	ID       string `json:"id"`
	Site     string `json:"site"`
	Username string `json:"username"`
	Password string `json:"password"`
	Notes    string `json:"notes"`
	Created  string `json:"created"`
}

type VaultFile struct {
	Version   int    `json:"version"`
	Salt      string `json:"salt"`      // base64 Argon2id salt
	AuthHash  string `json:"authHash"`  // SHA-256(derivedKey) for unlock verification
	Nonce     string `json:"nonce"`     // base64 AES-GCM nonce
	Ciphertext string `json:"ciphertext"` // base64 encrypted entries JSON
}

// ─────────────────────────────────────────────
// Argon2id Parameters (OWASP recommended)
// ─────────────────────────────────────────────
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 32
)

// ─────────────────────────────────────────────
// Key Derivation
// ─────────────────────────────────────────────

func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		argonTime,
		argonMemory,
		argonThreads,
		argonKeyLen,
	)
}

func keyAuthHash(key []byte) string {
	h := sha256.Sum256(key)
	return base64.StdEncoding.EncodeToString(h[:])
}

// ─────────────────────────────────────────────
// AES-256-GCM Encrypt / Decrypt
// ─────────────────────────────────────────────

func encrypt(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

func decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ─────────────────────────────────────────────
// JS-Exported: createVault
// Args: masterPassword (string)
// Returns: { salt, authHash } as JSON string
// ─────────────────────────────────────────────

func jsCreateVault(_ js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return jsError("createVault: missing masterPassword")
	}
	password := args[0].String()

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return jsError("createVault: rand failed: " + err.Error())
	}

	key := deriveKey(password, salt)
	defer zeroBytes(key)

	authHash := keyAuthHash(key)

	result := map[string]string{
		"salt":     base64.StdEncoding.EncodeToString(salt),
		"authHash": authHash,
	}
	b, _ := json.Marshal(result)
	return string(b)
}

// ─────────────────────────────────────────────
// JS-Exported: unlockVault
// Args: masterPassword, vaultFileJSON
// Returns: JSON array of VaultEntry or error JSON
// ─────────────────────────────────────────────

func jsUnlockVault(_ js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return jsError("unlockVault: requires password + vaultJSON")
	}
	password := args[0].String()
	vaultJSON := args[1].String()

	var vf VaultFile
	if err := json.Unmarshal([]byte(vaultJSON), &vf); err != nil {
		return jsError("unlockVault: invalid vault format")
	}

	salt, err := base64.StdEncoding.DecodeString(vf.Salt)
	if err != nil {
		return jsError("unlockVault: bad salt encoding")
	}

	key := deriveKey(password, salt)
	defer zeroBytes(key)

	// Verify master password without storing the key itself
	if keyAuthHash(key) != vf.AuthHash {
		return `{"error":"WRONG_PASSWORD"}`
	}

	nonce, err := base64.StdEncoding.DecodeString(vf.Nonce)
	if err != nil {
		return jsError("unlockVault: bad nonce encoding")
	}
	ct, err := base64.StdEncoding.DecodeString(vf.Ciphertext)
	if err != nil {
		return jsError("unlockVault: bad ciphertext encoding")
	}

	plaintext, err := decrypt(key, nonce, ct)
	if err != nil {
		return jsError("unlockVault: decryption failed")
	}
	defer zeroBytes(plaintext)

	return string(plaintext)
}

// ─────────────────────────────────────────────
// JS-Exported: saveVault
// Args: masterPassword, saltB64, authHash, entriesJSON
// Returns: full VaultFile JSON string ready to download
// ─────────────────────────────────────────────

func jsSaveVault(_ js.Value, args []js.Value) interface{} {
	if len(args) < 4 {
		return jsError("saveVault: requires password, salt, authHash, entriesJSON")
	}
	password := args[0].String()
	saltB64 := args[1].String()
	authHash := args[2].String()
	entriesJSON := args[3].String()

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return jsError("saveVault: bad salt")
	}

	key := deriveKey(password, salt)
	defer zeroBytes(key)

	if keyAuthHash(key) != authHash {
		return `{"error":"WRONG_PASSWORD"}`
	}

	nonce, ciphertext, err := encrypt(key, []byte(entriesJSON))
	if err != nil {
		return jsError("saveVault: encryption failed")
	}

	vf := VaultFile{
		Version:    1,
		Salt:       saltB64,
		AuthHash:   authHash,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	b, _ := json.Marshal(vf)
	return string(b)
}

// ─────────────────────────────────────────────
// JS-Exported: generatePassword
// Args: length (int), useSymbols (bool)
// Returns: random password string
// ─────────────────────────────────────────────

func jsGeneratePassword(_ js.Value, args []js.Value) interface{} {
	length := 20
	useSymbols := true
	if len(args) >= 1 {
		length = args[0].Int()
	}
	if len(args) >= 2 {
		useSymbols = args[1].Bool()
	}
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if useSymbols {
		charset += "!@#$%^&*()-_=+[]{}|;:,.<>?"
	}
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return jsError("generatePassword: rand failed")
	}
	for i, b := range buf {
		buf[i] = charset[int(b)%len(charset)]
	}
	return string(buf)
}

// ─────────────────────────────────────────────
// JS-Exported: deriveKeyWithDelay
// Runs Argon2id and signals JS when done (simulates async)
// Args: password (string), salt (string, b64)
// Returns: authHash string
// ─────────────────────────────────────────────

func jsDeriveKeyBenchmark(_ js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return jsError("benchmark: missing args")
	}
	password := args[0].String()
	saltB64 := args[1].String()
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return jsError("benchmark: bad salt")
	}
	start := time.Now()
	key := deriveKey(password, salt)
	elapsed := time.Since(start).Milliseconds()
	h := keyAuthHash(key)
	zeroBytes(key)
	result := map[string]interface{}{
		"authHash": h,
		"ms":       elapsed,
	}
	b, _ := json.Marshal(result)
	return string(b)
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func jsError(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b)
}

// ─────────────────────────────────────────────
// main: Register JS functions and block forever
// ─────────────────────────────────────────────

func main() {
	fmt.Println("[vault.wasm] Zero-Knowledge Vault loaded.")

	js.Global().Set("vaultCreateNew", js.FuncOf(jsCreateVault))
	js.Global().Set("vaultUnlock", js.FuncOf(jsUnlockVault))
	js.Global().Set("vaultSave", js.FuncOf(jsSaveVault))
	js.Global().Set("vaultGenPassword", js.FuncOf(jsGeneratePassword))
	js.Global().Set("vaultBenchmark", js.FuncOf(jsDeriveKeyBenchmark))

	// Signal JS that WASM is ready
	js.Global().Call("onVaultWasmReady")

	// Keep the Go runtime alive
	select {}
}
