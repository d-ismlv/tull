# APK Security Report: Acme Bank

| Field | Value |
|-------|-------|
| File | `acme_bank_v4.1.2.apk` |
| Package | `com.acmebank.mobile` |
| Version | 4.1.2 |
| Size | 38.4 MB |
| SHA256 | `a3f8c2d1e9b047a6f5c3d2e1b8a9f0c4d7e6b5a4f3c2d1e0b9a8f7c6d5e4b3` |
| Risk Level | **HIGH** |
| MobSF Score | 41 / 100  (CVSS avg: 6.8) |
| Analyzed | 2026-04-21 08:14 UTC |

---

## Executive Summary

Acme Bank is a retail banking application serving account management, fund transfers, and card controls. The overall risk posture is **HIGH**. Two findings stand out: a hardcoded RSA private key embedded directly in the application source, and a WebView JavaScript bridge that exposes a token-retrieval method to any page loaded in the view. Both are directly exploitable without privileged access. Seven additional findings cover SSL validation weaknesses, insecure local storage of session tokens, and overly permissive exported components.

---

## Findings

### 🔴 Critical

#### [C-01] Hardcoded RSA Private Key in Source

- **Category**: Hardcoded Credential / Private Key Material
- **Location**: `com/acmebank/mobile/crypto/SigningHelper.java:23`

**Evidence:**
```java
private static final String PRIVATE_KEY =
    "-----BEGIN RSA PRIVATE KEY-----\n" +
    "MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29W7XSJJ7Nkab\n" +
    "jHDdCMCeEfMpKNMBqFPMEhRMoFcCCBVMSCxQGJi5RKiPrH8dOoVCMXg7SW0VFg\n" +
    // ... 22 more lines
    "-----END RSA PRIVATE KEY-----";
```

**Impact**: Anyone who decompiles this APK obtains the private key used to sign requests to the transaction API. An attacker can forge signed requests, authorise transfers, or impersonate the mobile client at the server side.

**Recommendation**: Remove the key from source immediately. Use Android Keystore to generate and store signing keys on-device; the private key material never leaves secure hardware. Rotate the exposed key on all backend services now.

---

#### [C-02] Authentication Token Exposed via JavaScript Bridge

- **Category**: WebView JS Bridge
- **Location**: `com/acmebank/mobile/webview/BridgeActivity.java:81`

**Evidence:**
```java
webView.addJavascriptInterface(new Object() {
    @JavascriptInterface
    public String getSessionToken() {
        return SessionManager.getInstance().getToken();  // returns live Bearer token
    }
}, "AcmeBridge");
```

**Impact**: `addJavascriptInterface` exposes the annotated method to every page loaded in this WebView. If the view loads any attacker-controlled URL (via a deep link or server-side redirect), JavaScript running on that page calls `AcmeBridge.getSessionToken()` and exfiltrates the live session token. Full account takeover without any user interaction.

**Recommendation**: Remove the bridge entirely. Pass data to the WebView at load time via `evaluateJavascript` with explicit, minimal payloads. Restrict the WebView to a fixed origin allowlist.

---

### 🟠 High

#### [H-01] SSL Hostname Verification Disabled in HTTP Client

- **Category**: SSL Bypass
- **Location**: `com/acmebank/mobile/net/ApiClient.java:57`

**Evidence:**
```java
builder.hostnameVerifier((hostname, session) -> true);
```

**Impact**: Any TLS certificate for any hostname is accepted. A network attacker performing a MitM on the same Wi-Fi segment intercepts all API traffic, including credentials and account data, without the user receiving any warning.

**Recommendation**: Remove the custom `HostnameVerifier`. The default Android verifier is correct. If certificate pinning is desired, implement it via `network_security_config.xml`.

---

#### [H-02] Session Token Written to External Storage

- **Category**: Sensitive Data Exposure
- **Location**: `com/acmebank/mobile/session/SessionCache.java:34`

**Evidence:**
```java
File cacheFile = new File(Environment.getExternalStorageDirectory(), "session.dat");
FileOutputStream fos = new FileOutputStream(cacheFile);
fos.write(token.getBytes());
```

**Impact**: Files on external storage are world-readable by any app holding `READ_EXTERNAL_STORAGE`. On Android 9 and below (still a significant install base per MobSF tracker data) this requires no permission at all. Token theft enables account takeover.

**Recommendation**: Use `getFilesDir()` (internal storage, app-private) or `EncryptedSharedPreferences` from Jetpack Security. Never write auth material to external storage.

---

### 🟡 Medium

#### [M-01] ECB Mode Used for PAN Encryption

- **Category**: Unsafe Cryptography
- **Location**: `com/acmebank/mobile/crypto/CardEncryptor.java:19`

**Evidence:**
```java
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
```

**Impact**: ECB mode does not use an IV; identical plaintext blocks produce identical ciphertext blocks. For structured data like card PANs this leaks patterns and enables chosen-plaintext attacks. Not immediately exploitable without access to the ciphertext, but a defence-in-depth failure in a PCI-relevant context.

**Recommendation**: Replace with `AES/GCM/NoPadding`. GCM provides authenticated encryption; no padding oracle is possible and integrity is guaranteed.

---

#### [M-02] Deep Link Handler Accepts Arbitrary URLs Without Validation

- **Category**: Dangerous Component Exposure
- **Location**: `com/acmebank/mobile/DeepLinkActivity.java:44` · `AndroidManifest.xml`

**Evidence:**
```java
String url = getIntent().getStringExtra("target_url");
webView.loadUrl(url);  // no allowlist check
```

Manifest declares `android:exported="true"` with `<intent-filter>` for `acmebank://open`.

**Impact**: Any installed application can fire `acmebank://open?target_url=https://attacker.example` and have the WebView load an attacker-controlled page. Combined with the JavaScript bridge [C-02], this is a complete account-takeover chain requiring only a second app installed on the device.

**Recommendation**: Validate `target_url` against an explicit allowlist of trusted origins before loading. Remove `android:exported="true"` if external deep links are not a product requirement.

---

#### [M-03] Sensitive Fields Logged at DEBUG Level

- **Category**: Sensitive Data Logged
- **Location**: `com/acmebank/mobile/auth/LoginViewModel.java:88`

**Evidence:**
```java
Log.d("LoginVM", "login response: " + response.toString());  // includes auth token
```

**Impact**: Android log output is readable by any app holding `READ_LOGS` on pre-4.1 devices, and by ADB without root on all versions. Debug builds shipped to production (confirmed by MobSF: `debuggable=true` in manifest) expose this to anyone with USB access.

**Recommendation**: Remove sensitive values from log statements. Use ProGuard rules to strip all `Log.d` / `Log.v` calls in release builds. Set `android:debuggable="false"` in the release manifest.

---

### 🟢 Low / Informational

#### [L-01] Backup Enabled — Sensitive App Data Included

- **Category**: Android Backup
- **Location**: `AndroidManifest.xml`

**Evidence:**
```xml
<application android:allowBackup="true" ...>
```

**Impact**: ADB backup (`adb backup`) extracts the full app data directory including internal storage files, shared preferences, and databases without device unlock on older Android versions. Low risk on modern Android (11+) but still a concern for enterprise deployments with MDM policies.

**Recommendation**: Set `android:allowBackup="false"` or define a `BackupRules` XML that explicitly excludes credential stores.

---

#### [L-02] Cleartext HTTP Permitted in Network Security Config

- **Category**: Network Security
- **Location**: `res/xml/network_security_config.xml:8`

**Evidence:**
```xml
<base-config cleartextTrafficPermitted="true"/>
```

**Impact**: Non-TLS connections are permitted application-wide. No cleartext endpoints were observed in the discovered URL list, but the configuration allows them. Low risk if no cleartext endpoints exist in production.

**Recommendation**: Set `cleartextTrafficPermitted="false"`. Add explicit `<domain-config>` entries only if specific legacy endpoints require it.

---

## Attack Surface

### Permissions

| Permission | Type | Risk |
|---|---|---|
| `READ_EXTERNAL_STORAGE` | Dangerous | Used to read session cache written to external storage [H-02] |
| `WRITE_EXTERNAL_STORAGE` | Dangerous | Used to write session cache to external storage [H-02] |
| `CAMERA` | Dangerous | Cheque deposit feature — legitimate use |
| `READ_CONTACTS` | Dangerous | Payee autofill — review if strictly necessary |
| `INTERNET` | Normal | Required |
| `ACCESS_NETWORK_STATE` | Normal | Required |
| `RECEIVE_BOOT_COMPLETED` | Normal | Background sync — low risk |

### Exported Components

| Component | Type | Risk |
|---|---|---|
| `DeepLinkActivity` | Activity | Accepts arbitrary `target_url` parameter [M-02] |
| `SyncService` | Service | No permission check on `onStartCommand` — any app can trigger sync |
| `PushReceiver` | Receiver | Exported without `android:permission` — accepts intents from any app |

### Network Endpoints

- `https://api.acmebank.com/v3/` — primary REST API
- `https://cdn.acmebank.com/` — static assets
- `https://analytics.acmebank.com/` — telemetry (3rd party: Mixpanel)
- `https://maps.googleapis.com/` — branch locator feature

---

## Recommendations (Priority Order)

1. **[Immediate]** Rotate the exposed RSA private key on all backend services and remove it from source. Treat all previously signed requests as potentially forged.
2. **[Immediate]** Remove the `addJavascriptInterface` bridge. Audit all WebView loading points for unvalidated URL input.
3. **[This sprint]** Fix SSL hostname verification — remove the `(hostname, session) -> true` verifier.
4. **[This sprint]** Move session token storage from external storage to `EncryptedSharedPreferences`.
5. **[Short-term]** Replace ECB cipher mode with AES/GCM across all encryption calls.
6. **[Short-term]** Set `android:debuggable="false"` in release manifest; strip debug log calls via ProGuard.
7. **[Short-term]** Add permission checks to exported `SyncService` and `PushReceiver`.
8. **[Long-term]** Validate all deep-link `target_url` values against an origin allowlist.
9. **[Long-term]** Set `android:allowBackup="false"` and `cleartextTrafficPermitted="false"`.

---

## Tool Status

- ✅ **apkleaks** (41 findings across 8 categories)
- ✅ **jadx** (12,847 Java files decompiled)
- ✅ **mobsf** (score: 41/100 · cvss: 6.8)

---

*Generated by tull — APK Security Analyzer*
*Model: claude-sonnet-4-6 | Tools: APKLeaks · MobSF · JADX*
