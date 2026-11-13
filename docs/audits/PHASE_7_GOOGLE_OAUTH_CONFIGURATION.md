# CyberGuard Phase 7 Engineering Audit: Google OAuth 2.0 PKCE Configuration & Desktop Client Architecture

## Executive Summary

Phase 6 established the underlying desktop OAuth 2.0 PKCE engine, loopback HTTP callback listener, and Windows DPAPI-encrypted token storage. However, as noted in the executive review:
```text
GOOGLE_CLIENT_ID is absent.
Consequently, the application returns: { setupRequired: true }
```
Phase 7 audits the completed desktop OAuth authorization architecture, details the dual configuration mechanisms for administrative deployment, enforces strict state decoupling between CyberGuard user sessions and Gmail mailbox tokens, and provides an end-to-end Google Cloud Console setup guide.

---

## 1. Desktop OAuth 2.0 Architecture (RFC 8252 & PKCE)

### Desktop Native Flow Compliance
Desktop applications are public clients that cannot maintain the confidentiality of a client secret. In strict accordance with RFC 8252 (OAuth 2.0 for Native Apps) and Google Identity recommendations:
1. **Proof Key for Code Exchange (PKCE)**:
   - A high-entropy cryptographic code verifier (64 bytes URL-safe base64) is generated per authorization attempt.
   - A SHA-256 code challenge (`code_challenge_method=S256`) is computed and submitted with the authorization request.
2. **System Browser Authorization**:
   - The user is redirected to Google's official authorization endpoint via their default system browser (`electron.shell.openExternal`).
   - Embedded WebViews are strictly prohibited to prevent credential interception and maintain Google policy compliance.
3. **Ephemeral Loopback Callback Listener**:
   - CyberGuard binds an ephemeral HTTP server to `127.0.0.1` on a dynamically assigned port (`0`).
   - The redirect URI is deterministically formatted as `http://127.0.0.1:<port>/oauth2callback`.
   - The server validates the cryptographic `state` parameter to prevent Cross-Site Request Forgery (CSRF).
   - Once the authorization code or error is received, the server returns an informative HTML page to the browser and immediately closes the socket listener.

---

## 2. Decoupled Authentication State Model

As visible in the user's screenshots, the application displays two distinct authentication indicators:
- **CyberGuard User State**: Header pill (`Sign In` vs `User Profile / Role`).
- **Gmail Mailbox State**: Email Protection module (`DISCONNECTED` vs `PROTECTED` / `INITIAL_SYNC_PENDING`).

### Mandatory Pre-Condition Enforcement
In `desktop/frontend/app.js`:
```javascript
// OAuth Connect button
if (oauthBtn) {
  oauthBtn.addEventListener('click', async () => {
    const ep = AppState.endpoint;
    if (!ep) return;
    // Verify user is signed in to associate mailbox
    if (!AppState.currentUser) {
      alert('Please sign in to CyberGuard before connecting your Google account.\n' +
            '(CyberGuard account identity and Gmail authentication are separate states).');
      return;
    }
    ...
  });
}
```
**Guarantees:**
1. A guest or unauthenticated user cannot initiate mailbox binding.
2. Mailbox credentials and synchronization history are strictly keyed to the authenticated user's ID in SQLite (`local_store.js` and `user_<id>.db`).
3. Switching or logging out of the CyberGuard user profile automatically unbinds and clears the in-memory mailbox token context, preventing cross-tenant data leakage.

---

## 3. Configuration Mechanisms

CyberGuard supports two administrative configuration channels:

### Option A: Local Enclave / Environment Variables (`.env`)
In the application root or deployment configuration:
```env
# Google OAuth 2.0 Desktop Client Credentials
GOOGLE_CLIENT_ID=108234857239-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.apps.googleusercontent.com
# Optional: Client secret is NOT required for PKCE public desktop clients, but supported if configured
GOOGLE_CLIENT_SECRET=GOCSPX-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

### Option B: Runtime Settings Console
Within the desktop application under `Settings & Account` > `Cloud & Integration Settings`:
- Administrators can input or rotate the `Google Desktop Client ID`.
- The configuration is safely encrypted via Windows DPAPI before persistence to `cyberguard-data/settings.json`.

### Truthful UI State Transition Policy
If `GOOGLE_CLIENT_ID` is missing, CyberGuard will **never** display fake connected indicators. It cleanly surfaces `{ setupRequired: true }` and presents the administrator with the setup modal detailing the required environment key.

---

## 4. Google Cloud Console Onboarding & Setup Guide

To obtain a valid `GOOGLE_CLIENT_ID` for production or enterprise deployment:

### Step 1: Create or Select a Google Cloud Project
1. Navigate to the [Google Cloud Console](https://console.cloud.google.com/).
2. Click **Select a project** > **New Project**.
3. Name the project `CyberGuard Endpoint Security` and assign your organization.

### Step 2: Enable the Gmail API
1. In the navigation menu, go to **APIs & Services** > **Library**.
2. Search for `Gmail API`.
3. Click **Gmail API** and click **Enable**.

### Step 3: Configure the OAuth Consent Screen
1. Go to **APIs & Services** > **OAuth consent screen**.
2. Select **User Type**:
   - **Internal**: Recommended for Google Workspace organizations (all enterprise members can sign in without verification warnings).
   - **External**: Required for general `@gmail.com` accounts. Add designated test users under **Test users**.
3. Fill in the App Information:
   - App name: `CyberGuard Endpoint Security`
   - User support email: `cyberguardadmin@gmail.com`
   - Developer contact email: `cyberguardadmin@gmail.com`
4. Add Scopes:
   - `https://www.googleapis.com/auth/gmail.readonly` (Read-only mailbox inspection for phishing and malware threats)
   - `https://www.googleapis.com/auth/gmail.metadata` (Read message headers and labels without modifying mailbox state)
5. Save and continue.

### Step 4: Create Desktop OAuth Client Credentials
1. Go to **APIs & Services** > **Credentials**.
2. Click **Create Credentials** > **OAuth client ID**.
3. In the **Application type** dropdown, select **Desktop app**.
4. Name the client `CyberGuard Desktop Client`.
5. Click **Create**.
6. Copy the generated **Client ID** (e.g., `108234857239-xxxxxxxx.apps.googleusercontent.com`).
7. Paste this Client ID into your CyberGuard `.env` or Settings Console.

### Verification and Approval Note:
For public releases using the **External** consent screen type with restricted scopes (`gmail.readonly`), Google requires a Cloud Security Assessment (CASA Tier 2). However, for development, internal enterprise Workspace deployments, and designated test accounts, no external security assessment is required.

