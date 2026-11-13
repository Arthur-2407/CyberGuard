/**
 * Execute real Google OAuth 2.0 PKCE flow and live mailbox sync.
 */
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const gmailService = require('../desktop/engine/gmail_service');
const localStore = require('../desktop/engine/local_store');

const clientId = gmailService._getGoogleClientId();
console.log('Using Desktop Client ID:', clientId);

if (!clientId) {
  console.error('ERROR: No GOOGLE_CLIENT_ID configured.');
  process.exit(1);
}

const codeVerifier = crypto.randomBytes(32).toString('base64url');
const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
const state = crypto.randomBytes(16).toString('hex');

const server = http.createServer(async (req, res) => {
  try {
    const reqUrl = new URL(req.url, `http://127.0.0.1:${server.address().port}`);
    if (reqUrl.pathname === '/oauth2callback') {
      const returnedState = reqUrl.searchParams.get('state');
      const returnedCode = reqUrl.searchParams.get('code');
      const returnedError = reqUrl.searchParams.get('error');

      if (returnedError) {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end(`<html><body style="font-family:sans-serif;padding:30px;text-align:center;"><h2>Authorization Error</h2><p>${returnedError}</p></body></html>`);
        console.error('OAuth Callback returned error:', returnedError);
        server.close();
        process.exit(1);
      }

      if (returnedState !== state || !returnedCode) {
        res.writeHead(400, { 'Content-Type': 'text/html' });
        res.end('<html><body><h2>State Mismatch</h2></body></html>');
        console.error('OAuth state mismatch!');
        server.close();
        process.exit(1);
      }

      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`
        <!DOCTYPE html>
        <html>
        <head><title>CyberGuard Authorized</title></head>
        <body style="font-family: sans-serif; text-align: center; padding: 50px; background: #0f172a; color: white;">
          <h2>CyberGuard Authorization Successful</h2>
          <p>Authorization code received. You may return to the console.</p>
        </body>
        </html>
      `);

      console.log('Received valid authorization code from Google!');
      console.log('Exchanging authorization code for tokens via PKCE...');

      const redirectUri = `http://127.0.0.1:${server.address().port}/oauth2callback`;
      const clientSecret = gmailService._getGoogleClientSecret();
      const tokenResult = await gmailService._exchangeAuthCode(returnedCode, codeVerifier, redirectUri, clientId, clientSecret);

      if (!tokenResult.success) {
        console.error('Token exchange failed:', tokenResult.error);
        server.close();
        process.exit(1);
      }

      console.log('SUCCESS: Tokens acquired!');
      console.log('Authorized Google Account:', tokenResult.email);
      console.log('Token Types:', Object.keys(tokenResult.tokens));
      console.log('Has access_token:', Boolean(tokenResult.tokens.access_token));
      console.log('Has refresh_token:', Boolean(tokenResult.tokens.refresh_token));
      console.log('Expires in:', tokenResult.tokens.expires_in, 'seconds');
      console.log('Scope granted:', tokenResult.tokens.scope);

      // Save encrypted tokens for user ID 1 (cyberguardadmin@gmail.com)
      localStore.saveGmailTokens(1, tokenResult.tokens);
      gmailService.authorize(tokenResult.email, tokenResult.tokens, 1);

      console.log('\n--- Initiating Live Mailbox Synchronization ---');
      const syncResult = await gmailService.syncMailbox(1);
      console.log('Mailbox Sync Result:', JSON.stringify(syncResult, null, 2));

      const updatedStatus = gmailService.getStatus(1);
      console.log('\nUpdated Gmail Status:', JSON.stringify(updatedStatus, null, 2));

      // Write results to evidence file
      fs.writeFileSync(path.join(__dirname, 'oauth_evidence.json'), JSON.stringify({
        timestamp: new Date().toISOString(),
        email: tokenResult.email,
        scope: tokenResult.tokens.scope,
        hasRefreshToken: Boolean(tokenResult.tokens.refresh_token),
        syncResult,
        status: updatedStatus
      }, null, 2));

      console.log('\nEvidence recorded to scripts/oauth_evidence.json.');
      server.close();
      process.exit(0);
    }
  } catch (err) {
    console.error('Server error:', err);
    server.close();
    process.exit(1);
  }
});

server.listen(0, '127.0.0.1', () => {
  const port = server.address().port;
  const redirectUri = `http://127.0.0.1:${port}/oauth2callback`;
  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${encodeURIComponent(clientId)}&` +
    `redirect_uri=${encodeURIComponent(redirectUri)}&` +
    `response_type=code&` +
    `scope=${encodeURIComponent('https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/userinfo.email')}&` +
    `code_challenge=${encodeURIComponent(codeChallenge)}&` +
    `code_challenge_method=S256&` +
    `state=${encodeURIComponent(state)}&` +
    `access_type=offline&` +
    `prompt=consent`;

  console.log(`AUTH_SERVER_LISTENING:${port}`);
  console.log(`AUTH_URL:${authUrl}`);
});
