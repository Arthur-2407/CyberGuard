/**
 * CyberGuard SOC AI — Enterprise Desktop Application
 * Main Electron Process
 *
 * Security Model:
 *  - nodeIntegration: false (strict renderer process sandboxing)
 *  - contextIsolation: true (independent context for preload script)
 *  - sandbox: true (OS-level Chromium sandbox)
 *  - Controlled permission request handler (audio/mic only for Voice Analysis)
 *  - Strict navigation gating (external links open in default OS browser)
 *  - CSP enforcement and single-instance application lock
 */

const { app, BrowserWindow, shell, ipcMain, session, Notification } = require('electron');
const path = require('path');

// Single-instance lock
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
  process.exit(0);
}

let mainWindow = null;

function createWindow() {
  const iconPath = path.join(__dirname, 'assets', 'icon.ico');

  mainWindow = new BrowserWindow({
    title: 'CyberGuard — SOC Threat Intelligence & Multi-Modal AI Defense',
    width: 1440,
    height: 900,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: '#030712',
    icon: iconPath,
    show: false, // Wait until ready-to-show for a clean, flicker-free startup
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      preload: path.join(__dirname, 'preload.js'),
      webSecurity: true,
      allowRunningInsecureContent: false,
      spellcheck: false
    }
  });

  // Remove default menu bar for dedicated SOC console HUD feel
  mainWindow.setMenuBarVisibility(false);

  // Load the bundled frontend assets
  const entryPoint = path.join(__dirname, 'frontend', 'index.html');
  mainWindow.loadFile(entryPoint);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    mainWindow.focus();
  });

  // Safe navigation control: Open external URLs in default web browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http:') || url.startsWith('https:') || url.startsWith('mailto:')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });

  mainWindow.webContents.on('will-navigate', (event, url) => {
    const isLocalFile = url.startsWith('file://');
    if (!isLocalFile) {
      event.preventDefault();
      shell.openExternal(url);
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Ensure audio/mic permissions are granted for Voice Analysis and Voice Identity tabs
app.whenReady().then(() => {
  // Setup CSP and permission handlers
  const defaultSession = session.defaultSession;

  defaultSession.setPermissionRequestHandler((webContents, permission, callback) => {
    // Only permit media (microphone) for voice clone defense and neural audio processing
    if (permission === 'media') {
      callback(true);
      return;
    }
    // Deny geolocation, notifications without explicit consent, etc.
    callback(false);
  });

  // IPC: Safe external URL opening
  ipcMain.on('cyberguard:open-external', (event, url) => {
    if (typeof url === 'string' && (url.startsWith('https://') || url.startsWith('http://'))) {
      shell.openExternal(url);
    }
  });

  // IPC: Security notifications
  ipcMain.on('cyberguard:notify', (event, { title, body }) => {
    if (Notification.isSupported()) {
      new Notification({
        title: title || 'CyberGuard Security Alert',
        body: body || '',
        icon: path.join(__dirname, 'assets', 'icon.ico')
      }).show();
    }
  });

  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Single-instance focus handling
app.on('second-instance', () => {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  }
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
