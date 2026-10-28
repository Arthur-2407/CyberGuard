/**
 * CyberGuard Desktop Preload Bridge
 *
 * Runs in an isolated execution context with full contextIsolation.
 * Exposes safe, audited host platform capabilities to the SOC UI.
 */
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('cyberguardDesktop', {
  isDesktop: true,
  platform: process.platform,
  arch: process.arch,
  version: '1.0.0',
  defaultCloudEndpoint: 'https://cyberguard-backend-8rbz.onrender.com',
  getAppVersion: () => '1.0.0',
  openExternal: (url) => ipcRenderer.send('cyberguard:open-external', url),
  showNotification: (title, body) => ipcRenderer.send('cyberguard:notify', { title, body })
});

// Configure default window API base if not explicitly configured in localStorage
window.addEventListener('DOMContentLoaded', () => {
  if (typeof window !== 'undefined') {
    window.__CYBERGUARD_CONFIG__ = window.__CYBERGUARD_CONFIG__ || {};
    if (!window.__CYBERGUARD_CONFIG__.api_base) {
      const stored = localStorage.getItem('cyberguard_api_base');
      if (!stored) {
        window.__CYBERGUARD_CONFIG__.api_base = 'https://cyberguard-backend-8rbz.onrender.com';
        localStorage.setItem('cyberguard_api_base', 'https://cyberguard-backend-8rbz.onrender.com');
      }
    }
  }
});
