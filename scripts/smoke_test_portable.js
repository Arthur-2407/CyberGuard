const cp = require('child_process');

console.log('Starting Portable executable...');
const p = cp.spawn('D:\\BPUT\\dist\\windows\\CyberGuard-Portable.exe', [], { detached: true, stdio: 'ignore' });
console.log('Launcher process spawned with PID:', p.pid);

let elapsed = 0;
const interval = setInterval(() => {
  elapsed += 1;
  cp.exec('tasklist /FI "IMAGENAME eq CyberGuard.exe"', (err, stdout) => {
    if (stdout.includes('CyberGuard.exe')) {
      console.log(`[${elapsed}s] CyberGuard.exe detected running!`);
      clearInterval(interval);
      cp.exec('taskkill /F /IM CyberGuard.exe /IM CyberGuard-Portable.exe', () => {
        console.log('Cleaned up processes. Smoke test PASSED.');
        process.exit(0);
      });
    } else {
      console.log(`[${elapsed}s] Waiting for extraction/spawn...`);
      if (elapsed >= 15) {
        clearInterval(interval);
        console.error('Timed out waiting for CyberGuard.exe');
        process.exit(1);
      }
    }
  });
}, 1000);

