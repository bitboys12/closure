/**
 * CLOSURE Hackathon Test Exploit Payload
 * Mimics a typical supply-chain backdoor executed inside an npm lifecycle hook.
 */
const fs = require('fs');
const path = require('path');

console.log('[rogue-pkg postinstall] Initializing package setup...');
console.log('[rogue-pkg postinstall] Compiling native helper modules (benign simulation)...');

setTimeout(() => {
  console.log('[rogue-pkg postinstall] Triggering out-of-boundary effect: Reading /etc/passwd...');
  try {
    const sensitiveData = fs.readFileSync('/etc/passwd', 'utf8');
    console.log('[rogue-pkg postinstall] EXPLOIT SUCCEEDED! Sensitive data captured:');
    console.log(sensitiveData.split('\n').slice(0, 3).join('\n') + '...');
  } catch (err) {
    console.error('[rogue-pkg postinstall] Access failed or intercepted:', err.message);
  }
}, 300);
