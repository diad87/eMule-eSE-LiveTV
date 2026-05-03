// Revert the HLS patch from channel_api.js and re-apply properly  
const fs = require('fs');
const path = require('path');

const apiPath = path.join(__dirname, 'eSE-live', 'channel_api.js');
let s = fs.readFileSync(apiPath, 'latin1');

// Remove the injected block between handleRoute opening and the first real route
const hlsStart = s.indexOf("\n  // eSE: Serve HLS segments");
if (hlsStart < 0) {
    console.log('No HLS block found, nothing to revert');
    process.exit(0);
}

// The block ends right before the first real route (p === '/api/live/status')
const firstRoute = s.indexOf("  if (p === '/api/live/status");
if (firstRoute < 0) {
    // Try alternative
    const alt = s.indexOf("  // === GET /api/live/status");
    if (alt < 0) { console.error('Cannot find end of block'); process.exit(1); }
    // Remove from hlsStart to alt
    s = s.substring(0, hlsStart) + '\n' + s.substring(alt);
} else {
    s = s.substring(0, hlsStart) + '\n\n  ' + s.substring(firstRoute);
}

fs.writeFileSync(apiPath, s, 'latin1');
console.log('Reverted HLS injection from channel_api.js');

// Verify syntax
try {
    require('child_process').execSync('node -c ' + apiPath, { stdio: 'pipe' });
    console.log('Syntax OK');
} catch(e) {
    console.error('Syntax error after revert!');
}
