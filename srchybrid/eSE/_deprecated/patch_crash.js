const fs = require('fs');
let content = fs.readFileSync('server.js', 'latin1');

// Remove existing uncaughtException/unhandledRejection/clientError if present
content = content.replace(/process\.on\('[a-zA-Z]+'[\s\S]*?\}\);\s*/g, '');
content = content.replace(/server\.on\('clientError'[\s\S]*?\}\);\s*/g, '');

const insert = `
process.on('uncaughtException', err => {
    console.log('[Uncaught Exception]', err.message);
});
process.on('unhandledRejection', err => {
    console.log('[Unhandled Rejection]', err);
});
`;

content = insert + content;
fs.writeFileSync('server.js', content, 'latin1');
console.log('Patch applied successfully.');
