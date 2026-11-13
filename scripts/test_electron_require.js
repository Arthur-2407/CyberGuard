const el = require('electron');
console.log('TYPE:', typeof el);
console.log('KEYS:', Object.keys(el || {}));
console.log('APP:', el && el.app);

