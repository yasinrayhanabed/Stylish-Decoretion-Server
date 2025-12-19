const fs = require('fs');
const key = fs.readFileSync('./stylish-decoretor-firebase-adminsdk-fbsvc-3603462bd7.json', 'utf8')
const base64 = Buffer.from(key).toString('base64')
console.log(base64)