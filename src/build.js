/*
Run this file to generate new classified.html file
*/

const { header, footer, getIntro } = require('./misc');
const path = require('path');
const fs = require('fs');

// read files
const body = fs.readFileSync(path.join(__dirname, 'body.js'), 'utf8');
const base64js = fs.readFileSync(path.join(__dirname, './base64-js.js'), 'utf8');
const license = fs.readFileSync(path.join(__dirname, '..', './LICENSE'), 'utf8');

// get file, filepath
const fileContents = (
`${header}
${getIntro(license)}
${base64js}
${body}
${footer}`);
const filePath = path.join(__dirname, '..', 'classified.html');

// write file
fs.writeFileSync(filePath, fileContents, 'utf8');

console.log(`Build finished: ${filePath}`);
