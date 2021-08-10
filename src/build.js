/*
Run this file to generate new classified.html file
*/
const path = require('path');
const fs = require('fs');

// read the required files
const read = (file) => fs.readFileSync(path.join(__dirname, file), 'utf8');
let main = read('main.js');
const base64js = read('./base64-js.js');
const license = read('../LICENSE');
const mockPage = read('mockPage.html');

// replace main.js keywords with other files
const mainReplace = (name, file) => (main = main.replace(name, file.trim()));
mainReplace('LICENCE', license);
mainReplace('// BASE64-JS', base64js);
mainReplace('SVG-TERMS', mockPage.split('SVG-TERMS')[1]);
mainReplace('/*CSS*/', mockPage.split('/*CSS*/')[1]);
mainReplace('<!--HTML-->', mockPage.split('<!--HTML-->')[1]);

// build the final file
const fileContents = (
`//classified.html requires JavaScript to work properly<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'></head><body><script>
${main}
//</script></body></html>`);

// write file
const filePath = path.join(__dirname, '..', 'classified.html');
fs.writeFileSync(filePath, fileContents, 'utf8');

// log finish status
console.log(`Build finished: ${filePath}`);
