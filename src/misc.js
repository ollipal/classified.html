/*
These in separate files to make linters ignore the values
*/

const header = "//<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'></head><body><script>";
const footer = '//</script></body></html>';
const getIntro = (license) => (
`/*
classied.html

${license}*/


const data = \`
\`;// data end
`
);

module.exports = { header, footer, getIntro };
