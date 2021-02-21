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
salt:51-231-23-26-140-35-137-124-244-101-176-105-42-161-46-140
iv:202-193-152-50-189-102-124-22-47-74-248-43
data:
Yq30olWyBZxXnT7E7ubaMr+DsZlbCCNeKQ==
\`;// data end
`
);

module.exports = { header, footer, getIntro };
