/*
These in separate files to make linters ignore the values
*/

const header = "//<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'></head><body><script>";
const footer = '//</script></body></html>';
const getIntro = (license) => (
`/*
wasmProof.html

${license}*/


const data = \`
salt:222-14-77-28-195-123-191-143-174-73-57-136-63-177-209-247
iv:124-246-101-57-175-99-139-26-227-238-43-9
data:
vA08YQ+fvdXJ79ywhB7FiFJMOQ45k1BuC/lOjAw3
\`;// data end
`
);

module.exports = { header, footer, getIntro };
