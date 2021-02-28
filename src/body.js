const inBrowser = () => typeof window !== 'undefined';

const checkNodeVersionSupported = () => {
  const NODE_VERSION = process.versions.node;
  if (NODE_VERSION.split('.')[0] < 15) {
    console.log(`Uses Web Crypto API, Node 15 or higher required (current ${NODE_VERSION})`);
    process.exit(1);
  }
};

const dataEmpty = () => data === '\n';

// set variables based on the execution environment
let subtle;
let getRandomValues;
const utf8Encoder = new TextEncoder('utf-8');
const DATA_LINE_LEN = 100;
if (inBrowser()) {
  subtle = window.crypto.subtle;
  getRandomValues = (arr) => window.crypto.getRandomValues(arr);
} else {
  checkNodeVersionSupported();
  const crypto = require('crypto');
  subtle = crypto.webcrypto.subtle;
  getRandomValues = (buffer) => {
    buffer.set(crypto.randomBytes(buffer.length));
    return buffer;
  };
}

// from: https://github.com/ollipal/minimal-password-prompt
const captureStdin = (onData) => {
  process.stdin.setEncoding('utf-8');
  process.stdin.setRawMode(true);
  process.stdin.on('data', onData);
  process.stdin.resume();
};

const releaseStdin = (onData) => {
  process.stdin.pause();
  process.stdin.removeListener('data', onData);
  process.stdin.setRawMode(false);
  process.stdout.write('\n');
};

const prompt = (question, ctrlcExits = true) => (
  new Promise((resolve, reject) => {
    let input = '';
    const onData = (data) => {
      switch (data) {
        case '\u000A': // \n
        case '\u000D': // \r
        case '\u0004': // Ctrl+D
          releaseStdin(onData);
          resolve(input);
          break;
        case '\u0003': // Ctrl+C
          releaseStdin(onData);
          ctrlcExits // exit or raise error
            ? process.exit()
            : reject(new Error('Ctrl+C'));
          break;
        case '\u0008': // Backspace
        case '\u007F': // Delete
          input = input.slice(0, -1);
          break;
        default: // any other
          input += data;
      };
    };
    captureStdin(onData);
    process.stdout.write(question);
  })
);

const pickPassword = async () => {
  let password, repassword;
  while (true) {
    password = await prompt('pick a password: ');
    repassword = await prompt('re-enter password: ');
    if (password === '') {
      console.log('cannot be empty');
      continue;
    }
    if (password === repassword) break;
    console.log('passwords did not match, please try again:');
  }
  return password;
};

/*
First derive key material from password and salt,
then use keymaterial and salt to derive an AES-GCM key using PBKDF2.
*/
const getKey = async (password, salt) => {
  const keyMaterial = await subtle.importKey(
    'raw',
    utf8Encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
};

const toLines = (str) => {
  const numLines = Math.ceil(str.length / DATA_LINE_LEN);
  const lines = new Array(numLines);
  for (let i = 0, start = 0; i < numLines; ++i, start += DATA_LINE_LEN) {
    lines[i] = str.substr(start, DATA_LINE_LEN);
  }
  return lines.join('\n');
};

const arrayBufferToBase64 = (buf) => (
  fromByteArray(new Uint8Array(buf))
);

const encryptionValuesToStrorableSring = (salt, iv, encrypted) => (
  `salt:${salt.join('-')}\niv:${iv.join('-')}\ndata:\n${toLines(arrayBufferToBase64(encrypted))}`
);

const encryptionValuesFromStroredSring = (str) => {
  const lines = str.split(/\r?\n|\r/g);
  const salt = new Uint8Array(lines[1].replace('salt:', '').split('-'));
  const iv = new Uint8Array(lines[2].replace('iv:', '').split('-'));
  const data = lines.splice(4).join('');
  return { salt, iv, data };
};

/*
Placeholder to always home some data to enctrypt.
This because on node decrypt seems to fail if there
is no data to return (v15.9.0)
*/
const placeholder = 'classified.html\n';

/*
Derive a key from a password supplied by the user, and use the key
to encrypt the message.
Return a storable string that contains salt, initialization vector and the
encrypted data encoded with base64.
*/
const encrypt = async (password, message) => {
  const salt = getRandomValues(new Uint8Array(16));
  const iv = getRandomValues(new Uint8Array(12));
  const key = await getKey(password, salt);

  const encrypted = await subtle.encrypt(
    {
      name: 'AES-GCM',
      iv
    },
    key,
    utf8Encoder.encode(placeholder + message)
  );

  return encryptionValuesToStrorableSring(salt, iv, encrypted);
};

/*
Derive a key from a password supplied by the user, and use the key
to decrypt the ciphertext.
If the ciphertext was decrypted successfully,
update the "decryptedValue" box with the decrypted value.
If there was an error decrypting,
update the "decryptedValue" box with an error message.
*/
const decrypt = async (password, data) => {
  const parsedData = encryptionValuesFromStroredSring(data);
  const key = await getKey(password, parsedData.salt);

  try {
    const decrypted = await subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: parsedData.iv
      },
      key,
      toByteArray(parsedData.data)
    );

    const dec = new TextDecoder('utf-8', { fatal: true });
    const message = dec.decode(decrypted).slice(placeholder.length);
    return { data: message, success: true };
  } catch (e) {
    return { data: '', success: false };
  }
};

const updateSourceData = (source, data) => {
  // remove the old data and insert new
  const sourceStart = source.split('const data' + ' = `')[0] + 'const data' + ' = `\n';
  const sourceEnd = '\n\`;// ' + 'data end' + source.split('\`;// ' + 'data end')[1];
  return sourceStart + data + sourceEnd;
};

if (typeof window === 'undefined') { // executed in Node.js
  const fs = require('fs');
  const path = require('path');
  const os = require('os');
  const readline = require('readline');

  const question = (q) => new Promise(resolve => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    rl.question(q, (a) => {
      rl.close();
      resolve(a);
    });
  });

  const filename = path.basename(__filename);
  const tmpPath = path.join(os.tmpdir(), filename);

  (async () => {
    let password, decryptedData;
    if (dataEmpty()) {
      password = await pickPassword();
      decryptedData = '';
    } else if (password === undefined) {
      let decryptionResult;
      while (true) {
        password = await prompt('enter password: ');
        if (password === '') {
          console.log('cannot be empty');
          continue;
        }
        decryptionResult = await decrypt(password, data);
        if (decryptionResult.success) break;
        console.log('incorrect password');
      }
      decryptedData = decryptionResult.data;
    }

    console.log('\x1b[36m%s\x1b[0m', 'Text'); // cyan color
    if (decryptedData !== '') {
      console.log(decryptedData);
    };
    let newNewData;
    let newData = '';
    while (true) {
      newNewData = await question('enter new data (empty to skip): ');
      if (newNewData === '') {
        break;
      };
      newData += newNewData + '\n';
      console.log(newData);
    }

    if (newData !== '' || decryptedData === '') { // TODO do not re-enrypt if just reopening empty file
      // if new data
      // copy file to tmp file, and rename
      const datas = decryptedData + newData;
      console.log('datas');
      console.log(datas);
      const updatedData = await encrypt(password, datas);
      fs.readFile(__filename, 'utf8', (err, source) => {
        if (err) throw err;
        const updatedSource = updateSourceData(source, updatedData);
        fs.writeFile(tmpPath, updatedSource, (err) => {
          if (err) throw err;
          fs.rename(tmpPath, __filename, (err) => {
            if (err) throw err;
            console.log('saved!');
          });
        });
      });
    }
  })();
} else { // executed in Browser
  const htmlTop = "//<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'></head><body><script>";
  const htmlBottom = '<\/script></body></html>';
  const filename = location.href.split('/').slice(-1);
  const source = htmlTop + document.currentScript.innerHTML + htmlBottom;

  window.addEventListener('DOMContentLoaded', () => {
    document.body.childNodes[0].textContent = ''; // remove the first '//' required for cli excecution
    document.title = filename; // set document title based on the file name
  });

  // add text field for the password
  const passwordInput = document.createElement('input');
  passwordInput.type = 'text';
  document.body.appendChild(passwordInput);

  // add button to load source
  const decryptButton = document.createElement('a');
  decryptButton.innerHTML = 'Decrypt';
  const onClickDecrypt = async (event) => {
    event.preventDefault();
    const password = passwordInput.value;
    const decryptionResult = await decrypt(password, data);
    if (!decryptionResult.success) {
      alert('Incorrect password');
    } else {
      // add text field for the data
      const dataInput = document.createElement('input');
      dataInput.type = 'text';
      dataInput.value = decryptionResult.data;
      document.body.appendChild(dataInput);

      // add button to downlaod source
      const downloadButton = document.createElement('a');
      downloadButton.innerHTML = 'Download source';
      const onClickDownload = async (event) => {
        const tmpButton = document.createElement('a');
        const updatedData = await encrypt(password, dataInput.value);
        tmpButton.href = URL.createObjectURL(
          new Blob(
            [updateSourceData(source, updatedData)],
            { type: 'data:text/plain' }
          )
        );
        tmpButton.download = filename;
        tmpButton.click();
        console.log('clicked');
        // downloadButton.click();
      };
      downloadButton.onclick = onClickDownload;
      document.body.appendChild(downloadButton);
    }
  };
  decryptButton.onclick = onClickDecrypt;
  document.body.appendChild(decryptButton);

  // newline
  document.write('<br>');
}
