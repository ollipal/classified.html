const VERSION = '0.0.1';

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
      hash: 'SHA-512'
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
  `salt:${salt.join('-')}\niv:${iv.join('-')}\ndata:\n${toLines(arrayBufferToBase64(encrypted))}\n`
);

const encryptionValuesFromStroredSring = (str) => {
  const lines = str.split(/\r?\n|\r/g);
  const salt = new Uint8Array(lines[1].replace('salt:', '').split('-'));
  const iv = new Uint8Array(lines[2].replace('iv:', '').split('-'));
  const data = lines.splice(4).join('');
  return { salt, iv, data };
};

/*
Placeholder to always home some data to encrypt.
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
  const sourceEnd = '\`;// ' + 'data end' + source.split('\`;// ' + 'data end')[1];
  return sourceStart + data + sourceEnd;
};

if (typeof window === 'undefined') { // executed in Node.js
  const fs = require('fs');
  const path = require('path');
  const os = require('os');
  const readline = require('readline');

  const filename = path.basename(__filename);
  const tmpPath = path.join(os.tmpdir(), filename);

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

  const downloadEmpty = async (savePath) => {
    if (savePath === undefined) {
      const proposedDir = path.dirname(__filename) + path.sep;
      let directory = await question(`save directory? [default: ${proposedDir}] `);
      if (directory === '') directory = proposedDir;
      if (!(directory.endsWith(path.sep))) directory += path.sep;
      let name = await question('save name? ');
      if (!(name.endsWith('.html'))) name += '.html';
      savePath = directory + name;
    }

    try {
      const source = fs.readFileSync(__filename, 'utf8');
      fs.writeFileSync(savePath, updateSourceData(source, ''), { flag: 'wx' });
      console.log(`${savePath} saved`);
    } catch (err) {
      console.log(`Could not save ${savePath}:\n${err}`);
    }
  };

  (async () => {
    const args = process.argv.slice(2);
    if (['-h', '--help'].includes(args[0])) {
      console.log(`Usage: node ${filename} [OPTIONS] [ARGS]

classified.html version ${VERSION}
Normal use does not require any options or arguments.
      
Options:
  -h, --help\t\tShow this help message
  -e, --empty\t\tDownload empty classified.html. Will ask for save location if not specified in ARGS
      `);
      process.exit();
    }
    if (['-e', '--empty'].includes(args[0])) {
      await downloadEmpty(args[1]);
      process.exit();
    }

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

    let newData = decryptedData.endsWith('\n') ? '' : '\n';
    let newNewData;

    const printContents = () => {
      console.clear();
      console.log(decryptedData + newData);
    };

    while (true) {
      printContents();
      newNewData = await question('enter new data (empty to exit): ');
      if (newNewData === '') {
        console.clear();
        break;
      };
      newData += newNewData + '\n';
      if (decryptedData !== '') {
        console.log(decryptedData);
      };
      console.log(newData);
    }

    // save if new data or first time
    if (newData !== '' || dataEmpty()) {
      // copy file to tmp file, and rename
      try {
        const source = fs.readFileSync(__filename, 'utf8');
        const updatedData = await encrypt(password, decryptedData + newData);
        const updatedSource = updateSourceData(source, updatedData);
        fs.writeFileSync(tmpPath, updatedSource);
        fs.renameSync(tmpPath, __filename);
        console.clear();
        console.log('changes saved!');
      } catch (err) {
        console.log(`Could not save ${__filename}:\n${err}`);
      };
    } else {
      console.clear();
      console.log('no changes to save');
    }
  })();
} else { // executed in Browser
  const htmlTop = "//<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'></head><body><script>";
  const htmlBottom = '<\/script></body></html>';
  let filename = location.href.split('/').slice(-1)[0];
  // %2F means forward slash on mobile chrome for local files
  if (navigator.canShare) {
    filename = filename.split('%2F').slice(-1)[0];
  }
  const source = htmlTop + document.currentScript.innerHTML + htmlBottom;

  window.addEventListener('DOMContentLoaded', () => {
    // set document html
    document.getElementsByTagName('body')[0].innerHTML = `
<div id="form-div">
  <h2>classified.html</h2>
  <form id="form">
    <input type="password" id="password" class="form-field" autocomplete="new-password" placeholder="pick a password">
    <input type="password" id="repassword" class="form-field" autocomplete="new-password" placeholder="re-enter password">
    <input type="submit" value="Create" id="form-submit">
  </form>
</div>

<div id=main-div>
  <div class="navbar">
    <button id="change">change password</button>
    <button id="save">save changes</button>
    <button id="empty">get new empty</button>
  </div>
  <div id="text-div">
    <div id="text" contenteditable="true"></div>
    <div>
      <div id="space">
    </div>
  </div> 
    </div> 
  </div> 
    </div> 
  </div>
    </div> 
  </div> 
</div>
    `;
    // set document css
    const style = document.createElement('style');
    style.textContent = `
/*The state*/
:root {
  --display-form: inline;
  --display-repw: inline;
  --display-main: none;
  --display-save: none;
}

body {
  font-family: 'Courier New', Courier, monospace;
}

#form-div {
  position: absolute;
  left: 50%;
  top: 30%;
  transform: translate(-50%, -50%);
  width: 90%;
  max-width: 350px;
  text-align:center;
  display: var(--display-form);
}

#repassword {
  display: var(--display-repw);
}

.form-field {
  filter: none;
  display: grid;
  text-align: center; 
  width: 100%;
  border: none;
  border-bottom: 1px solid black;
  margin-bottom: 10px;
  outline: none;
  font-family: 'Courier New', Courier, monospace;
  padding: 0px 0px 5px 0px;
}

#form-submit {
  width: 100%;
  padding: 5px;
  border: 1px solid black;
  color: white;
  font-weight: bold;
  background-color: black;
  outline: none;
  font-family: 'Courier New', Courier, monospace;
  cursor: pointer;
  transition: 100ms ease;
}

#form-submit:hover {
  padding: 5px;
  border: 1px solid black;
  background-color: white;
  color: black;
}

#main-div {
  display: var(--display-main);
}

/* Firefox scrollbar */
* {
  scrollbar-width: thin;
  scrollbar-color: black white;
}

/* Chrome, Edge, and Safari scrollbar */
::-webkit-scrollbar {
  height: 7px;
  width: 7px;
}
::-webkit-scrollbar-track {
  background: white;
}
::-webkit-scrollbar-thumb {
  background-color: black;
}
::selection {
  background: black;
  color: white;
}

#text-div {
  position: absolute;
  left: 50%;
  transform: translate(-50%);
  max-width: 818px;
}

#text {
  min-height:1058px;
  height:auto;
  background-color: white;
  /* border: 1px solid black; */
  font-family: 'Courier New', Courier, monospace;
  padding: 96px; /* Todo smaller padding small screens */
  overflow-wrap: anywhere; /* other option: overflow-wrap:normal; overflow: hidden; overflow-x: scroll; */
  outline: none;
  box-shadow: 0 4px 8px 0 rgba(0, 0, 0, 0.2), 0 6px 20px 0 rgba(0, 0, 0, 0.19);
  transition: 200ms ease;
}

@media only screen and (max-width: 800px) { /*small*/
  #text-div {
    top: 1%;
    width: 96%;
  }

  #text {
    padding: 15px;
  }
}

@media only screen and (min-width: 800px) { /*large*/
  #text-div {
    top: 5%;
    width: 90%;
  }

  #text {
    padding: 96px;
  }
}

#text:focus-within {
  box-shadow: 0 4px 8px 0 rgba(0, 0, 0, 0.30), 0 6px 20px 0 rgba(0, 0, 0, 0.25);
}

#change, #save, #empty {
  width: 30%;
  min-width: 200px;
  padding: 5px;
  border: 1px solid black;
  color: white;
  font-weight: bold;
  background-color: black;
  outline: none;
  font-family: 'Courier New', Courier, monospace;
  cursor: pointer;
  margin: 10px;
  transition: 100ms ease;
  display: var(--display-save);
}

#change:hover, #save:hover, #empty:hover {
  padding: 5px;
  border: 1px solid black;
  background-color: white;
  color: black;
}

#space {
  height: 5vh;
  min-height: 50px;
  width: 100%;
}

/* The navigation bar */
.navbar {
  overflow: hidden;
  background-color: transparent;
  position: fixed;
  bottom: 0;
  width: 100%;
  z-index: 100;
  text-align:center;
}
`;
    document.head.append(style);
    document.title = filename;

    const form = document.getElementById('form');
    const formSubmit = document.getElementById('form-submit');
    const dataInput = document.getElementById('text');
    const saveButton = document.getElementById('save');
    const changePasswordButton = document.getElementById('change');
    const emptyButton = document.getElementById('empty');
    let currentPassword; // this can change if the user changes password

    const setProperty = (key, value) => document.documentElement.style.setProperty(key, value);

    const preventUnload = (e) => {
      e.preventDefault(); // this enables the unload warning message
      e.returnValue = ''; // Chrome requires returnValue to be set
    };

    const activateSaveButton = _ => {
      setProperty('--display-save', 'inline');
      window.addEventListener('beforeunload', preventUnload); // activate reminder about unsaved content
    };

    const downloadFile = (file) => {
      const tmpButton = document.createElement('a');
      tmpButton.href = URL.createObjectURL(file);
      tmpButton.download = filename;
      tmpButton.click();
      tmpButton.remove();
    };

    const shareFile = async (file) => {
      try {
        await navigator.share({ files: [file], title: filename });
      } catch (error) {
        if (confirm(`Sharing failed: "${error.message}".\nDownload intead?`)) downloadFile(file);
      }
    };

    /*
    Download or share the file depending on the device used
    */
    const obtainFile = async (data, name) => {
      const fileContent = updateSourceData(source, data);
      const file = new File([fileContent], name, { type: 'text/html' });

      if (navigator.canShare && navigator.canShare({ files: [file] })) {
        await shareFile(file);
      } else {
        downloadFile(file);
      }
    };

    const getPasswordValue = () => {
      const password = form.password.value;
      const repassword = form.repassword.value;
      if (password === '') {
        alert('cannot be empty');
        return undefined;
      } else if (password !== repassword) {
        alert('passwords did not match, please try again');
        form.password.value = '';
        form.repassword.value = '';
        return undefined;
      } else {
        return password;
      }
    };

    const pickPassword = async (e) => {
      e.preventDefault();
      const password = getPasswordValue();
      if (password !== undefined) {
        formSubmit.removeEventListener('click', pickPassword);
        currentPassword = password;
        await showDecrypted('');
      }
    };

    const repickPassword = async (e) => {
      e.preventDefault();
      const password = getPasswordValue();
      if (password !== undefined) {
        setProperty('--display-save', 'inline');
        formSubmit.removeEventListener('click', repickPassword);
        currentPassword = password;
        await showDecrypted();
      }
    };

    const enterPassword = async (e) => {
      e.preventDefault();
      const password = form.password.value;
      const decryptionResult = await decrypt(password, data);
      if (!decryptionResult.success) {
        alert('Incorrect password');
        form.password.value = '';
      } else {
        formSubmit.removeEventListener('click', enterPassword);
        currentPassword = password;
        showDecrypted(decryptionResult.data);
      }
    };

    changePasswordButton.addEventListener('click', async (_) => {
      formSubmit.addEventListener('click', repickPassword);
      form.password.value = '';
      form.repassword.value = '';
      setProperty('--display-form', 'inline');
      setProperty('--display-repw', 'inline');
      setProperty('--display-main', 'none');
      setProperty('--display-save', 'none');
      form.password.focus();
    });

    saveButton.addEventListener('click', async (_) => {
      await obtainFile(await encrypt(currentPassword, dataInput.innerText), filename);

      // reset saving functionality, user might continue use after save
      setProperty('--display-save', 'none');
      window.removeEventListener('beforeunload', preventUnload);
      dataInput.addEventListener('input', activateSaveButton, { once: true });
    });

    emptyButton.addEventListener('click', async (_) => {
      await obtainFile('', filename);
    });

    // this will be called again if password is changed
    const showDecrypted = (decryptedData = undefined) => {
      // show content, hide login
      setProperty('--display-form', 'none');
      setProperty('--display-repw', 'none');
      setProperty('--display-main', 'inline');

      if (decryptedData !== undefined) {
        dataInput.innerText = decryptedData;
      }
      dataInput.removeEventListener('input', activateSaveButton, { once: true }); // remove if previous still exists
      dataInput.addEventListener('input', activateSaveButton, { once: true });

      // detect ctrl+s, save only if save button is shown
      window.addEventListener('keydown', (event) => {
        if (!(event.ctrlKey && event.key === 's')) return true;
        if (document.documentElement.style.getPropertyValue('--display-save') === 'inline') {
          saveButton.click();
        }
        event.preventDefault();
        return false;
      });

      // focus if empty
      if (decryptedData === '') {
        dataInput.focus();
      }
    };

    if (dataEmpty()) {
      setProperty('--display-repw', 'inline');
      formSubmit.addEventListener('click', pickPassword);
    } else {
      form.password.autocomplete = 'current-password';
      form.password.focus();
      setProperty('--display-repw', 'none');
      formSubmit.addEventListener('click', enterPassword);
    };
  });
}
