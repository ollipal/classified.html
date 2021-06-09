/*
 * Shared code and functions for all platforms
 */

const VERSION = '0.0.1';
const inBrowser = () => typeof window !== 'undefined';
const dataEmpty = () => data === '\n';

const checkNodeVersionSupported = () => {
  const NODE_VERSION = process.versions.node;
  if (NODE_VERSION.split('.')[0] < 15) {
    console.log(`Uses Web Crypto API, Node 15 or higher required (current ${NODE_VERSION})`);
    process.exit(1);
  }
};

// set global variables based on the execution environment
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

/*
Convert a long data string to parts of certain length for storage
*/
const toLines = (str) => {
  const numLines = Math.ceil(str.length / DATA_LINE_LEN);
  const lines = new Array(numLines);
  for (let i = 0, start = 0; i < numLines; ++i, start += DATA_LINE_LEN) {
    lines[i] = str.substr(start, DATA_LINE_LEN);
  }
  return lines.join('\n');
};

/*
Convert array buffer to storable base64 characters
*/
const arrayBufferToBase64 = (buf) => fromByteArray(new Uint8Array(buf));

/*
Helper for storing user data in a recoverable way as a string
*/
const encryptionValuesToStrorableSring = (salt, iv, encrypted) => (
  `salt:${salt.join('-')}\niv:${iv.join('-')}\ndata:\n${toLines(arrayBufferToBase64(encrypted))}\n`
);

/*
Helper for recovering stored data from string
*/
const encryptionValuesFromStroredSring = (str) => {
  const lines = str.split(/\r?\n|\r/g);
  const salt = new Uint8Array(lines[1].replace('salt:', '').split('-'));
  const iv = new Uint8Array(lines[2].replace('iv:', '').split('-'));
  const data = lines.splice(4).join('');
  return { salt, iv, data };
};

/*
Placeholder data to always have home some data to encrypt.
This because on node decrypt seems to fail if there
was no data when it was encrypted (Node.js v15.9.0)
*/
const placeholderData = 'classified.html\n';

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
    utf8Encoder.encode(placeholderData + message)
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
    const message = dec.decode(decrypted).slice(placeholderData.length);
    return { data: message, success: true };
  } catch (e) {
    return { data: '', success: false };
  }
};

/*
Remove the old data from source and insert new
*/
const updateSourceData = (source, data) => {
  const sourceStart = source.split('const data' + ' = `')[0] + 'const data' + ' = `\n';
  const sourceEnd = '\`;// ' + 'data end' + source.split('\`;// ' + 'data end')[1];
  return sourceStart + data + sourceEnd;
};

if (!inBrowser()) { // executed in Node.js
  /*
   * Node.js specific code
   */

  const fs = require('fs');
  const os = require('os');
  const readline = require('readline');
  const path = require('path');
  const filename = path.basename(__filename);
  const helpString = `classified.html version ${VERSION}
Open in browser or with Node.js by running 'node ${filename}'


Advanced usage: node ${filename} [COMMAND [TARGET [DATA...]]]

COMMANDS:
  Data modifying commands:
    add         add DATA to TARGET
    replace     replace existing data with DATA on TARGET
    delete      delete TARGET and its data
    copy        copy TARGET's data to clipboard
    show        show TARGET's data on the terminal, clear the terminal after pressing enter and exit
    password    change password. Will ask the new one if not spesified in in TARGET

  Other commands:
    new         download empty classified.html. Will ask for save location if not specified in TARGET
    help        show this help message
    exit        save and exit, same as the default when the command is left empty
    discard     discard changes, clear concole and quit, same as pressing ctrl+c

TARGETS:
  text          all of the text
  row ROWNUM    some spesific row of text, for example 'row 5'
  values        all of the values
  value KEY     spesific value, for example 'value "server key"'. Key must be quoteted if it has spaces.


Example usage:
  add text This is classified.html    append 'This is classified.html' row to text
  delete row 1                        delete the first row of text
  add value 'server key' 1234         add value '1234' with a key 'server key' to values
  copy value 'server key'             copy value with a key 'server key' to the clipboard`;

  // global variables to handle Node.js state
  let password, decryptedData, newData;
  let passwordChanged = false;

  /*
  prompt from: https://github.com/ollipal/minimal-password-prompt
  Allows reading user input so that it is hidden
  */
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

  // always clear the console on exit if exit has not been marked to be handled properly
  let exitHandled = false;
  process.on('exit', (code) => {
    if (!exitHandled) {
      console.clear();
      console.log('possible changes discarded');
    }
    process.exit(code);
  });

  /*
  Ask for new command and parse the response to command, target and value.
  Use a list of previous commands as hints.
  */
  const parseCommand = (input) => {
    let [command, target, ...value] = input.split(' ');
    value = value.join(' ');
    if (command === '') command = undefined;
    if (value === '') value = undefined;
    if (value === "''" || value === '""') value = '';
    return [command, target, value];
  };

  /*
  Show the help string
  */
  const showHelp = () => console.log(helpString);

  /*
  Download new empty classified.html to savePath. If savePath was not supplied, ask for it.
  */
  const downloadNew = async (savePath) => {
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

  /*
  Helper function to select a new password
  */
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
  Ask user password until the data has been encrypted successfully.
  Return both the data and the password.
  */
  const decryptExistingData = async () => {
    let decryptionResult, password;
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
    return [password, decryptionResult.data];
  };

  /*
  Get or pick password and return existing decrypted data
  */
  const getPasswordAndData = async () => {
    if (dataEmpty()) {
      return [await pickPassword(), ''];
    } else {
      return await decryptExistingData();
    }
  };

  /*
  Ask question and wait for reply.
  Allow using up/down arrows for prefilling options if given.
  */
  const question = (question, previous = []) => new Promise(resolve => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    const maxPreviousIndex = previous.length - 1;
    let previousIndex = -1;
    const clearLine = () => rl.write(null, { ctrl: true, name: 'u' });
    const reactUpDown = (input) => {
      if (input === '\u001b[A') { // arrow up
        if (previousIndex < maxPreviousIndex) {
          previousIndex++;
          clearLine();
          rl.write(previous[previousIndex]);
        }
      } else if (input === '\u001b[B') { // down arrow
        if (previousIndex > -1) {
          previousIndex--;
          clearLine();
          rl.write(previous[previousIndex]);
        } else {
          clearLine();
        }
      }
    };

    process.stdin.on('data', reactUpDown);
    rl.question(question, (reply) => {
      process.stdin.removeListener('data', reactUpDown);
      rl.close();
      resolve(reply);
    });
  });

  /*
  Save changes only if new data, first time or password changed.
  Saving is done by writing data to a temporary file, and renaming it to the actual one.
  */
  const saveChanges = async (password, decryptedData, newData) => {
    if (newData !== '' || dataEmpty() || passwordChanged) {
      // copy file to tmp file, and rename
      try {
        const tmpPath = path.join(os.tmpdir(), filename);
        const source = fs.readFileSync(__filename, 'utf8');
        const updatedData = await encrypt(password, decryptedData + newData);
        const updatedSource = updateSourceData(source, updatedData);
        fs.writeFileSync(tmpPath, updatedSource);
        fs.renameSync(tmpPath, __filename);
        console.log('changes saved!');
      } catch (err) {
        console.log(`could not save ${__filename}:\n${err}`);
      };
    } else {
      console.log('no changes to save');
    }
  };

  /*
  Command handling helpers:
  */

  const printContents = () => {
    console.clear();
    if (decryptedData + newData !== '\n') console.log(decryptedData + newData);
  };

  const addText = (value) => {
    newData += value + '\n';
    printContents();
  };

  const changePassword = async () => {
    console.clear();
    console.log('changing password:');
    password = await pickPassword();
    passwordChanged = true;
  };

  /*
  Handle user command. Returns a boolean which tells was the command handled properly
  and a message that should be logged.
  */
  const handleCommand = async (command, target, value) => {
    let unknownCommand = false;
    let handleMessage;
    if (command === 'exit' || command === undefined) {
      console.clear();
      await saveChanges(password, decryptedData, newData);
      exitHandled = true;
      process.exit();
    } else if (command === 'add' && target === 'text' && value !== undefined) {
      addText(value);
    } else if (command === 'password') {
      await changePassword();
      handleMessage = 'password changed successfully';
    } else if (command === 'discard') {
      process.exit(); // this will trigger on exit with exitHandled = false
    } else {
      unknownCommand = true;
    }
    return [!unknownCommand, handleMessage];
  };

  (async () => {
    // parse commands passed through args
    const [command, target, value] = parseCommand(process.argv.slice(2).join(' '));

    // handle the cases whitch do not require password
    if (['-h', '--help', 'help'].includes(command)) {
      showHelp();
      exitHandled = true;
      process.exit();
    }
    if (['-n', '--new', 'new'].includes(command)) {
      await downloadNew(args[1]);
      exitHandled = true;
      process.exit();
    }

    // select password, or decrypt data with the existing one
    [password, decryptedData] = await getPasswordAndData();
    // initialize new data
    newData = decryptedData.endsWith('\n') ? '' : '\n';

    // handle any other command that required password except the default (exit)
    if (command !== undefined) {
      const [handled, message] = await handleCommand(command, target, value);
      console.clear();
      if (handled) {
        if (message) console.log(message);
        await saveChanges(password, decryptedData, newData);
      } else {
        console.log('error: could not handle command');
      }
      exitHandled = true;
      process.exit();
    }

    let previous = ['add text ', 'exit']; // hints
    let handled, message;
    while (true) {
      printContents();
      if (message) console.log(message);
      const reply = await question("type 'help', enter a command or leave empty to save and exit: ", previous);
      const [command, target, value] = await parseCommand(reply);
      [handled, message] = await handleCommand(command, target, value); // this can exit the program

      // prepend list of hints if values were used, and is different to the first one
      if (handled) {
        const newPrevious = `${command} ${target ? target + ' ' : ''}`;
        if (newPrevious !== previous[0]) previous = [newPrevious, ...previous];
      }
    }
  })();
} else { // executed in Browser
  /*
   * Browser specific code
   */

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
