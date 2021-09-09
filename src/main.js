/*
classied.html

LICENCE
*/

const data = `
`;// data end

/*
* Shared code and functions for all platforms
*/

const VERSION = '0.0.2';
DEFAULT_PBKDF2_ITERATIONS = 100000;
const inBrowser = () => typeof window !== 'undefined';
const dataEmpty = () => data === '\n';
const nodeVersionSupported = () => !(process.versions.node.split('.')[0] < 15);
const browserSupported = () => window.crypto?.subtle !== undefined;

try { // catch errors for displaying alerts if in browser
  // BASE64-JS

  // set global variables based on the execution environment
  let subtle;
  let getRandomValues;
  const utf8Encoder = new TextEncoder('utf-8');
  const DATA_LINE_LEN = 100;
  if (inBrowser()) {
    if (!browserSupported()) {
      document.body.innerHTML = '<p>classified.html requires a browser that supports <a href="https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API">Web Crypto API</a>. Please update or try some other browser.</p>';
      throw new Error('classified.html requires a browser that supports Web Crypto API');
    }
    subtle = window.crypto.subtle;
    getRandomValues = (arr) => window.crypto.getRandomValues(arr);
  } else {
    if (!nodeVersionSupported()) {
      console.log(`classified.html uses Web Crypto API, Node.js version 15 or higher required (current version: ${process.versions.node})`);
      process.exit(1);
    }
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
  const encryptionValuesToStrorableSring = (salt, iv, iterations, encrypted) => (
    `salt:${salt.join('-')}\niv:${iv.join('-')}\niterations:${iterations}\ndata:\n${toLines(arrayBufferToBase64(encrypted))}\n`
  );

  /*
  Helper for recovering stored data from string
  */
  const encryptionValuesFromStroredSring = (str) => {
    const lines = str.split(/\r?\n|\r/g);
    const salt = new Uint8Array(lines[1].replace('salt:', '').split('-'));
    const iv = new Uint8Array(lines[2].replace('iv:', '').split('-'));
    const iterations = parseInt(lines[3].replace('iterations:', ''));
    const data = lines.splice(5).join('');
    return { salt, iv, data, iterations };
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
  const getKey = async (password, salt, iterations) => {
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
        salt,
        iterations,
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
  const encrypt = async (password, message, iterations) => {
    const salt = getRandomValues(new Uint8Array(16));
    const iv = getRandomValues(new Uint8Array(12));
    const key = await getKey(password, salt, iterations);

    const encrypted = await subtle.encrypt(
      {
        name: 'AES-GCM',
        iv
      },
      key,
      utf8Encoder.encode(placeholderData + message)
    );

    return encryptionValuesToStrorableSring(salt, iv, iterations, encrypted);
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
    const key = await getKey(password, parsedData.salt, parsedData.iterations);

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
      const data = dec.decode(decrypted).slice(placeholderData.length);
      return { success: true, data, iterations: parsedData.iterations };
    } catch (e) {
      return { success: false };
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

  /*
  Encode values and text into a spesific extendable format, which is later decodeable.

  The format is designed to work without limiting any characters from the input
  and without needing to handle escaping characters. This is done by saving lengths of
  text and each value. It can also handle skipping unknown sections.

  header:
  - start with header length, each section is separated by '&'
  - each section starts with the section name, and is followed by part lengths, separated by '|'

  body:
  - concatonates all data together without separations. Can be splitted according to the header part lengths.

  example:
  values: [key1, value1], [key2, value2] text: 'example_text'
  encoded: 22&values|4|6|4|6&text|13key1value1key2value2example_text

  NOTE: currently only encodes text, other data types can be added in the future
  */
  const encode = (text) => {
    let header = '';
    let body = '';

    // append text info to header and text to body
    header += 'text';
    header += `|${text.length}`;
    body += `${text}`;

    // prepend header with the header length
    header = `${header.length}&${header}`;

    // return encoded
    return header + body;
  };

  /*
  Decode values and text from input. See explanation form 'encode'.
  */
  const decode = (input) => {
    let text = '';

    // separate headersections form the body
    const headerLen = Number(input.substring(0, input.indexOf('&')));
    const headerSectionsArray = input.substring(input.indexOf('&') + 1, headerLen + String(headerLen).length + 1).split('&');
    const body = input.substring(input.indexOf('&') + 1 + headerLen, input.length);

    // parse each header section, read the parts from the body and do operations based on the name at the start
    let bodyReadPos = 0;
    for (const section of headerSectionsArray) {
      const [name, ...lengths] = section.split('|');
      const parts = lengths.map(len => {
        const part = body.substring(bodyReadPos, bodyReadPos + Number(len));
        bodyReadPos += Number(len);
        return part;
      });

      switch (name) {
        case 'text':
          text += parts[0];
          break;
        default:
          console.log(`Unknown header section: ${name}`);
      };
    }

    return text;
  };

  if (!inBrowser()) { // executed in Node.js
    /*
    * Node.js specific code
    */

    const fs = require('fs');
    const readline = require('readline');
    const path = require('path');
    const filename = path.basename(__filename);
    const args = process.argv.slice(2);
    const helpString = `
classified.html version ${VERSION}

Open in browser or with Node.js by running 'node ${filename}'
Advanced usage: node ${filename} [COMMAND [TARGET [DATA...]]]

COMMANDS:
  Data modifying commands:
    add         add DATA to TARGET
    modify      modify current TARGETs data
    replace     replace existing data with DATA on TARGET
    delete      delete TARGET and its data
    show        show TARGET's data on the terminal

  Other commands:
    new         download empty classified.html. Will ask for save location if not specified in TARGET
    help        show this help message
    exit        save and exit, same as the default when the command is left empty
    discard     discard changes, clear concole and quit, same as pressing ctrl+c
    password    change password. Will ask the new one if not spesified in in TARGET
    debug       put 'debug' before COMMAND to disable clearing the console

TARGETS:
  text          all of the text
  row ID        row of text. ID can be a number or a start of the line, for example 'row 5' or 'row the'

Example usage:
  NOTE: all of these commands can be used after opening with 'node ${filename}' or
  you can can pass them directly before giving password, for example: 'node ${filename} show row email'.
  This will make the program exit automatically after the command has been executed.

  add text This is classified.html    append 'This is classified.html' row to text
  delete row 1                        delete the first row of text
  add text email user password        appends 'email user password' row to text
  show row email                      show row which starts with 'email'
  delete row 2                        delete row number 2
  modify row email                    modify row which starts with email
  delete text                         deletes all text content
`;

    // global variables to handle Node.js state
    let password, rows, iterations;
    let changes = false;
    let waitingForCommand = false;
    let readLineInterface;
    let debugging = false;

    // clear console if not debugging, seems to work on all major platforms: https://stackoverflow.com/a/32899667 should be tested more
    const clearConsole = () => { if (!debugging) process.stdout.write('\x1Bc'); };

    // put into debug mode if requested and remove the debug command from args
    if (args.length > 0 && ['-d', '--debug', 'debug'].includes(args[0])) {
      debugging = true;
      args.shift();
    }

    // always clear the console on exit if exit has not been marked to be handled properly and not debugging
    let exitHandled = false;
    if (!debugging) {
      process.on('exit', (code) => {
        if (!exitHandled) {
          clearConsole();
          console.log('possible changes discarded');
        }
        process.exit(code);
      });
    }

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

    // write to global readline, if resized when waiting for a command
    process.stdout.on('resize', () => {
      if (waitingForCommand) readLineInterface.write('resize\n');
    });

    /*
    Ask for new command and parse the response to command, target and data.
    Use a list of previous commands as hints.
    */
    const parseCommand = (input) => {
      let [command, target, ...commandData] = input.split(' ');
      commandData = commandData.join(' ');
      if (command === '') command = undefined;
      if (commandData === '') commandData = undefined;
      if (commandData === "''" || commandData === '""') commandData = '';
      return [command, target, commandData];
    };

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
        return `${savePath} saved`;
      } catch (err) {
        return `Could not save ${savePath}:\n${err}`;
      }
    };

    /*
    Helper function to select a new password
    */
    const choosePassword = async () => {
      let password, repassword;
      while (true) {
        password = await prompt('choose a password: ');
        repassword = await prompt('re-enter the password: ');
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
      return [password, await decode(decryptionResult.data), decryptionResult.iterations];
    };

    /*
    Get or choose password and return existing decrypted data
    */
    const getPasswordAndData = async () => {
      if (dataEmpty()) {
        return [await choosePassword(), '', DEFAULT_PBKDF2_ITERATIONS]; // TODO allow choosing the iterations on cli
      } else {
        return await decryptExistingData();
      }
    };

    /*
    Ask question and wait for reply.
    Allow using up/down arrows for prefilling options if given.
    readLineInterface can be written outside, if terminal is resized when waiting for command.
    */
    const question = (question, previous = [], placeholder) => new Promise(resolve => {
      readLineInterface = readline.createInterface({
        input: process.stdin,
        output: process.stdout
      });

      const maxPreviousIndex = previous.length - 1;
      let previousIndex = -1;
      const clearLine = () => readLineInterface.write(null, { ctrl: true, name: 'u' });
      const reactUpDown = (input) => {
        if (input === '\u001b[A') { // arrow up
          if (previousIndex < maxPreviousIndex) {
            previousIndex++;
            clearLine();
            readLineInterface.write(previous[previousIndex]);
          }
        } else if (input === '\u001b[B') { // down arrow
          if (previousIndex > -1) {
            previousIndex--;
            clearLine();
            readLineInterface.write(previous[previousIndex]);
          } else {
            clearLine();
          }
        }
      };

      process.stdin.on('data', reactUpDown);
      readLineInterface.question(question, (reply) => {
        process.stdin.removeListener('data', reactUpDown);
        readLineInterface.close();
        resolve(reply);
      });
      if (placeholder) readLineInterface.write(placeholder);
    });

    /*
    Save changes if a new file or changes
    Saving is done by writing data to a temporary file, and renaming it to the actual one.
    */
    const saveChanges = async (password, text) => {
      if (dataEmpty() || changes) {
        // generate source
        const source = fs.readFileSync(__filename, 'utf8');
        const updatedData = await encrypt(password, await encode(text), iterations);
        const updatedSource = updateSourceData(source, updatedData);

        let triesLeft = 10;
        while (true) {
          // get temporary path to a file that does not yet exist
          const tempPath = `${__filename}_temp-${require('crypto').randomBytes(10).toString('hex')}`;
          if (fs.existsSync(tempPath)) {
            if (triesLeft === 0) {
              console.log(`could not save ${__filename}: could not generate temp path`);
              break;
            }
            triesLeft--;
            continue;
          }

          // copy file to temp file, and rename
          try {
            fs.writeFileSync(tempPath, updatedSource, { flag: 'wx' });
            fs.renameSync(tempPath, __filename);
            console.log('changes saved!');
            break;
          } catch (err) {
            if (triesLeft === 0) {
              console.log(`could not save ${__filename}:\n${err}`);
              break;
            }
            triesLeft--;
          };
        }
      } else {
        console.log('no changes to save');
      }
    };
    /*
    Command handling helpers:
    */

    const minRowLen = 58; // note, can be shorter if the terminal is shorter

    // append input with a cyan row number and space, normal text to black and background to white
    const row = (str, len, num) => {
      numStr = String(num).padEnd(2);
      if (str.length < len - numStr.length) {
        return `\x1b[36m\x1b[47m${numStr}\x1b[30m\x1b[47m${str.padEnd(len - numStr.length)}\x1b[0m`;
      } else {
        const fillerSpaces = ' '.repeat(process.stdout.columns - (numStr + str).length % process.stdout.columns);
        return `\x1b[36m\x1b[47m${numStr}\x1b[30m\x1b[47m${str}${fillerSpaces}\x1b[0m`;
      }
    };

    const getPrintWidth = () => {
      let longestRowLen = 0;
      if (rows.length !== 0) {
        longestRowLen = rows.reduce((a, b) => a.length > b.length ? a : b).length + 3; // 3 because padding start and end
      }

      return Math.min(Math.max(longestRowLen, minRowLen), process.stdout.columns);
    };

    const printContents = () => {
      clearConsole();
      if (rows.length !== 0) {
        const printWidth = getPrintWidth();
        let textContents = '';
        for (let rowNum = 0; rowNum < rows.length; rowNum++) {
          textContents += row(rows[rowNum], printWidth, rowNum + 1) + '\n';
        }
        console.log(textContents.slice(0, -1));
      }
    };

    const onlyDigits = rowString => [...rowString].every(c => '0123456789'.includes(c));

    const parseRow = (commandData, multipleRowsAllowed = false) => {
      const rowString = commandData.split(' ')[0];
      let errorString;
      if (onlyDigits(rowString)) {
        const rowNumber = parseInt(rowString);
        if (isNaN(rowNumber) || rowNumber <= 0) errorString = `not a proper row: ${rowString}`;
        return [[rowNumber], errorString];
      } else {
        const rowNumbers = [];
        for (const [i, row] of rows.entries()) {
          if (row.startsWith(rowString)) rowNumbers.push(i + 1);
        }
        if (rowNumbers.length === 0) errorString = `no row matches: ${rowString}`;
        if (!multipleRowsAllowed && rowNumbers.length > 1) errorString = `multiple row matches: ${rowNumbers.length}`;
        return [rowNumbers, errorString];
      }
    };

    const parseRowCommand = (commandData, multipleRowsAllowed = false) => {
      let [rowNumbers, errorString] = parseRow(commandData, multipleRowsAllowed);
      const command = commandData.split(' ').slice(1).join(' ');
      if (command === '') errorString = 'command data missing';
      return [rowNumbers, command, errorString];
    };

    const addText = (commandData) => {
      changes = true;
      rows.push(commandData);
      return 'new row added';
    };

    const addRow = (commandData) => {
      changes = true;
      const [rowNumbers, command, errorString] = parseRowCommand(commandData);
      if (errorString !== undefined) return errorString;
      const rowNumber = rowNumbers[0];
      if (rowNumber > rows.length + 1) return `row index too high: ${rowNumber}, use 'add row ${rows.length + 1}' or 'add text' to add row to the end`;
      rows.splice(rowNumber - 1, 0, command);
      return 'new row added';
    };

    const modifyRow = async (commandData) => {
      changes = true;
      const [rowNumbers, errorString] = parseRow(commandData);
      if (errorString !== undefined) return errorString;
      const rowNumber = rowNumbers[0];
      if (rowNumber > rows.length) return `row index too high: ${rowNumber}`;
      clearConsole();
      rows[rowNumber - 1] = await question('', [], rows[rowNumber - 1]);
      return `row ${rowNumber} modified`;
    };

    const deleteText = () => {
      changes = true;
      rows = [];
      return 'text deleted';
    };

    const deleteRow = (commandData) => {
      changes = true;
      const [rowNumbers, errorString] = parseRow(commandData);
      if (errorString !== undefined) return errorString;
      const rowNumber = rowNumbers[0];
      if (rowNumber > rows.length) return `row index too high: ${rowNumber}`;
      rows.splice(rowNumber - 1, 1);
      return `row ${rowNumber} deleted`;
    };

    const replaceText = (commandData) => {
      changes = true;
      rows = [commandData];
      return 'text replaced';
    };

    const replaceRow = (commandData) => {
      changes = true;
      const [rowNumbers, command, errorString] = parseRowCommand(commandData);
      if (errorString !== undefined) return errorString;
      const rowNumber = rowNumbers[0];
      if (rowNumber < rows.length + 1) {
        rows[rowNumber - 1] = command;
        return `row ${rowNumber} replaced`;
      } else {
        return `could not replace row ${rowNumber}`;
      }
    };

    const showText = () => rows.join('\n');

    const showRow = (commandData) => {
      const [rowNumbers, errorString] = parseRow(commandData, true);
      if (errorString !== undefined) return errorString;
      let result = '';
      for (const rowNumber of rowNumbers) {
        if (rowNumber > rows.length) return `row index too high: ${row}`;
        result += rows[rowNumber - 1] + '\n';
      }
      return result.slice(0, -1); // remove extra newline
    };

    const changePassword = async () => {
      changes = true;
      clearConsole();
      console.log('changing password:');
      password = await choosePassword();
      return 'password changed successfully';
    };

    /*
    Handle user command. Returns a boolean which tells was the command handled properly
    and a message that should be logged.
    */
    const handleCommand = async (command, target, commandData) => {
      let unknownCommand = false;
      let handleMessage;
      if (command === 'exit' || command === undefined) {
        clearConsole();
        await saveChanges(password, rows.join('\n'));
        exitHandled = true;
        process.exit();
      } else if (command === 'discard') {
        process.exit(); // this will trigger on exit with exitHandled = false
      } else if (command === 'new') {
        handleMessage = await downloadNew(target);
      } else if (command === 'help') {
        handleMessage = helpString + '\n';
      } else if (command === 'add' && target === 'text' && commandData !== undefined) {
        handleMessage = addText(commandData);
      } else if (command === 'add' && target === 'row' && commandData !== undefined) {
        handleMessage = addRow(commandData);
      } else if (command === 'modify' && target === 'row' && commandData !== undefined) {
        handleMessage = await modifyRow(commandData);
      } else if (command === 'modify' && target === 'text') {
        handleMessage = 'currently modify works only on rows';
      } else if (command === 'delete' && target === 'text' && commandData === undefined) {
        handleMessage = deleteText();
      } else if (command === 'delete' && target === 'row' && commandData !== undefined) {
        handleMessage = deleteRow(commandData);
      } else if (command === 'delete' && target === 'row' && commandData === undefined) {
        handleMessage = 'row number to delete missing';
      } else if (command === 'show' && target === 'text' && commandData === undefined) {
        handleMessage = showText();
      } else if (command === 'show' && target === 'row' && commandData !== undefined) {
        handleMessage = showRow(commandData);
      } else if (command === 'replace' && target === 'text' && commandData !== undefined) {
        handleMessage = replaceText(commandData);
      } else if (command === 'replace' && target === 'text' && commandData === undefined) {
        handleMessage = 'replace data missing';
      } else if (command === 'replace' && target === 'row' && commandData !== undefined) {
        handleMessage = replaceRow(commandData);
      } else if (command === 'password') {
        handleMessage = await changePassword();
      } else {
        unknownCommand = true;
        handleMessage = `command did not work: COMMAND: ${command}, TARGET: ${target}, DATA: ${commandData}`;
      }
      return [!unknownCommand, handleMessage];
    };

    (async () => {
      // parse commands passed through args
      const [command, target, commandData] = parseCommand(args.join(' '));

      // handle the cases whitch do not require password
      if (['-h', '--help', 'help'].includes(command)) {
        console.log(helpString);
        exitHandled = true;
        process.exit();
      }
      if (['-n', '--new', 'new'].includes(command)) {
        console.log(await downloadNew(target));
        exitHandled = true;
        process.exit();
      }

      // select password, or decrypt data with the existing one
      let decryptedData;
      [password, decryptedData, iterations] = await getPasswordAndData();
      // initialize rows
      rows = decryptedData === '' ? [] : decryptedData.split('\n');

      // handle any other command that required password except the default (exit)
      if (command !== undefined) {
        const [handled, message] = await handleCommand(command, target, commandData);
        clearConsole();
        if (handled) {
          if (message) console.log(message + '\n');
          if (command === 'show') {
            await question('(press enter to exit)');
            clearConsole();
          }
          await saveChanges(password, rows.join('\n'));
        } else {
          console.log('error: could not handle command');
        }
        exitHandled = true;
        process.exit();
      }

      let hints = ['add text ', 'exit', 'discard', 'help', 'delete row ', 'replace row ', 'add row ', 'show row ', 'modify row '];
      let handled, message;
      while (true) {
        printContents();
        if (message) console.log(message + '\n');
        waitingForCommand = true;
        const reply = await question("type 'help', enter a command or leave empty to save and exit: ", hints);
        waitingForCommand = false;
        if (reply === 'resize') continue;

        const [command, target, commandData] = await parseCommand(reply);
        [handled, message] = await handleCommand(command, target, commandData); // this can exit the program

        // prepend list of hints if command was handled, and is different to the first one
        if (handled) {
          const newHint = `${command} ${target ? target + ' ' : ''}`;
          if (newHint !== hints[0]) hints = [newHint, ...hints];
        }
      }
    })();
  } else { // executed in Browser
    /*
    * Browser specific code
    */

    /*
  SVG-TERMS
    */
    const htmlTop = "//classified.html requires JavaScript to work properly. Try other browser or device.<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1.0'></head><body><script>";
    const htmlBottom = '<\/script></body></html>';
    let filename;
    if (location.href === 'https://classifiedhtml.com/') { // hosted
      filename = 'classified.html';
    } else { // local file
      filename = location.href.split('/').slice(-1)[0];
      if (navigator.canShare) { // local file on mobile
        filename = filename.split('%2F').slice(-1)[0]; // %2F means forward slash on mobile chrome for local files
      }
    }
    const source = htmlTop + document.currentScript.innerHTML + htmlBottom;

    window.addEventListener('DOMContentLoaded', () => {
      // set document html
      document.getElementsByTagName('body')[0].innerHTML = `
<!--HTML-->
      `;
      // set document css
      const style = document.createElement('style');
      style.textContent = `
/*CSS*/
      `;
      document.head.append(style);
      document.title = filename;

      const form = document.getElementById('form');
      const formSubmit = document.getElementById('form-submit');
      const dataInput = document.getElementById('text');
      const saveButton = document.getElementById('save');
      const changePasswordButton = document.getElementById('change');
      const emptyButton = document.getElementById('empty');
      const whatDiv = document.getElementById('what');
      const closeWhat = document.getElementById('close-popup');
      const iterations = document.getElementById('iterations');
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

      /*
      This handles automatically resizing textarea
      */
      const resize = () => {
        dataInput.style.height = 'auto';
        dataInput.style.height = dataInput.scrollHeight - 2 * parseInt(getComputedStyle(dataInput).paddingTop) + 'px';
      };

      dataInput.addEventListener('input', resize);
      window.addEventListener('resize', resize);
      resize();

      const downloadFile = async (data, name) => {
        const fileContent = updateSourceData(source, data);
        const file = new File([fileContent], name, { type: 'text/html' });

        const tmpButton = document.createElement('a');
        tmpButton.href = URL.createObjectURL(file);
        tmpButton.download = filename;
        tmpButton.click();
        tmpButton.remove();
      };

      /*
      Verfiy that the password values match and iterations field has a proper value.
      If everything is ok, return the password.
      */
      const getPasswordValue = () => {
        const password = form.password.value;
        const repassword = form.repassword.value;
        if (password === '') {
          alert('password cannot be empty');
          return undefined;
        } else if (password !== repassword) {
          alert('passwords did not match, please try again');
          form.password.value = '';
          form.repassword.value = '';
          return undefined;
        } else if (isNaN(parseInt(iterations.value)) || parseInt(iterations.value) < 1) {
          alert('Not a proper PBKDF2 iteration value');
        } else {
          return password;
        }
      };

      const choosePassword = async (e) => {
        e.preventDefault();
        const password = getPasswordValue();
        if (password !== undefined) {
          formSubmit.removeEventListener('click', choosePassword);
          currentPassword = password;
          await showDecrypted('');
        }
      };

      const rechoosePassword = async (e) => {
        e.preventDefault();
        const password = getPasswordValue();
        if (password !== undefined) {
          setProperty('--display-save', 'inline');
          formSubmit.removeEventListener('click', rechoosePassword);
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
          const text = await decode(decryptionResult.data);
          formSubmit.removeEventListener('click', enterPassword);
          currentPassword = password;
          showDecrypted(text);
        }
      };

      whatDiv.addEventListener('click', () => setProperty('--display-what', 'inline'));
      closeWhat.addEventListener('click', () => setProperty('--display-what', 'none'));

      changePasswordButton.addEventListener('click', async (_) => {
        form.password.autocomplete = 'new-password'; // block autocompleting old password
        form.password.placeholder = 'choose a password';
        formSubmit.value = 'Create';

        // set UI correclty
        formSubmit.addEventListener('click', rechoosePassword);
        form.password.value = '';
        form.repassword.value = '';
        setProperty('--display-form', 'inline-block');
        setProperty('--display-repw', 'inline');
        setProperty('--display-main', 'none');
        setProperty('--display-save', 'none');
        form.password.focus();
      });

      saveButton.addEventListener('click', async (_) => {
        await downloadFile(await encrypt(currentPassword, await encode(dataInput.value), parseInt(iterations.value)), filename); // TODO get iterations.value from decryptionResult?

        // reset saving functionality, user might continue use after save
        setProperty('--display-save', 'none');
        window.removeEventListener('beforeunload', preventUnload);
        dataInput.addEventListener('input', activateSaveButton, { once: true });
      });

      emptyButton.addEventListener('click', async (_) => {
        await downloadFile('', filename);
      });

      // this will be called again if password is changed
      const showDecrypted = (decryptedData = undefined) => {
        // show content, hide login
        setProperty('--display-form', 'none');
        setProperty('--display-repw', 'none');
        setProperty('--display-main', 'inline');

        if (decryptedData !== undefined) {
          dataInput.value = decryptedData;
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
        formSubmit.addEventListener('click', choosePassword);
      } else {
        form.password.autocomplete = 'current-password';
        form.password.placeholder = 'enter password';
        form.password.focus();
        formSubmit.value = 'Open';
        setProperty('--display-repw', 'none');
        setProperty('--display-advanced', 'none');
        formSubmit.addEventListener('click', enterPassword);
      };
    });
  }
} catch (e) {
  if (inBrowser()) alert(`error: ${e.message}\n\n${e.stack}`);
  throw (e);
}
