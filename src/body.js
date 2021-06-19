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
  add value 'server key' 1 2 3         add value '1 2 3' with a key 'server key' to values
  copy value 'server key'             copy value with a key 'server key' to the clipboard`;

  // global variables to handle Node.js state
  let password, decryptedData, newData;
  let passwordChanged = false;
  let waitingForCommand = false;
  let rl;
  const values = {};

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

  // clear console, seems to work on all major platforms: https://stackoverflow.com/a/32899667 should be tested more
  const clearConsole = () => process.stdout.write('\x1Bc');

  // always clear the console on exit if exit has not been marked to be handled properly
  let exitHandled = false;
  process.on('exit', (code) => {
    if (!exitHandled) {
      clearConsole();
      console.log('possible changes discarded');
    }
    process.exit(code);
  });

  // write to global readline, if resized when waiting for a command
  process.stdout.on('resize', () => {
    if (waitingForCommand) rl.write('resize\n');
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
  rl can be written outside, if terminal is resized when waiting for command.
  */
  const question = (question, previous = []) => new Promise(resolve => {
    rl = readline.createInterface({
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

  const minRowLen = 58; // note, can be shorter if the terminal is shorter

  // return text padded with spaces, bolded, white and with black background
  const title = (str, len) => `\x1b[1m\x1b[37m\x1b[40m  ${str.padEnd(len - 2)}\x1b[0m`;

  // return value padded with spaces, bolded, white and with black background and cut to max length of the terminal
  const value = (key, value, len) => {
    if ((key + value).length <= len - 3) {
      return `\x1b[30m\x1b[47m ${key.padEnd(len - value.length - 2)}${'*'.repeat(value.length)} \x1b[0m`;
    } else if (process.stdout.columns - key.length - 6 >= 0) {
      return `\x1b[30m\x1b[47m ${key} ${'*'.repeat(process.stdout.columns - key.length - 6)}... \x1b[0m`;
    } else if (process.stdout.columns > 4) {
      return `\x1b[30m\x1b[47m${(' ' + key).substr(0, process.stdout.columns - 4)}... \x1b[0m`;
    }
  };

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
    let maxValuePrintLen = 0;
    Object.keys(values)
      .forEach((v, _) => {
        const len = v.length + values[v].length + 3; // 3 because at least one space in between and padding on both sides
        if (len > maxValuePrintLen) maxValuePrintLen = len;
      });

    let longestRowLen = 0;
    if (decryptedData + newData !== '\n') {
      const rows = (decryptedData + newData).split('\n');
      rows.shift(); // remove first
      rows.pop(); // remove last TODO why these are needed?
      longestRowLen = rows.reduce((a, b) => a.length > b.length ? a : b).length + 3; // 3 because padding start and end
    }

    return Math.min(Math.max(maxValuePrintLen, longestRowLen, minRowLen), process.stdout.columns);
  };

  const printContents = () => {
    clearConsole();
    const printWidth = getPrintWidth();

    if (Object.keys(values).length !== 0) {
      console.log(title('Values', printWidth));
      let textContents = '';
      Object.keys(values)
        .sort()
        .forEach((v, _) => {
          textContents += value(v, values[v], printWidth) + '\n';
        });
      textContents += value('', '', printWidth) + '\n';
      console.log(textContents);
    }

    if (decryptedData + newData !== '\n') {
      const rows = (decryptedData + newData).split('\n');
      rows.shift(); // remove first
      rows.pop(); // remove last TODO why these are needed?
      console.log(title('Text', printWidth));
      let textContents = '';
      for (let rowNum = 0; rowNum < rows.length; rowNum++) {
        textContents += row(rows[rowNum], printWidth, rowNum + 1) + '\n';
      }
      textContents += row('', printWidth, ' ');
      console.log(textContents);
    }
  };

  const addText = (commandData) => {
    newData += commandData + '\n';
  };

  const addValue = async (commandData) => {
    let key, value;
    // parse key
    if (commandData.startsWith('"') && commandData.split('"').length >= 3) {
      key = commandData.split('"')[1];
      value = commandData.slice(key.length + 3); // 2 x quotes + space = 3
    } else if (commandData.startsWith("'") && commandData.split("'").length >= 3) {
      key = commandData.split("'")[1];
      value = commandData.slice(key.length + 3); // 2 x quotes + space = 3
    } else if (commandData.split(' ').length >= 2) {
      key = commandData.split(' ')[0];
      value = commandData.slice(key.length + 1); // 1 x space = 1
    } else {
      key = commandData;
    }
    // check for duplicate
    if (key in values) {
      return `error: ${key} already in values, delete first if you want to replace`;
    }

    // get value if not present
    if (!value) {
      value = await prompt(`value for key ${key}: `);
    }

    // add value
    values[key] = value;
    return `value for ${key} added`;
  };

  const changePassword = async () => {
    clearConsole();
    console.log('changing password:');
    password = await pickPassword();
    passwordChanged = true;
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
      await saveChanges(password, decryptedData, newData);
      exitHandled = true;
      process.exit();
    } else if (command === 'discard') {
      process.exit(); // this will trigger on exit with exitHandled = false
    } else if (command === 'new') {
      handleMessage = await downloadNew(target);
    } else if (command === 'help') {
      handleMessage = helpString + '\n';
    } else if (command === 'add' && target === 'value' && commandData !== undefined) {
      handleMessage = await addValue(commandData);
    } else if (command === 'add' && target === 'text' && commandData !== undefined) {
      addText(commandData);
      handleMessage = 'new row added';
    } else if (command === 'password') {
      await changePassword();
      handleMessage = 'password changed successfully';
    } else {
      unknownCommand = true;
      handleMessage = `command did not work: COMMAND: ${command}, TARGET: ${target}, DATA: ${commandData}`;
    }
    return [!unknownCommand, handleMessage];
  };

  (async () => {
    // parse commands passed through args
    const [command, target, commandData] = parseCommand(process.argv.slice(2).join(' '));

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
    [password, decryptedData] = await getPasswordAndData();
    // initialize new data
    newData = decryptedData.endsWith('\n') ? '' : '\n';

    // handle any other command that required password except the default (exit)
    if (command !== undefined) {
      const [handled, message] = await handleCommand(command, target, commandData);
      clearConsole();
      if (handled) {
        if (message) console.log(message);
        await saveChanges(password, decryptedData, newData);
      } else {
        console.log('error: could not handle command');
      }
      exitHandled = true;
      process.exit();
    }

    let previous = ['add value ', 'add text ', 'exit', 'discard']; // hints
    let handled, message;
    while (true) {
      printContents();
      if (message) console.log(message);
      waitingForCommand = true;
      const reply = await question("type 'help', enter a command or leave empty to save and exit: ", previous);
      waitingForCommand = false;
      if (reply === 'resize') continue;

      const [command, target, commandData] = await parseCommand(reply);
      [handled, message] = await handleCommand(command, target, commandData); // this can exit the program

      // prepend list of hints if command was handled, and is different to the first one
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

  /*
  All of the svg logos used in this project are taken from Googles material-design-icons project.
  This licence file is also available at https://github.com/google/material-design-icons/blob/master/LICENSE

                                  Apache License
                            Version 2.0, January 2004
                          http://www.apache.org/licenses/

    TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

    1. Definitions.

        "License" shall mean the terms and conditions for use, reproduction,
        and distribution as defined by Sections 1 through 9 of this document.

        "Licensor" shall mean the copyright owner or entity authorized by
        the copyright owner that is granting the License.

        "Legal Entity" shall mean the union of the acting entity and all
        other entities that control, are controlled by, or are under common
        control with that entity. For the purposes of this definition,
        "control" means (i) the power, direct or indirect, to cause the
        direction or management of such entity, whether by contract or
        otherwise, or (ii) ownership of fifty percent (50%) or more of the
        outstanding shares, or (iii) beneficial ownership of such entity.

        "You" (or "Your") shall mean an individual or Legal Entity
        exercising permissions granted by this License.

        "Source" form shall mean the preferred form for making modifications,
        including but not limited to software source code, documentation
        source, and configuration files.

        "Object" form shall mean any form resulting from mechanical
        transformation or translation of a Source form, including but
        not limited to compiled object code, generated documentation,
        and conversions to other media types.

        "Work" shall mean the work of authorship, whether in Source or
        Object form, made available under the License, as indicated by a
        copyright notice that is included in or attached to the work
        (an example is provided in the Appendix below).

        "Derivative Works" shall mean any work, whether in Source or Object
        form, that is based on (or derived from) the Work and for which the
        editorial revisions, annotations, elaborations, or other modifications
        represent, as a whole, an original work of authorship. For the purposes
        of this License, Derivative Works shall not include works that remain
        separable from, or merely link (or bind by name) to the interfaces of,
        the Work and Derivative Works thereof.

        "Contribution" shall mean any work of authorship, including
        the original version of the Work and any modifications or additions
        to that Work or Derivative Works thereof, that is intentionally
        submitted to Licensor for inclusion in the Work by the copyright owner
        or by an individual or Legal Entity authorized to submit on behalf of
        the copyright owner. For the purposes of this definition, "submitted"
        means any form of electronic, verbal, or written communication sent
        to the Licensor or its representatives, including but not limited to
        communication on electronic mailing lists, source code control systems,
        and issue tracking systems that are managed by, or on behalf of, the
        Licensor for the purpose of discussing and improving the Work, but
        excluding communication that is conspicuously marked or otherwise
        designated in writing by the copyright owner as "Not a Contribution."

        "Contributor" shall mean Licensor and any individual or Legal Entity
        on behalf of whom a Contribution has been received by Licensor and
        subsequently incorporated within the Work.

    2. Grant of Copyright License. Subject to the terms and conditions of
        this License, each Contributor hereby grants to You a perpetual,
        worldwide, non-exclusive, no-charge, royalty-free, irrevocable
        copyright license to reproduce, prepare Derivative Works of,
        publicly display, publicly perform, sublicense, and distribute the
        Work and such Derivative Works in Source or Object form.

    3. Grant of Patent License. Subject to the terms and conditions of
        this License, each Contributor hereby grants to You a perpetual,
        worldwide, non-exclusive, no-charge, royalty-free, irrevocable
        (except as stated in this section) patent license to make, have made,
        use, offer to sell, sell, import, and otherwise transfer the Work,
        where such license applies only to those patent claims licensable
        by such Contributor that are necessarily infringed by their
        Contribution(s) alone or by combination of their Contribution(s)
        with the Work to which such Contribution(s) was submitted. If You
        institute patent litigation against any entity (including a
        cross-claim or counterclaim in a lawsuit) alleging that the Work
        or a Contribution incorporated within the Work constitutes direct
        or contributory patent infringement, then any patent licenses
        granted to You under this License for that Work shall terminate
        as of the date such litigation is filed.

    4. Redistribution. You may reproduce and distribute copies of the
        Work or Derivative Works thereof in any medium, with or without
        modifications, and in Source or Object form, provided that You
        meet the following conditions:

        (a) You must give any other recipients of the Work or
            Derivative Works a copy of this License; and

        (b) You must cause any modified files to carry prominent notices
            stating that You changed the files; and

        (c) You must retain, in the Source form of any Derivative Works
            that You distribute, all copyright, patent, trademark, and
            attribution notices from the Source form of the Work,
            excluding those notices that do not pertain to any part of
            the Derivative Works; and

        (d) If the Work includes a "NOTICE" text file as part of its
            distribution, then any Derivative Works that You distribute must
            include a readable copy of the attribution notices contained
            within such NOTICE file, excluding those notices that do not
            pertain to any part of the Derivative Works, in at least one
            of the following places: within a NOTICE text file distributed
            as part of the Derivative Works; within the Source form or
            documentation, if provided along with the Derivative Works; or,
            within a display generated by the Derivative Works, if and
            wherever such third-party notices normally appear. The contents
            of the NOTICE file are for informational purposes only and
            do not modify the License. You may add Your own attribution
            notices within Derivative Works that You distribute, alongside
            or as an addendum to the NOTICE text from the Work, provided
            that such additional attribution notices cannot be construed
            as modifying the License.

        You may add Your own copyright statement to Your modifications and
        may provide additional or different license terms and conditions
        for use, reproduction, or distribution of Your modifications, or
        for any such Derivative Works as a whole, provided Your use,
        reproduction, and distribution of the Work otherwise complies with
        the conditions stated in this License.

    5. Submission of Contributions. Unless You explicitly state otherwise,
        any Contribution intentionally submitted for inclusion in the Work
        by You to the Licensor shall be under the terms and conditions of
        this License, without any additional terms or conditions.
        Notwithstanding the above, nothing herein shall supersede or modify
        the terms of any separate license agreement you may have executed
        with Licensor regarding such Contributions.

    6. Trademarks. This License does not grant permission to use the trade
        names, trademarks, service marks, or product names of the Licensor,
        except as required for reasonable and customary use in describing the
        origin of the Work and reproducing the content of the NOTICE file.

    7. Disclaimer of Warranty. Unless required by applicable law or
        agreed to in writing, Licensor provides the Work (and each
        Contributor provides its Contributions) on an "AS IS" BASIS,
        WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
        implied, including, without limitation, any warranties or conditions
        of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
        PARTICULAR PURPOSE. You are solely responsible for determining the
        appropriateness of using or redistributing the Work and assume any
        risks associated with Your exercise of permissions under this License.

    8. Limitation of Liability. In no event and under no legal theory,
        whether in tort (including negligence), contract, or otherwise,
        unless required by applicable law (such as deliberate and grossly
        negligent acts) or agreed to in writing, shall any Contributor be
        liable to You for damages, including any direct, indirect, special,
        incidental, or consequential damages of any character arising as a
        result of this License or out of the use or inability to use the
        Work (including but not limited to damages for loss of goodwill,
        work stoppage, computer failure or malfunction, or any and all
        other commercial damages or losses), even if such Contributor
        has been advised of the possibility of such damages.

    9. Accepting Warranty or Additional Liability. While redistributing
        the Work or Derivative Works thereof, You may choose to offer,
        and charge a fee for, acceptance of support, warranty, indemnity,
        or other liability obligations and/or rights consistent with this
        License. However, in accepting such obligations, You may act only
        on Your own behalf and on Your sole responsibility, not on behalf
        of any other Contributor, and only if You agree to indemnify,
        defend, and hold each Contributor harmless for any liability
        incurred by, or claims asserted against, such Contributor by reason
        of your accepting any such warranty or additional liability.

    END OF TERMS AND CONDITIONS
  */

  const htmlTop = "//<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'></head><body><script>";
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
<div id=spacer></div>

<div class="grid">
  <div id="navbar">
    <div id="menu">
      <!-- <span class="logo-text">classified.html</span> -->
      <!--Menu-svg-->
      <svg height="32px" width="32px" viewBox="0 0 24 24" fill="none">
        <path d="M0 0h24v24H0V0z" fill="none"/>
        <path d="M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z" fill="currentColor"/>
      </svg>
    </div>
    <div class="nav-text">What is classified.html?</div>
    <div class="nav-text" id="empty">Download new empty</div>
    <div class="nav-text hide-when-not-main">Check for updates</div>
    <div class="nav-text hide-when-not-main" id="change">Change password</div>
    <div class="nav-text hide-when-not-main">Settings</div>
    <div class="nav-text" id="last-nav-text">v0.0.1 ollipal 2021</div>
  </div>

  <div id="values-container">
    <div id="values" class="data-sheet">
      <div class="title">Values</div>
      <div>TODO add value form</div>
    </div>
  </div>
  <div id="text-container">
    <div id="text" class="data-sheet">
      <div class="title">Text</div>
      <div id="text-div" contenteditable="true">Content</div>
    </div>
  </div>
</div>

<div class="save-container">
  <button id="save">save changes</button>
</div>
    `;
    // set document css
    const style = document.createElement('style');
    style.textContent = `
:root {
  /*State*/
  --display-form: inline-block;
  --display-repw: inline;
  --display-main: none;
  --display-save: none;
  --inner-height: 100vh; /*temporary*/
  /*Theme*/
  --col-primary: #000000;
  --col-secondary: #ffffff;
  --col-tertiary: #919191;
  --transition-speed: 150ms;
}

::placeholder { 
  color: var(--col-tertiary);
  opacity: 1; /* Firefox */
}

html {
  height: 100%;
}

body {
  font-family: 'Courier New', Courier, monospace;
  margin: 0px;
  height: 100%;
}

/* Firefox scrollbar */
* {
  scrollbar-width: thin;
  scrollbar-color: var(--col-primary) var(--col-secondary);
}
/* Chrome, Edge, and Safari scrollbar */
::-webkit-scrollbar {
  height: 7px;
  width: 7px;
}
::-webkit-scrollbar-track {
  background: var(--col-secondary);
}
::-webkit-scrollbar-thumb {
  background-color: var(--col-primary);
}
::selection {
  background: var(--col-primary);
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
  border-bottom: 1px solid var(--col-primary);
  margin-bottom: 10px;
  outline: none;
  font-family: 'Courier New', Courier, monospace;
  padding-bottom: 5px;
}

#form-submit {
  width: 70%;
  margin: 5px;
  padding: 5px;
  border: 1px solid var(--col-primary);
  color: var(--col-secondary);
  font-weight: bold;
  background-color: var(--col-primary);
  outline: none;
  font-family: 'Courier New', Courier, monospace;
  cursor: pointer;
  transition: 100ms ease;
}

#form-submit:hover {
  padding: 5px;
  border: 1px solid var(--col-primary);
  background-color: var(--col-secondary);
  color: var(--col-primary);
}

#main-div {
  display: var(--display-main);
}

.grid {
  display: grid;
  margin: 0;
}

#navbar {
  grid-area: navbar-container;
  position: fixed;
  background-color: transparent;
  transition: width 400ms ease;
  overflow: hidden;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  height: 100%;
}

#menu {
  height: 4rem;
  font-weight: bold;
  text-align: center;
  letter-spacing: 0.3ch;
  width: 100%;
  color: var(--col-primary);
  display: inline;
  padding-left: 0;
  display: flex;
  align-items: center;
}

#navbar:hover #menu{
  display: none;
}

.nav-text {
  width: 100%;
  align-items: center;
  height: 4rem;
  line-height: 4rem;
  display: none;
  white-space:nowrap;
  padding-left: 3rem;
}

.nav-text:last-child {
  margin-top: auto;
}

.nav-text:hover {
  background: var(--col-primary);
  color: var(--col-secondary);
}

#last-nav-text {
  background: var(--col-secondary);
  color: var(--col-primary);
}

#menu svg {
  width: 4rem;
  min-width: 4rem;
  display: flex;
  align-items: center;
}

#values-container {
  grid-area: values-container;
  display: var(--display-main);
}

#text-container {
  grid-area: text-container;
  display: var(--display-main);
}

.title {
  font-weight: bold;
  color: var(--col-secondary);
  background-color: var(--col-primary);
  letter-spacing: 0.3ch;
  height: 4rem;
  line-height: 4rem;
  padding-left: 1.5rem;
}

.data-sheet:focus-within {
  box-shadow: 0 4px 8px 0 rgba(0, 0, 0, 0.30), 0 6px 20px 0 rgba(0, 0, 0, 0.25);
}

.data-sheet {
  background-color: var(--col-secondary);
  font-family: 'Courier New', Courier, monospace;
  height:auto;
  max-width: 818px;
  box-shadow: 0 4px 8px 0 rgba(0, 0, 0, 0.2), 0 6px 20px 0 rgba(0, 0, 0, 0.19);
  text-align: left;
  overflow-wrap: anywhere; /* other option: overflow-wrap:normal; overflow: hidden; overflow-x: scroll; */
}

#navbar:hover {
  width: 18rem;
  box-shadow: 0 4px 8px 0 rgba(0, 0, 0, 0.30), 0 6px 20px 0 rgba(0, 0, 0, 0.25);
  background-color: var(--col-secondary);
}

#navbar:hover .nav-text:first-child {
  background-color: var(--col-primary);
}

#navbar:hover .nav-text {
  display: inline;
}

#navbar:hover .nav-text {
  transition: var(--transition-speed);
}

#text {
  margin: 1vw 1vw 6rem 0.5vw;
}

#text-div {
  padding: clamp(20px, 4vw, 96px);
  min-height:1058px;
  outline:none;
}

#values{
  margin: 1vw 0.5vw 6rem auto;
}

#values-container {
  padding-left: 1vw;
}


#save {
  width: 30%;
  min-width: 200px;
  line-height: 4rem;
  border: 1px solid var(--col-primary);
  color: var(--col-secondary);
  font-weight: bold;
  background-color: var(--col-primary);
  outline: none;
  font-family: 'Courier New', Courier, monospace;
  cursor: pointer;
  margin: 10px;
  transition: 50ms ease;
  display: var(--display-save);
}

#save:hover{
  width: 33%;
  line-height: 4.5rem;
  min-width: 250px;
  border: 1px solid var(--col-primary);
  background-color: var(--col-secondary);
  color: var(--col-primary);
}

.save-container {
  overflow: hidden;
  background-color: transparent;
  position: fixed;
  bottom: 0;
  width: calc(100% - 4rem);
  margin-left: 4rem;
  z-index: 100;
  text-align:center;
}

/*large screen*/
@media only screen and (min-width: 801px) {*
  #navbar {
    top: 0;
    width: 4rem;
    height: 100vh;
    background-color: transparent;
  }

  .grid {
    grid-template-columns: 4rem 1fr 1fr;
    grid-template-areas:'navbar-container values-container text-container';
  }

  .nav-text {
    display: none !important;
  }

  #navbar:hover .nav-text {
    display: inline !important;
  }

  #navbar:hover .hide-when-not-main {
    display: var(--display-main) !important;
  }
}

/*small screen*/
@media only screen and (max-width: 800px) {
  .grid {
    grid-template-areas:
      'values-container'
      'text-container'
      'navbar-container';
    overflow: hidden;
  }

  #text {
    margin: 1rem;
    min-height: 80vh;
  }

  #text-div {
    padding: 15px;
  }

  #values {
    margin: 1rem 1rem 0 1rem;
  }

  #values-container {
    padding-left: 0;
  }

  #navbar{
    position: unset;
    background-color: var(--col-secondary);
    transition: none;
  }

  .nav-text {
    display: inline;
    padding: 0;
    color: var(--col-tertiary);
    margin: auto;
    line-height: 3rem;
    height: 3rem;
    text-align: center;
    width: 100vw;
  }

  #last-nav-text {
    color: var(--col-tertiary);
  }


  #navbar:hover .nav-text {
    left: 0;
    padding: 0;
    margin: 0;
  }

  #menu {
    height: 3rem;
  }

  #navbar:hover {
    width: 100vw;
    box-shadow: none;
  }

  .title {
    height: 3rem;
    line-height: 3rem;
  }

  #save {
    line-height: 3rem;
  }

  #save:hover{
    line-height: 3.5rem;
  }

  .save-container {
    width: 100%;
    margin-left: 0;
  }

  #spacer {
    height: calc(100% - 3*3rem - 5px);/*without 5px scrolls for some reason...*/
    display: var(--display-form);
  }

  #menu{
    display: none;
  }

  .hide-when-not-main {
    display: inline;
  }
}

.hide-when-not-main {
  display: var(--display-main);
}

#navbar:hover .hide-when-not-main {
  display: var(--display-main);
}    
`;
    document.head.append(style);
    document.title = filename;

    const form = document.getElementById('form');
    const formSubmit = document.getElementById('form-submit');
    const dataInput = document.getElementById('text-div');
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
        alert('password cannot be empty');
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
      // reset pre-enterPassword changes
      form.password.autocomplete = 'new-password';
      form.password.placeholder = 'pick a password';
      formSubmit.value = 'Create';

      // set UI correclty
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
      form.password.placeholder = 'enter password';
      form.password.focus();
      formSubmit.value = 'Open';
      setProperty('--display-repw', 'none');
      formSubmit.addEventListener('click', enterPassword);
    };
  });
}
