#!/usr/bin/env node
import { promises as fs } from 'node:fs'
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { encrypt, decrypt, inspect } from './crypto.js'
import { armor, readContainer } from './armor.js'
import { promptHidden } from './prompt.js'
import { secureDelete } from './secure-delete.js'

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))

const BOOLEAN_FLAGS = new Set(['burn', 'armor', 'stdout', 'force', 'help', 'version'])
const ALIASES = { o: 'out', h: 'help', v: 'version' }

function parseArgs(argv) {
  const args = { _: [] }
  for (let i = 0; i < argv.length; i++) {
    let token = argv[i]
    if (token.startsWith('--')) {
      token = token.slice(2)
      const eq = token.indexOf('=')
      if (eq !== -1) {
        args[token.slice(0, eq)] = token.slice(eq + 1)
      } else if (BOOLEAN_FLAGS.has(token)) {
        args[token] = true
      } else {
        args[token] = argv[++i]
      }
    } else if (token.startsWith('-') && token.length > 1) {
      const name = ALIASES[token.slice(1)] || token.slice(1)
      if (BOOLEAN_FLAGS.has(name)) {
        args[name] = true
      } else {
        args[name] = argv[++i]
      }
    } else {
      args._.push(token)
    }
  }
  return args
}

function fail(message) {
  process.stderr.write(`sealbox: ${message}\n`)
  process.exit(1)
}

async function readStdin() {
  const chunks = []
  for await (const chunk of process.stdin) chunks.push(chunk)
  return Buffer.concat(chunks)
}

async function readInput(args) {
  if (typeof args.text === 'string') {
    return { data: Buffer.from(args.text, 'utf8'), source: { type: 'text' } }
  }
  const path = args._[1]
  if (path) {
    if (!existsSync(path)) fail(`file not found: ${path}`)
    return { data: await fs.readFile(path), source: { type: 'file', path } }
  }
  if (!process.stdin.isTTY) {
    return { data: await readStdin(), source: { type: 'stdin' } }
  }
  fail('no input given. Pass a file, use --text, or pipe data on stdin.')
}

async function getPassphrase({ confirm }) {
  if (typeof args.passphrase === 'string') {
    process.stderr.write('sealbox: warning, a passphrase on the command line can be stored in your shell history.\n')
    return args.passphrase
  }
  if (process.env.SEALBOX_PASSPHRASE) {
    return process.env.SEALBOX_PASSPHRASE
  }
  const first = await promptHidden('Passphrase: ')
  if (!first) fail('empty passphrase.')
  if (confirm) {
    const again = await promptHidden('Confirm passphrase: ')
    if (first !== again) fail('the passphrases did not match.')
  }
  return first
}

async function writeOutput(path, data, force) {
  if (!force && existsSync(path)) {
    fail(`output already exists: ${path}. Use --force to overwrite.`)
  }
  await fs.writeFile(path, data)
}

async function runEncrypt() {
  const { data, source } = await readInput(args)
  const passphrase = await getPassphrase({ confirm: true })
  const container = encrypt(data, passphrase, { burn: Boolean(args.burn) })

  if (args.out) {
    const payload = args.armor ? Buffer.from(armor(container), 'utf8') : container
    await writeOutput(args.out, payload, Boolean(args.force))
    process.stderr.write(`Encrypted to ${args.out}\n`)
    return
  }

  if (source.type === 'file' && !args.stdout && !args.armor) {
    const outPath = `${source.path}.sealbox`
    await writeOutput(outPath, container, Boolean(args.force))
    process.stderr.write(`Encrypted to ${outPath}\n`)
    return
  }

  process.stdout.write(armor(container))
}

async function runDecrypt() {
  const { data, source } = await readInput(args)
  const container = readContainer(data)
  const passphrase = await getPassphrase({ confirm: false })
  const { plaintext, burn } = decrypt(container, passphrase)

  let outPath = args.out
  if (!outPath && !args.stdout) {
    if (source.type === 'file' && source.path.endsWith('.sealbox')) {
      outPath = source.path.slice(0, -'.sealbox'.length)
    }
  }

  if (outPath) {
    await writeOutput(outPath, plaintext, Boolean(args.force))
    process.stderr.write(`Decrypted to ${outPath}\n`)
  } else {
    process.stdout.write(plaintext)
  }

  if (burn) {
    if (source.type === 'file') {
      await secureDelete(source.path)
      process.stderr.write(`This was a one time file. ${source.path} has been destroyed.\n`)
    } else {
      process.stderr.write('This was a one time message. It cannot be opened again from its source.\n')
    }
  }
}

async function runInfo() {
  const { data } = await readInput(args)
  const meta = inspect(readContainer(data))
  process.stdout.write(
    [
      `format version : ${meta.version}`,
      `cipher         : AES-256-GCM`,
      `key derivation : scrypt (N=2^${meta.params.logN}, r=${meta.params.r}, p=${meta.params.p})`,
      `one time (burn): ${meta.burn ? 'yes' : 'no'}`,
      `salt bytes     : ${meta.saltLength}`,
      `nonce bytes    : ${meta.ivLength}`,
      `ciphertext     : ${meta.ciphertextLength} bytes`,
      '',
    ].join('\n'),
  )
}

function printHelp() {
  process.stdout.write(`sealbox ${pkg.version}
Strong file and text encryption with an optional one time mode.

Usage:
  sealbox encrypt [file] [options]
  sealbox decrypt [file] [options]
  sealbox info [file]

Commands:
  encrypt   Encrypt a file, a --text string, or data piped on stdin.
  decrypt   Decrypt a sealbox file or message.
  info      Show the settings of a sealbox file without decrypting it.

Options:
  -o, --out <path>   Write the result to this path.
  --burn             Mark the file as one time. It is destroyed after the
                     first successful decryption.
  --armor            Write or read base64 text instead of a binary file.
  --stdout           Write the result to standard output.
  --force            Overwrite the output file if it already exists.
  --text <string>    Use this text as the input instead of a file.
  --passphrase <s>   Provide the passphrase directly. Not recommended.
  -h, --help         Show this help.
  -v, --version      Show the version.

Passphrase:
  By default sealbox asks for the passphrase without showing it.
  You can also set the SEALBOX_PASSPHRASE environment variable, which is
  needed when the input is piped on stdin.

Examples:
  sealbox encrypt notes.txt
  sealbox decrypt notes.txt.sealbox
  sealbox encrypt secret.zip --burn
  sealbox encrypt --text "meeting code 4821" --armor
  echo "token" | SEALBOX_PASSPHRASE=hunter2 sealbox encrypt --armor
`)
}

const args = parseArgs(process.argv.slice(2))
const command = args._[0]

async function main() {
  if (args.version) {
    process.stdout.write(`${pkg.version}\n`)
    return
  }
  if (args.help || !command || command === 'help') {
    printHelp()
    return
  }
  switch (command) {
    case 'encrypt':
      await runEncrypt()
      break
    case 'decrypt':
      await runDecrypt()
      break
    case 'info':
      await runInfo()
      break
    default:
      fail(`unknown command: ${command}. Run "sealbox --help".`)
  }
}

main().catch((error) => fail(error.message))
