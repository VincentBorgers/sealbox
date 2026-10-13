import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url))
const PASSPHRASE = 'command line passphrase'

function run(args, { input, env, cwd } = {}) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    input,
    cwd,
    env: { ...process.env, SEALBOX_PASSPHRASE: PASSPHRASE, ...env },
  })
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr.toString('utf8'),
  }
}

async function workdir() {
  return fs.mkdtemp(path.join(os.tmpdir(), 'sealbox-cli-'))
}

test('encrypt writes a .sealbox file and decrypt restores the original', async () => {
  const dir = await workdir()
  await fs.writeFile(path.join(dir, 'notes.txt'), 'the original content')

  const enc = run(['encrypt', 'notes.txt'], { cwd: dir })
  assert.equal(enc.status, 0, enc.stderr)
  assert.ok(await fs.access(path.join(dir, 'notes.txt.sealbox')).then(() => true, () => false))

  await fs.rm(path.join(dir, 'notes.txt'))
  const dec = run(['decrypt', 'notes.txt.sealbox'], { cwd: dir })
  assert.equal(dec.status, 0, dec.stderr)
  assert.equal(await fs.readFile(path.join(dir, 'notes.txt'), 'utf8'), 'the original content')
})

test('decrypt with a wrong passphrase fails without writing the output', async () => {
  const dir = await workdir()
  await fs.writeFile(path.join(dir, 'notes.txt'), 'secret')
  run(['encrypt', 'notes.txt'], { cwd: dir })
  await fs.rm(path.join(dir, 'notes.txt'))

  const dec = run(['decrypt', 'notes.txt.sealbox'], { cwd: dir, env: { SEALBOX_PASSPHRASE: 'wrong' } })
  assert.equal(dec.status, 1)
  assert.match(dec.stderr, /Wrong passphrase/)
  assert.equal(await fs.access(path.join(dir, 'notes.txt')).then(() => true, () => false), false)
})

test('encrypt refuses to overwrite an existing output unless --force is given', async () => {
  const dir = await workdir()
  await fs.writeFile(path.join(dir, 'notes.txt'), 'content')
  await fs.writeFile(path.join(dir, 'notes.txt.sealbox'), 'existing')

  const blocked = run(['encrypt', 'notes.txt'], { cwd: dir })
  assert.equal(blocked.status, 1)
  assert.match(blocked.stderr, /already exists/)
  assert.equal(await fs.readFile(path.join(dir, 'notes.txt.sealbox'), 'utf8'), 'existing')

  const forced = run(['encrypt', 'notes.txt', '--force'], { cwd: dir })
  assert.equal(forced.status, 0, forced.stderr)
  assert.notEqual(await fs.readFile(path.join(dir, 'notes.txt.sealbox'), 'utf8'), 'existing')
})

test('a --text message can be armored and decrypted back through stdin', async () => {
  const enc = run(['encrypt', '--text', 'meeting code 4821', '--armor'])
  assert.equal(enc.status, 0, enc.stderr)
  const block = enc.stdout.toString('utf8')
  assert.match(block, /-----BEGIN SEALBOX MESSAGE-----/)

  const dec = run(['decrypt', '--stdout'], { input: block })
  assert.equal(dec.status, 0, dec.stderr)
  assert.equal(dec.stdout.toString('utf8'), 'meeting code 4821')
})

test('a --burn file is destroyed after a successful decrypt', async () => {
  const dir = await workdir()
  await fs.writeFile(path.join(dir, 'secret.zip'), 'zip bytes')
  run(['encrypt', 'secret.zip', '--burn'], { cwd: dir })
  await fs.rm(path.join(dir, 'secret.zip'))

  const dec = run(['decrypt', 'secret.zip.sealbox'], { cwd: dir })
  assert.equal(dec.status, 0, dec.stderr)
  assert.match(dec.stderr, /destroyed/)
  assert.equal(await fs.readFile(path.join(dir, 'secret.zip'), 'utf8'), 'zip bytes')
  assert.equal(await fs.access(path.join(dir, 'secret.zip.sealbox')).then(() => true, () => false), false)
})

test('info shows the settings without a passphrase', async () => {
  const dir = await workdir()
  await fs.writeFile(path.join(dir, 'notes.txt'), 'abcde')
  run(['encrypt', 'notes.txt', '--burn'], { cwd: dir })

  const info = run(['info', 'notes.txt.sealbox'], { cwd: dir, env: { SEALBOX_PASSPHRASE: '' } })
  assert.equal(info.status, 0, info.stderr)
  const text = info.stdout.toString('utf8')
  assert.match(text, /cipher\s+: AES-256-GCM/)
  assert.match(text, /one time \(burn\): yes/)
  assert.match(text, /scrypt \(N=2\^17, r=8, p=1\)/)
})

test('an unknown command fails with a clear message', () => {
  const result = run(['frobnicate'])
  assert.equal(result.status, 1)
  assert.match(result.stderr, /unknown command: frobnicate/)
})

test('decrypt of a missing file fails', async () => {
  const dir = await workdir()
  const result = run(['decrypt', 'nope.sealbox'], { cwd: dir })
  assert.equal(result.status, 1)
  assert.match(result.stderr, /file not found/)
})

test('--version prints the package version', () => {
  const result = run(['--version'])
  assert.equal(result.status, 0)
  assert.match(result.stdout.toString('utf8').trim(), /^\d+\.\d+\.\d+$/)
})

test('--help prints usage', () => {
  const result = run(['--help'])
  assert.equal(result.status, 0)
  assert.match(result.stdout.toString('utf8'), /Usage:\s*\n\s*sealbox encrypt/)
})
