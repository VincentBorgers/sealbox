import { test } from 'node:test'
import assert from 'node:assert/strict'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { secureDelete } from '../src/secure-delete.js'

async function tempFile(contents) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sealbox-sd-'))
  const file = path.join(dir, 'data.bin')
  await fs.writeFile(file, contents)
  return file
}

test('secureDelete removes the file', async () => {
  const file = await tempFile(Buffer.alloc(5000, 9))
  await secureDelete(file)
  assert.equal(await fs.access(file).then(() => true, () => false), false)
})

test('secureDelete handles an empty file', async () => {
  const file = await tempFile(Buffer.alloc(0))
  await secureDelete(file)
  assert.equal(await fs.access(file).then(() => true, () => false), false)
})

test('secureDelete handles a file larger than one chunk', async () => {
  const file = await tempFile(Buffer.alloc(64 * 1024 * 2 + 123, 3))
  await secureDelete(file)
  assert.equal(await fs.access(file).then(() => true, () => false), false)
})

test('secureDelete rejects when the file does not exist', async () => {
  await assert.rejects(() => secureDelete(path.join(os.tmpdir(), 'sealbox-does-not-exist-xyz')))
})
