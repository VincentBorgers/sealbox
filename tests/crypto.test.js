import { test } from 'node:test'
import assert from 'node:assert/strict'
import { encrypt, decrypt, inspect, parseHeader, MAGIC } from '../src/crypto.js'

const PASSPHRASE = 'correct horse battery staple'

test('encrypt then decrypt returns the original data', () => {
  const data = Buffer.from('hello sealbox')
  const container = encrypt(data, PASSPHRASE)
  const { plaintext } = decrypt(container, PASSPHRASE)
  assert.deepEqual(plaintext, data)
})

test('a wrong passphrase is rejected', () => {
  const container = encrypt(Buffer.from('secret'), PASSPHRASE)
  assert.throws(() => decrypt(container, 'wrong'), /Wrong passphrase/)
})

test('an empty input encrypts and decrypts', () => {
  const container = encrypt(Buffer.alloc(0), PASSPHRASE)
  const { plaintext } = decrypt(container, PASSPHRASE)
  assert.equal(plaintext.length, 0)
})

test('binary data with every byte value round trips', () => {
  const data = Buffer.from(Array.from({ length: 256 }, (_, i) => i))
  const { plaintext } = decrypt(encrypt(data, PASSPHRASE), PASSPHRASE)
  assert.deepEqual(plaintext, data)
})

test('unicode text round trips', () => {
  const data = Buffer.from('wachtwoord éà中文🔒', 'utf8')
  const { plaintext } = decrypt(encrypt(data, PASSPHRASE), PASSPHRASE)
  assert.equal(plaintext.toString('utf8'), 'wachtwoord éà中文🔒')
})

test('a larger payload round trips', () => {
  const data = Buffer.alloc(200 * 1024, 7)
  const { plaintext } = decrypt(encrypt(data, PASSPHRASE), PASSPHRASE)
  assert.deepEqual(plaintext, data)
})

test('the burn flag survives a round trip and is off by default', () => {
  assert.equal(decrypt(encrypt(Buffer.from('x'), PASSPHRASE), PASSPHRASE).burn, false)
  assert.equal(decrypt(encrypt(Buffer.from('x'), PASSPHRASE, { burn: true }), PASSPHRASE).burn, true)
})

test('two encryptions of the same input use a fresh salt and nonce', () => {
  const data = Buffer.from('same input')
  const a = encrypt(data, PASSPHRASE)
  const b = encrypt(data, PASSPHRASE)
  assert.ok(!a.equals(b), 'containers should differ')
  const headerA = parseHeader(a)
  const headerB = parseHeader(b)
  assert.ok(!headerA.salt.equals(headerB.salt), 'salt should differ')
  assert.ok(!headerA.iv.equals(headerB.iv), 'nonce should differ')
})

test('flipping a ciphertext byte is detected', () => {
  const container = encrypt(Buffer.from('tamper me, please'), PASSPHRASE)
  container[container.length - 1] ^= 0x01
  assert.throws(() => decrypt(container, PASSPHRASE), /changed/)
})

test('flipping an authentication tag byte is detected', () => {
  const container = encrypt(Buffer.from('hands off'), PASSPHRASE)
  // The tag sits just before the ciphertext, in the last 16 bytes of the header.
  const header = parseHeader(container)
  const tagStart = container.length - header.ciphertext.length - 16
  container[tagStart] ^= 0x80
  assert.throws(() => decrypt(container, PASSPHRASE), /changed/)
})

test('a container with the wrong magic is rejected', () => {
  const container = encrypt(Buffer.from('x'), PASSPHRASE)
  container.write('NOPEBOX1', 0, 'ascii')
  assert.throws(() => parseHeader(container), /not a sealbox file/)
})

test('a truncated container is rejected', () => {
  const container = encrypt(Buffer.from('x'), PASSPHRASE)
  assert.throws(() => parseHeader(container.subarray(0, 10)), /too small/)
})

test('parseHeader rejects a non buffer', () => {
  assert.throws(() => parseHeader('not a buffer'), /not a sealbox file/)
})

test('inspect reports the format without the passphrase', () => {
  const meta = inspect(encrypt(Buffer.from('abcde'), PASSPHRASE, { burn: true }))
  assert.equal(meta.version, 1)
  assert.equal(meta.burn, true)
  assert.equal(meta.params.logN, 17)
  assert.equal(meta.params.r, 8)
  assert.equal(meta.params.p, 1)
  assert.equal(meta.saltLength, 16)
  assert.equal(meta.ivLength, 12)
  assert.equal(meta.ciphertextLength, 5)
})

test('the magic marker is the documented value', () => {
  assert.equal(MAGIC.toString('ascii'), 'SEALBOX1')
})
