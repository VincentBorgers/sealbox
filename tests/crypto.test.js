import test from 'node:test'
import assert from 'node:assert/strict'
import { encrypt, decrypt, inspect, parseHeader } from '../src/crypto.js'
import { armor, dearmor, readContainer } from '../src/armor.js'

test('encrypt then decrypt returns the original data', () => {
  const message = Buffer.from('the eagle lands at noon')
  const container = encrypt(message, 'correct horse battery staple')
  const { plaintext } = decrypt(container, 'correct horse battery staple')
  assert.equal(plaintext.toString(), 'the eagle lands at noon')
})

test('a wrong passphrase is rejected', () => {
  const container = encrypt(Buffer.from('secret'), 'right')
  assert.throws(() => decrypt(container, 'wrong'), /Wrong passphrase/)
})

test('a changed file is rejected', () => {
  const container = encrypt(Buffer.from('secret'), 'pw')
  container[container.length - 1] ^= 0xff
  assert.throws(() => decrypt(container, 'pw'), /Wrong passphrase|changed/)
})

test('the burn flag survives a round trip', () => {
  const container = encrypt(Buffer.from('once'), 'pw', { burn: true })
  assert.equal(inspect(container).burn, true)
  assert.equal(decrypt(container, 'pw').burn, true)
})

test('an empty input encrypts and decrypts', () => {
  const container = encrypt(Buffer.alloc(0), 'pw')
  assert.equal(decrypt(container, 'pw').plaintext.length, 0)
})

test('non sealbox data is reported clearly', () => {
  assert.throws(() => parseHeader(Buffer.from('not a sealbox file at all')), /not a sealbox file/)
})

test('armor and dearmor are reversible', () => {
  const container = encrypt(Buffer.from('armored secret'), 'pw')
  const text = armor(container)
  const back = dearmor(text)
  assert.ok(back.equals(container))
  assert.equal(decrypt(readContainer(Buffer.from(text, 'utf8')), 'pw').plaintext.toString(), 'armored secret')
})
