import { test } from 'node:test'
import assert from 'node:assert/strict'
import { armor, dearmor, readContainer } from '../src/armor.js'
import { encrypt } from '../src/crypto.js'

const PASSPHRASE = 'armor passphrase'

test('armor and dearmor are reversible', () => {
  const container = encrypt(Buffer.from('armored secret'), PASSPHRASE)
  const text = armor(container)
  assert.deepEqual(dearmor(text), container)
})

test('an armored block has the sealbox header and footer', () => {
  const text = armor(encrypt(Buffer.from('x'), PASSPHRASE))
  assert.match(text, /^-----BEGIN SEALBOX MESSAGE-----\n/)
  assert.match(text, /\n-----END SEALBOX MESSAGE-----\n$/)
})

test('armored lines are wrapped at 64 characters', () => {
  const text = armor(encrypt(Buffer.alloc(300, 1), PASSPHRASE))
  const body = text.split('\n').slice(1, -2)
  assert.ok(body.length > 1, 'expected several wrapped lines')
  for (const line of body) {
    assert.ok(line.length <= 64, `line too long: ${line.length}`)
  }
})

test('dearmor ignores surrounding text and extra whitespace', () => {
  const container = encrypt(Buffer.from('loose text around'), PASSPHRASE)
  const text = `please decrypt this\n\n${armor(container)}\n\nthanks`
  assert.deepEqual(dearmor(text), container)
})

test('dearmor returns null when there is no block', () => {
  assert.equal(dearmor('just some random text'), null)
})

test('readContainer accepts a raw binary container', () => {
  const container = encrypt(Buffer.from('raw'), PASSPHRASE)
  assert.deepEqual(readContainer(container), container)
})

test('readContainer accepts an armored container', () => {
  const container = encrypt(Buffer.from('armored'), PASSPHRASE)
  const armored = Buffer.from(armor(container), 'utf8')
  assert.deepEqual(readContainer(armored), container)
})

test('readContainer rejects data that is neither', () => {
  assert.throws(() => readContainer(Buffer.from('not a sealbox payload')), /not a sealbox/)
})
