import crypto from 'node:crypto'

// Binary container layout (all integers big endian):
//   magic        8 bytes   "SEALBOX1"
//   flags        1 byte    bit 0 = burn after reading
//   logN         1 byte    scrypt cost, N = 2 ** logN
//   r            4 bytes   scrypt block size
//   p            4 bytes   scrypt parallelism
//   salt        16 bytes
//   iv          12 bytes
//   tag         16 bytes   AES-GCM authentication tag
//   ciphertext  rest

export const MAGIC = Buffer.from('SEALBOX1', 'ascii')

const FLAG_BURN = 0x01
const SALT_LEN = 16
const IV_LEN = 12
const TAG_LEN = 16
const KEY_LEN = 32
const HEADER_LEN = MAGIC.length + 1 + 1 + 4 + 4 + SALT_LEN + IV_LEN + TAG_LEN

const KDF = { logN: 17, r: 8, p: 1 }
const SCRYPT_MAXMEM = 256 * 1024 * 1024

function deriveKey(passphrase, salt, params) {
  return crypto.scryptSync(passphrase, salt, KEY_LEN, {
    N: 2 ** params.logN,
    r: params.r,
    p: params.p,
    maxmem: SCRYPT_MAXMEM,
  })
}

export function encrypt(plaintext, passphrase, options = {}) {
  const burn = Boolean(options.burn)
  const salt = crypto.randomBytes(SALT_LEN)
  const iv = crypto.randomBytes(IV_LEN)
  const key = deriveKey(passphrase, salt, KDF)

  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv)
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
    const tag = cipher.getAuthTag()

    const header = Buffer.alloc(HEADER_LEN)
    let offset = 0
    offset += MAGIC.copy(header, offset)
    header.writeUInt8(burn ? FLAG_BURN : 0, offset); offset += 1
    header.writeUInt8(KDF.logN, offset); offset += 1
    header.writeUInt32BE(KDF.r, offset); offset += 4
    header.writeUInt32BE(KDF.p, offset); offset += 4
    offset += salt.copy(header, offset)
    offset += iv.copy(header, offset)
    offset += tag.copy(header, offset)

    return Buffer.concat([header, ciphertext])
  } finally {
    key.fill(0)
  }
}

export function parseHeader(container) {
  if (!Buffer.isBuffer(container) || container.length < HEADER_LEN) {
    throw new Error('This is not a sealbox file (too small or wrong format).')
  }
  if (!container.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error('This is not a sealbox file (bad header).')
  }

  let offset = MAGIC.length
  const flags = container.readUInt8(offset); offset += 1
  const logN = container.readUInt8(offset); offset += 1
  const r = container.readUInt32BE(offset); offset += 4
  const p = container.readUInt32BE(offset); offset += 4
  const salt = container.subarray(offset, offset + SALT_LEN); offset += SALT_LEN
  const iv = container.subarray(offset, offset + IV_LEN); offset += IV_LEN
  const tag = container.subarray(offset, offset + TAG_LEN); offset += TAG_LEN
  const ciphertext = container.subarray(offset)

  return {
    burn: (flags & FLAG_BURN) !== 0,
    params: { logN, r, p },
    salt,
    iv,
    tag,
    ciphertext,
  }
}

export function decrypt(container, passphrase) {
  const { burn, params, salt, iv, tag, ciphertext } = parseHeader(container)
  const key = deriveKey(passphrase, salt, params)

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv)
    decipher.setAuthTag(tag)
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()])
    return { plaintext, burn }
  } catch {
    throw new Error('Wrong passphrase, or the file has been changed.')
  } finally {
    key.fill(0)
  }
}

export function inspect(container) {
  const { burn, params, salt, iv, ciphertext } = parseHeader(container)
  return {
    version: 1,
    burn,
    params,
    saltLength: salt.length,
    ivLength: iv.length,
    ciphertextLength: ciphertext.length,
  }
}
