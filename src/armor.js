import { MAGIC } from './crypto.js'

const HEADER_LINE = '-----BEGIN SEALBOX MESSAGE-----'
const FOOTER_LINE = '-----END SEALBOX MESSAGE-----'

export function armor(container) {
  const base64 = container.toString('base64')
  const lines = base64.match(/.{1,64}/g) ?? ['']
  return `${HEADER_LINE}\n${lines.join('\n')}\n${FOOTER_LINE}\n`
}

export function dearmor(text) {
  const match = text.match(/-----BEGIN SEALBOX MESSAGE-----([\s\S]*?)-----END SEALBOX MESSAGE-----/)
  if (!match) return null
  return Buffer.from(match[1].replace(/\s+/g, ''), 'base64')
}

// Accepts a buffer that is either a raw binary container or armored text and
// returns the binary container.
export function readContainer(raw) {
  if (raw.length >= MAGIC.length && raw.subarray(0, MAGIC.length).equals(MAGIC)) {
    return raw
  }
  const container = dearmor(raw.toString('utf8'))
  if (!container) {
    throw new Error('Input is not a sealbox file or a sealbox message.')
  }
  return container
}
