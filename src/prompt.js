const ENTER = ['\n', '\r']
const CTRL_C = String.fromCharCode(3)
const CTRL_D = String.fromCharCode(4)
const BACKSPACE = [String.fromCharCode(8), String.fromCharCode(127)]

// Reads a line from the terminal without echoing what the user types.
// Rejects when there is no interactive terminal, so callers can fall back
// to an environment variable.
export function promptHidden(question) {
  return new Promise((resolve, reject) => {
    const input = process.stdin
    const output = process.stderr

    if (!input.isTTY) {
      reject(new Error('No interactive terminal available. Set SEALBOX_PASSPHRASE instead.'))
      return
    }

    output.write(question)
    input.setRawMode(true)
    input.resume()

    let value = ''

    const cleanup = () => {
      input.setRawMode(false)
      input.pause()
      input.removeListener('data', onData)
    }

    const onData = (chunk) => {
      for (const char of chunk.toString('utf8')) {
        if (ENTER.includes(char) || char === CTRL_D) {
          cleanup()
          output.write('\n')
          resolve(value)
          return
        }
        if (char === CTRL_C) {
          cleanup()
          output.write('\n')
          reject(new Error('Cancelled.'))
          return
        }
        if (BACKSPACE.includes(char)) {
          value = value.slice(0, -1)
          continue
        }
        value += char
      }
    }

    input.on('data', onData)
  })
}
