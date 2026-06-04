import { promises as fs } from 'node:fs'
import crypto from 'node:crypto'

const CHUNK = 64 * 1024

// Overwrites the file with random bytes once, then removes it. This reduces
// the chance of recovery, but it is best effort. See the README for the
// limits on solid state drives, copy on write filesystems and backups.
export async function secureDelete(path) {
  let handle
  try {
    const stat = await fs.stat(path)
    handle = await fs.open(path, 'r+')
    const size = stat.size
    const buffer = Buffer.allocUnsafe(Math.min(CHUNK, Math.max(size, 1)))
    let written = 0
    while (written < size) {
      const length = Math.min(CHUNK, size - written)
      crypto.randomFillSync(buffer, 0, length)
      await handle.write(buffer, 0, length, written)
      written += length
    }
    await handle.sync()
  } finally {
    if (handle) await handle.close()
  }
  await fs.unlink(path)
}
