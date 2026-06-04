<h1 align="center">sealbox</h1>

<p align="center">
  Strong file and text encryption from the command line, with an optional one time mode that destroys the file after it is read once.
</p>

<p align="center">
  <a href="#license"><img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-blue.svg"></a>
  <img alt="Node" src="https://img.shields.io/badge/Node-%3E%3D18-339933?logo=node.js&logoColor=white">
  <img alt="Dependencies" src="https://img.shields.io/badge/dependencies-none-success">
  <a href="https://buymeacoffee.com/vincentborgers"><img alt="Buy me a coffee" src="https://img.shields.io/badge/Buy%20me%20a%20coffee-FFDD00?logo=buymeacoffee&logoColor=black"></a>
</p>

---

sealbox encrypts a file or a piece of text with a passphrase. It uses authenticated encryption, so it also detects if the data has been changed. There are no runtime dependencies. Everything is built on the crypto module that ships with Node.js.

## How it works

- The passphrase is turned into a 256 bit key with **scrypt** (N = 2^17, r = 8, p = 1). scrypt is slow and memory heavy on purpose, which makes guessing passphrases expensive.
- The data is encrypted with **AES-256-GCM**. GCM adds an authentication tag, so any change to the file is caught and decryption fails instead of returning wrong data.
- A new random salt and a new random nonce are generated for every file.
- All of this is stored in a small binary container. The settings travel with the file, so decryption needs nothing but the passphrase.

## Install

You need Node.js 18 or newer.

Clone and link it as a global command:

```bash
git clone https://github.com/VincentBorgers/sealbox.git
cd sealbox
npm link
```

After that the `sealbox` command is available in your terminal. To remove it again, run `npm unlink -g sealbox`.

You can also run it without installing, straight from the folder:

```bash
node src/cli.js encrypt notes.txt
```

## Usage

```text
sealbox encrypt [file] [options]
sealbox decrypt [file] [options]
sealbox info [file]
```

### Encrypt a file

```bash
sealbox encrypt notes.txt
```

This asks for a passphrase twice and writes `notes.txt.sealbox` next to the original. The original file is left in place.

### Decrypt a file

```bash
sealbox decrypt notes.txt.sealbox
```

This asks for the passphrase and writes `notes.txt` back.

### One time files

Add `--burn` to mark a file as one time. After the first successful decryption the encrypted file is overwritten with random bytes and removed, so it cannot be opened again.

```bash
sealbox encrypt secret.zip --burn
# send secret.zip.sealbox to someone
# on their side:
sealbox decrypt secret.zip.sealbox
# secret.zip is restored, and secret.zip.sealbox destroys itself
```

### Short text and copy paste

Use `--text` for a quick secret and `--armor` to get base64 text you can paste into a chat or email.

```bash
sealbox encrypt --text "meeting code 4821" --armor
```

This prints a block like:

```text
-----BEGIN SEALBOX MESSAGE-----
U0VBTEJPWDE...
-----END SEALBOX MESSAGE-----
```

To read it back, save the block to a file and decrypt it, or pipe it in:

```bash
sealbox decrypt message.txt --stdout
```

### Inspect a file

`info` shows the settings of a sealbox file without decrypting it and without a passphrase.

```bash
sealbox info notes.txt.sealbox
```

### Options

| Option              | Meaning                                                                 |
| ------------------- | ----------------------------------------------------------------------- |
| `-o, --out <path>`  | Write the result to this path.                                          |
| `--burn`            | Mark the file as one time. It is destroyed after the first decryption.  |
| `--armor`           | Write or read base64 text instead of a binary file.                    |
| `--stdout`          | Write the result to standard output.                                    |
| `--force`           | Overwrite the output file if it already exists.                        |
| `--text <string>`   | Use this text as the input instead of a file.                          |
| `--passphrase <s>`  | Provide the passphrase directly. Not recommended.                      |
| `-h, --help`        | Show help.                                                              |
| `-v, --version`     | Show the version.                                                       |

## Passphrase

By default sealbox asks for the passphrase and does not show it while you type.

When the input is piped on stdin, the terminal is busy reading that data, so sealbox cannot ask. In that case set the passphrase in an environment variable:

```bash
echo "token" | SEALBOX_PASSPHRASE=your-passphrase sealbox encrypt --armor
```

Avoid `--passphrase` on the command line when you can, because shells often save commands in a history file.

## What the one time mode does and does not protect

The `--burn` option overwrites the encrypted file once with random data and then deletes it. This is useful, but be honest about the limits:

- On solid state drives, copy on write filesystems such as APFS or Btrfs, and on systems with snapshots, an overwrite in place is not guaranteed to hit the original blocks. Older copies can survive.
- If the file was copied, synced to a cloud folder, or backed up before it was opened, those copies are not touched.
- Decrypted output that you write to disk is a normal file. sealbox does not track it.

If you need a stronger guarantee, keep the encrypted file on an encrypted volume, or use full disk encryption, and avoid syncing it.

## Security notes

- AES-256-GCM is authenticated, so tampering is detected and decryption fails with a clear message.
- scrypt with a random salt protects against precomputed and parallel guessing attacks.
- Pick a long passphrase. The strength of the whole thing comes from the passphrase, not the algorithm.
- This project has not had an external audit. Read the code, it is small and in `src/`.

## File format

A sealbox file is a header followed by the ciphertext.

```text
magic        8 bytes   "SEALBOX1"
flags        1 byte    bit 0 = burn after reading
logN         1 byte    scrypt cost, N = 2 ** logN
r            4 bytes   scrypt block size
p            4 bytes   scrypt parallelism
salt        16 bytes
nonce       12 bytes
tag         16 bytes   AES-GCM authentication tag
ciphertext  rest
```

## Development

Run the tests with the built in Node test runner:

```bash
npm test
```

The tests cover the round trip, a wrong passphrase, a changed file, the burn flag, empty input and the armor format.

## Rename

The name `sealbox` is a default. To use your own name, search the project for `sealbox` and `SEALBOX` and replace them. If you change the magic header, old files will no longer be readable, so only do that before you have files you care about.

## Disclaimer

This is a personal, non commercial open source project, made and shared in my
free time. It is not a product or a service, and it comes with no support or
guarantee, even though the contact address uses a domain name.

sealbox is provided as is, without any warranty, and it has not had an external
security audit. You use it at your own risk. You are responsible for choosing a
strong passphrase, for keeping your own backups, and for deciding whether this
tool fits your needs. The author is not liable for lost data or any damage that
results from using it.

This tool is meant for lawful use only, such as protecting your own files and
private information. Do not use it for anything illegal. You are responsible for
following the laws that apply to you, including any local rules about the use of
encryption. See the LICENSE file for the full terms.

## Support

If sealbox is useful to you, you can support the work here:

<a href="https://buymeacoffee.com/vincentborgers">
  <img alt="Buy me a coffee" src="https://img.shields.io/badge/Buy%20me%20a%20coffee-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black">
</a>

## License

MIT, copyright (c) 2026 Vincent Borgers. See [LICENSE](LICENSE).
