# enn

Encrypt notes with AES.

## Why make it?

**TLDR:**

- Simple codebase and to use
- Single password
- git based backup

It's designed to be simple. It's core goal is to have a single
directory and have all the notes in `.md` format, no sub-directories.

The directory containing notes does not have any subr-direcitories. It looks for
markdown `.md` files in the directory.


Git is primarily used to backup encrypted `.enc` files. There are flags build
in, `--push` and `--pull` from the remote repo. If file was changed in the remote
(most likely) from another device then it will ask if you want to decrypt them.


## Install

```sh
go install -ldflags "-s -w" github.com/wizsk/enn@latest
```
