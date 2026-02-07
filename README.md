# enn

Encrypt notes with AES-256-GCM.

Own your notes. Backup them with git where ever you want.

## Details

- Simple codebase and to use
- Single password
- Only markdown `.md` files
- No sub-directories
- git based backup


## Install

See [Release](github.com/wizsk/mujamalat/releases/latest) for binaries or

```sh
go install -ldflags "-s -w" github.com/wizsk/enn@latest
```

## Usages

- After installation run `enn` to setup notes directory and passkey.
- If you have old notes run `enn --dec-all` to decrypt them.
- Run `enn --check-dec` if you want to decrypt specific notes.
- After changing notes, run `enn` to encrypt notes, or `enn --ep` to encrypt and push.
- Or run `enn --push` separately.
- Run `enn --pull`, to pull, then it will ask you if you want to decrypt the changed notes.
- Run `enn --help` to see all the flags

## Multi device sync

After pushing form one device use `enn --pull` for pulling. It will ask you
if you want to decrypt the new files or not.

## Code structure

Code is kept simple as possible for audit.

```
├── main.go
├── conf.go     # handle config files
├── datas.go    # used for defining data types
├── enc.go      # encryption logic
├── enc_utils.go
├── flag.go
├── git.go
├── health.go
├── pass.go
├── manifest.go
└── utils.go
```
