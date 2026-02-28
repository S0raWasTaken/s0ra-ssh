# ssh0

A custom SSH-like protocol in Rust. TLS transport, keypair auth, PTY-backed remote shell.

> Not a replacement for OpenSSH. Personal project.

## Setup

**1. Generate a key pair**
```bash
ssh0-keygen
```
Saves to `~/.config/ssh0/` by default.

**2. Authorize your public key on the server**
```bash
cat ~/.config/ssh0/id_ed25519.pub >> ~/.config/ssh0-daemon/authorized_keys
```

**3. Start the daemon**
```bash
ssh0-daemon              # binds to 127.0.0.1:2121
ssh0-daemon 0.0.0.0      # all interfaces
```
TLS cert is auto-generated on first run.

**4. Connect**
```bash
ssh0 hostname
ssh0 hostname --port 2222
ssh0 hostname -i /path/to/key
```
On first connection you'll be asked to verify the server's TLS fingerprint.

## Known Limitations

- No terminal resize support
- No file transfer or port forwarding
- Removing a key from `authorized_keys` doesn't kill active sessions
