# deadcert

![Go Version](https://img.shields.io/badge/go-1.26%2B-blue)
![Release](https://img.shields.io/github/v/release/zuhayrb/deadcert)
![Build](https://github.com/zuhayrb/deadcert/actions/workflows/release.yaml/badge.svg)
![License](https://img.shields.io/github/license/zuhayrb/deadcert)

`deadcert` is a small Go CLI for checking when TLS certificates expire.

It accepts one or more domains, checks them concurrently, and reports whether
each certificate is healthy, expiring soon, already expired, or unreachable.

## Features

- Check one domain or many domains at once
- Read domains from a file
- Configure the warning window with `--warn-days`
- Configure the target port and per-domain timeout
- Emit human-readable output or JSON
- Use process exit codes that work well in scripts and CI
- Avoid external runtime dependencies

## Install

### Pre-built binaries (recommended)

**Linux / macOS / Windows:**

```sh
curl -fsSL https://github.com/zuhayrb/deadcert/releases/latest/download/install.sh | sh
```

This downloads the latest release for your platform, verifies the checksum, and installs to `~/.local/bin`. Make sure `~/.local/bin` is on your `PATH`.

### Go install

```sh
go install github.com/zuhayrb/deadcert@latest
```

### From source

```sh
go build -o deadcert .
./deadcert example.com
```

Or run directly during development:

```sh
go run . example.com
```

## Usage

```sh
deadcert [flags] <domain> [domain ...]
deadcert [flags] --file domains.txt
```

Examples:

```sh
deadcert example.com
deadcert --warn-days 14 example.com api.example.com
deadcert --json --no-color example.com
deadcert --file domains.txt --timeout 5s
deadcert --port 8443 internal.example.com
```

## Flags

| Flag | Default | Description |
| --- | ---: | --- |
| `--warn-days` | `30` | Warn when a certificate expires within this many days. Use `0` to report only already-expired certificates. |
| `--port` | `443` | TCP port to connect to. |
| `--timeout` | `10s` | Per-domain dial and TLS handshake timeout. Uses Go duration syntax such as `5s`, `30s`, or `1m`. |
| `--json` | `false` | Print a JSON array instead of human-readable output. |
| `--no-color` | `false` | Disable ANSI color output. |
| `--verbose` | `false` | Print detail lines for non-OK results in human output. |
| `--file` | empty | Read additional domains from a file, one per line. Blank lines and lines starting with `#` are skipped. |
| `--version` | `false` | Print the current version and exit. |

## Domain Files

Domain files are plain text:

```txt
# production
example.com
api.example.com

# internal service on another port:
internal.example.com
```

Run with:

```sh
deadcert --file domains.txt
```

If all domains in the file use a non-default port, pass it with `--port`:

```sh
deadcert --file domains.txt --port 8443
```

## JSON Output

Use `--json` for automation:

```sh
deadcert --json --no-color example.com
```

Example output:

```json
[
  {
    "domain": "example.com",
    "port": 443,
    "status": "ok",
    "expires_at": "2026-12-01T12:00:00Z",
    "days_left": 172,
    "message": "certificate valid for 172 days (2026-12-01)"
  }
]
```

Possible `status` values are:

- `ok`
- `warning`
- `expired`
- `error`

## Exit Codes

| Code | Meaning |
| ---: | --- |
| `0` | All checked certificates are healthy. |
| `1` | At least one certificate is expired, expiring within `--warn-days`, not yet valid, or unreachable. |
| `2` | Usage error, such as invalid flags, invalid timeout, or no domains. |

## What deadcert Checks

`deadcert` focuses on certificate expiry. It intentionally inspects the server's
leaf certificate and checks its validity dates.

It is not a full TLS audit tool. It does not try to prove CA trust, hostname
validity, cipher strength, revocation status, or general server hardening.

## Development

Run the test suite:

```sh
go test ./...
```

The tests use local TLS servers with generated certificates, so they do not
depend on external network access.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support ☕

If you find deadcert useful, consider supporting development:

- **BTC**: `bc1qarlskqtdq4wsdudecktv6g7zqv5jv52at9k5uk`
- **ETH/ERC-20**: `0x03d42691a1f0d9af62899813e1f3937da0f6039b`
- **SOL/SLP**: `J9jneBCAW8NaoSj5KekxLyxBcYbzNq3F2Wshdar7FHdf`