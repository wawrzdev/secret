# secret

`secret` generates random values and stores per-machine credentials as private
files. It keeps values out of command arguments, shell history, generated
documentation, and its own status output.

```console
$ secret generate
$ secret generate hex 31
$ secret generate base64 32
$ secret generate uuid

$ secret set github/token --env GITHUB_TOKEN_FILE
Secret:
stored github/token

$ printf '%s\n' "$TOKEN_FROM_A_SAFE_SOURCE" | secret set api/token --stdin
$ secret import service/account.json ./downloaded-account.json --env SERVICE_ACCOUNT_FILE
$ secret import tls/client.pem --stdin < client.pem
$ secret path service/account.json
$ secret check
$ secret exec api/token API_TOKEN -- command-that-requires-a-value
```

Bare `secret` prints command help. `generate` prints a URL-safe 32-character
value by default. `hex` and `url` lengths count output characters; `base64`
counts input bytes. Generation uses `crypto/rand`. On a local desktop the value
is also copied with `pbcopy`, `wl-copy`, `xclip`, or `xsel` when available.
Clipboard failure is silent and does not fail generation.

## Store

Credentials live below
`${XDG_CONFIG_HOME:-$HOME/.config}/secrets`. The directory is created only by a
write. Directories have mode `0700`; files and `env.zsh` have mode `0600`.
Names may contain nested path components, but absolute paths, empty components,
`.`/`..`, control characters, backslashes, helper-reserved names, the internal
registration marker, and symbolic links are rejected.

`set` reads a non-empty, single-line token. `import` also rejects an empty input
before creating the store or any destination directories. The default `set` prompt reads from the
controlling terminal with echo disabled. `--stdin` requires non-terminal input
and removes one terminating newline. `import` accepts a regular, non-symlink
file or non-terminal stdin and preserves every byte. Both commands refuse an
existing destination unless `--replace` is present.

Writes use a private temporary file in the destination directory. New
directories and their parents are synced as they are created so the complete
path is crash-durable before publication. New secrets
are published with an atomic create-if-absent operation; replacements use an
atomic rename after revalidating the destination. Replacement retains the old
inode until the new directory entry is durably committed; a commit-sync failure
rolls back and re-syncs the old value before reporting an ordinary failure.
Errors explicitly stating that the new value is committed or visible identify
the exceptional case where publication passed the commit point or automatic
rollback itself failed, so callers do not blindly retry. Store traversal uses
directory descriptors and no-follow opens to prevent a link swap from
redirecting a credential write or read.

## Environment paths and child commands

`--env VARIABLE` adds a sorted, idempotent entry to `secrets/env.zsh`. A private
store-local lock serializes registrations across processes, preventing one
successful command from losing another command's entry. Entries export the
credential file's absolute path, never its value. Source the optional file from
shell startup code:

```zsh
[[ ! -r ${XDG_CONFIG_HOME:-$HOME/.config}/secrets/env.zsh ]] ||
  source ${XDG_CONFIG_HOME:-$HOME/.config}/secrets/env.zsh
```

`secret exec NAME VARIABLE -- COMMAND ...` is the narrow escape hatch for an
application that requires a value in its environment. It validates that the
file contains textual data with no NUL byte, adds the value only to the child
environment, uses inherited standard streams, and returns the child's status.
Use `path` or `--env` for JSON, certificates, keys, and binary credentials.

## Validation and recovery

`secret check NAME` verifies one existing regular file. Bare `secret check`
walks the store and verifies directory/file types, `0700`/`0600` permissions,
and every environment registration. Empty credential files and unsafe names are
errors. An absent store is a valid empty state and is not created by the check.
It prints sanitized names and statuses only. It does not read values, change
permissions, replace links, or rewrite registrations.

Repair a bad or stale entry explicitly with `set --replace` or
`import --replace`. Remove an obsolete credential or registration with ordinary
local file editing after reviewing the target. Backups and credential rotation
remain the responsibility of the system that owns each credential.

## Development

The runtime dependencies are the audited Go `x/sys` package for descriptor-safe
filesystem calls and locking, and `x/term` for hidden terminal input. The test
suite uses `creack/pty` to verify terminal echo suppression and restoration.
There are no external cryptographic runtime dependencies.

```console
go test ./...
go test -race ./...
go vet ./...
goreleaser release --snapshot --clean
```

CI tests macOS and Linux without publishing. `.goreleaser.yaml` builds static
macOS/Linux archives and describes Debian and Arch packages for the separate
distribution repository.
