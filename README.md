# Codex-Auth-Sync

Sync Codex auth token across coding agents (Codex, OpenCode, Pi).

## Supported agents

| Agent  | Auth file       |
| ------ | --------------- |
| Codex  | `~/.codex/auth` |
| OpenCode | `~/.local/share/opencode/auth.json` |
| Pi     | `~/.pi/agent/auth.json` |

## Install

Requires Python 3.14+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/du00q/codex-auth-sync.git
cd codex-auth-sync
uv sync
```

## Usage

```bash
# Sync from Codex to Pi and OpenCode
uv run codex-auth-sync --source codex --targets pi opencode

# Sync from Pi to Codex
uv run codex-auth-sync --source pi --targets codex

# Custom paths
uv run codex-auth-sync --source codex --targets pi \
  --source-path ~/custom/auth.json \
  --target-paths ~/custom/pi.json
```

`--source` and `--targets` accept: `codex`, `pi`, `opencode`.

## Development

```bash
uv run poe format   # ruff format
uv run poe lint     # ruff check --fix
uv run poe check    # ty check --fix
uv run poe test     # pytest tests
```

## License

MIT. See [LICENSE](LICENSE).
