# NXD client 

NXD is an encrypted agent operating system from Nexplora Labs. It lets AI agents
seal, shield, tokenize and hand off sensitive data so plaintext never has to
leave the operator's machine.

This repository contains only the ** thin client** (Apache-2.0):

- `python/nxd/` – the CLI (`cli.py`), MCP server (`mcp_server.py`) and package entry (`__init__.py`)
- `npm/` – the `@nexplora/nxd` launcher for Node

## Install

```bash
npx @nexplora/nxd --help             # Node 18+ and Python 3.10+
npx -p @nexplora/nxd nxd-mcp         # MCP server over stdio

pip install nxd                      # Python 3.10+
nxd --help
```

## The core is closed

The NXD core (cryptography, vault, handoff, audit and so on) is **closed source**.
It ships only as compiled binaries inside the `nxd` wheels on PyPI, under the
Nexplora Labs Proprietary License. The Python files here import that compiled
core and do nothing without it. No core source is published in this repository.

## License

Thin client: Apache-2.0 (see `LICENSE`). Compiled core: proprietary (see `npm/NOTICE`).
