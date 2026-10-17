# nxd (npm launcher)

```bash
npx @nexplora/nxd --help
npx -p @nexplora/nxd nxd-mcp        # MCP server over stdio
```

**Requires Python 3.10 or newer on your PATH.** This package contains no
encryption code. On first run it creates a private virtualenv in your user
cache (`~/.cache/nxd-npm/<version>`, or `%LOCALAPPDATA%\nxd-npm` on Windows),
installs the matching `nxd` wheel from PyPI, and runs it. After that first
install everything runs locally and offline.

Environment overrides: `NXD_PYTHON` (interpreter), `NXD_NPM_HOME` (cache dir),
`NXD_PIP_SPEC` (install a local wheel path instead of PyPI).

MCP config: `{ "mcpServers": { "nxd": { "command": "npx", "args": ["-y", "-p", "nxd", "nxd-mcp"] } } }`

License: this launcher is Apache-2.0. The `nxd` Python package it installs
contains a compiled core under the Nexplora Labs Proprietary License (see its
`LICENSE-CORE`).

First run needs network access and installs numpy, pandas, scikit-learn,
cryptography and mcp; pre-warm it with `npx @nexplora/nxd --help` before adding it to an
MCP client so the client's startup timeout isn't hit.
