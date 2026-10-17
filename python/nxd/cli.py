from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, TextIO

from nxd._crypto import write_private_bytes
from nxd._crypto import OPERATOR_PASSPHRASE_ENV, OperatorKeyError, _validate_passphrase

IGNORE_LINES = [
    "*.nxd",
    "master.key",
    "vault/",
    ".nxd_vault/",
    "nxd_audit.log",
    "*.key",
    "*.pem",
    "dist/",
    "build/",
    "*.egg-info/",
    "__pycache__/",
    ".env",
]

CLAUDE_BLOCK = (
    "## NXD Protection\n"
    "Run nxd open, then python3 nx_protect.py at session start.\n"
    "\n"
)

README_BLOCK = (
    "## NXD\n\n"
    "[![Protected with NXD](https://img.shields.io/badge/protected%20with-NXD-0a7f5a)]"
    "(https://nexplora.ai)\n\n"
    "This project was initialized with NXD.\n\n"
    "```bash\n"
    "pipx install nxd  # CLI\n"
    "pip install nxd   # library\n"
    "nxd init-operator\n"
    "nxd open\n"
    "nxd init\n"
    "python3 nx_protect.py\n"
    "```\n"
)

GROUP_PREFIXES = {
    "EXCHANGE": ("COINBASE_", "KALSHI_", "POLY_", "SOLANA_", "TASTYTRADE_"),
    "DATABASE": ("SUPABASE_",),
    "AI": ("ANTHROPIC_", "OPENAI_"),
    "COMMS": ("TELEGRAM_",),
}


def parse_env_names(env_path: Path) -> list[str]:
    names: list[str] = []
    if not env_path.exists():
        return names
    for raw_line in env_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        name = line.split("=", 1)[0].strip()
        if name:
            names.append(name)
    return names


def detect_project(project_dir: Path) -> dict[str, object]:
    env_names = parse_env_names(project_dir / ".env")
    has_pyproject = (project_dir / "pyproject.toml").exists()
    has_package_json = (project_dir / "package.json").exists()
    if has_pyproject and has_package_json:
        project_kind = "Python and Node project"
    elif has_pyproject:
        project_kind = "Python project"
    elif has_package_json:
        project_kind = "Node project"
    else:
        project_kind = "Generic project"
    return {
        "project_kind": project_kind,
        "claude": (project_dir / "CLAUDE.md").exists(),
        "cursor": (project_dir / ".cursorrules").exists(),
        "readme": (project_dir / "README.md").exists(),
        "gitignore": (project_dir / ".gitignore").exists(),
        "env_count": len(env_names),
        "env_names": env_names,
    }


def categorize_env_names(env_names: list[str]) -> dict[str, list[str]]:
    groups = {name: [] for name in ("EXCHANGE", "DATABASE", "AI", "COMMS", "DATA")}
    for env_name in env_names:
        placed = False
        for group_name, prefixes in GROUP_PREFIXES.items():
            if env_name.startswith(prefixes):
                groups[group_name].append(env_name)
                placed = True
                break
        if not placed:
            groups["DATA"].append(env_name)
    return groups


def format_found(report: dict[str, object]) -> str:
    found: list[str] = []
    env_count = int(report["env_count"])
    if env_count:
        found.append(f".env ({env_count} variables)")
    if report["claude"]:
        found.append("CLAUDE.md")
    if report["cursor"]:
        found.append(".cursorrules")
    if report["readme"]:
        found.append("README.md")
    if report["gitignore"]:
        found.append(".gitignore")
    return ", ".join(found) if found else "No project files detected"


def prompt_yes_no(prompt: str, input_fn: Callable[[], str], out: TextIO) -> bool:
    while True:
        out.write(f"{prompt} (y/n)\n")
        out.flush()
        answer = input_fn().strip().lower()
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        out.write("Please answer y or n.\n")
        out.flush()


def _writeln(out: TextIO, text: str = "") -> None:
    out.write(text + "\n")
    out.flush()


def _clear_screen(out: TextIO | None = None) -> None:
    target = out or sys.stdout
    target.write("\033[2J\033[H")
    target.flush()


def _zero_text(value: str | None) -> None:
    if not value:
        return
    try:
        buf = bytearray(value.encode())
        for index in range(len(buf)):
            buf[index] = 0
        del buf
    except Exception:
        pass


def append_unique_lines(path: Path, lines: list[str]) -> bool:
    existing_lines: list[str] = []
    if path.exists():
        existing_lines = path.read_text().splitlines()
    changed = False
    merged = list(existing_lines)
    existing_set = set(existing_lines)
    for line in lines:
        if line not in existing_set:
            merged.append(line)
            existing_set.add(line)
            changed = True
    if changed or not path.exists():
        body = "\n".join(merged).rstrip("\n")
        path.write_text(body + "\n")
    return changed


_LEGACY_CLAIM = "Credentials exposed to AI: 0\n"


def prepend_block(path: Path, block: str) -> bool:
    if path.exists():
        existing = path.read_text()
        legacy = block.rstrip("\n") + "\n" + _LEGACY_CLAIM
        if legacy in existing:  # remove the unverifiable claim written by older nxd init
            path.write_text(existing.replace(legacy, block.rstrip("\n") + "\n", 1))
            return True
        if existing.startswith(block) or block.strip() in existing:
            return False
        path.write_text(block + existing)
        return True
    path.write_text(block)
    return True


def append_block(path: Path, block: str) -> bool:
    if path.exists():
        existing = path.read_text()
        if block.strip() in existing:
            return False
        separator = "\n\n" if existing.strip() else ""
        path.write_text(existing.rstrip("\n") + separator + block)
        return True
    path.write_text(block)
    return True


def render_nx_protect(env_names: list[str]) -> str:
    categories = categorize_env_names(env_names)
    group_lines = []
    for name in ("EXCHANGE", "DATABASE", "AI", "COMMS", "DATA"):
        rendered = ", ".join(f'"{value}"' for value in categories[name])
        group_lines.append(f"{name} = [{rendered}]")
    groups_block = "\n".join(group_lines)
    return (
        "#!/usr/bin/env python3\n"
        '"""Project-local NXD bootstrap generated by `nxd init`.\"\"\"\n\n'
        "from __future__ import annotations\n\n"
        "# First use after install:\n"
        "#   nxd init-operator\n"
        "#   nxd open\n"
        "# Then run: python3 nx_protect.py\n"
        "# Legacy fallback: set NXD_OPERATOR_PASSPHRASE in your shell\n"
        "# WARNING: vault.use callbacks must not return credential values\n\n"
        "import os\n"
        "import sys\n"
        "from pathlib import Path\n\n"
        "from nxd._crypto import OPERATOR_PASSPHRASE_ENV, OperatorKeyError\n"
        "from nxd.vault import Vault\n\n"
        f"{groups_block}\n\n"
        "ENV_FILE = Path('.env')\n"
        "VAULT_DIR = Path('.nxd_vault')\n\n"
        "def load_env(path: Path) -> dict[str, str]:\n"
        "    data: dict[str, str] = {}\n"
        "    if not path.exists():\n"
        "        return data\n"
        "    for raw_line in path.read_text().splitlines():\n"
        "        line = raw_line.strip()\n"
        "        if not line or line.startswith('#'):\n"
        "            continue\n"
        "        if line.startswith('export '):\n"
        "            line = line[len('export '):].strip()\n"
        "        if '=' not in line:\n"
        "            continue\n"
        "        name, value = line.split('=', 1)\n"
        "        data[name.strip()] = value.strip()\n"
        "    return data\n\n"
        "def main() -> None:\n"
        "    try:\n"
        "        env = load_env(ENV_FILE)\n"
        "        vault = Vault(vault_dir=VAULT_DIR, agent_id='nxd-init')\n"
        "        protected = 0\n"
        "        for name in EXCHANGE + DATABASE + AI + COMMS + DATA:\n"
        "            if name in env:\n"
        "                vault.store(name, env[name])\n"
        "                protected += 1\n"
        "        print('NXD protection active.')\n"
        "        print(f'Protected credentials: {protected}')\n"
        "        print(f'Vault path: {VAULT_DIR}')\n"
        "    except (OperatorKeyError, RuntimeError) as exc:\n"
        "        print(str(exc))\n"
        "        raise SystemExit(1) from exc\n\n"
        "if __name__ == '__main__':\n"
        "    main()\n"
    )


def write_nx_protect(path: Path, env_names: list[str]) -> bool:
    path.write_text(render_nx_protect(env_names))
    return True


_VALID_ENV_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def _prompt_operator_passphrase(out: TextIO) -> str | None:
    existing = os.environ.get(OPERATOR_PASSPHRASE_ENV)
    if existing:
        return existing
    while True:
        value = getpass.getpass("Enter a passphrase to protect your vault (min 12 chars): ")
        if not value:
            out.write("Skipping .env migration - no passphrase provided.\n")
            out.flush()
            return None
        ok, reason = _validate_passphrase(value)
        if not ok:
            out.write(reason + ".\n")
            out.flush()
            continue
        os.environ[OPERATOR_PASSPHRASE_ENV] = value
        return value


def _analyze_env_migration(original: str) -> tuple[list[str], dict[str, str], list[str], int]:
    updated_lines: list[str] = []
    valid_entries: dict[str, str] = {}
    messages: list[str] = []
    skipped = 0

    for raw_line in original.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            updated_lines.append(raw_line)
            continue

        prefix = ""
        line = raw_line
        if stripped.startswith("export "):
            prefix = "export "
            line = raw_line[raw_line.index("export ") + len("export ") :]

        name, value = line.split("=", 1)
        key = name.strip()
        cleaned_value = value.strip()

        if cleaned_value == "":
            messages.append(f"  Skipping {key} - no value")
            updated_lines.append(raw_line)
            skipped += 1
            continue
        if " " in key:
            messages.append(f"  Skipping '{key}' - invalid key name")
            updated_lines.append(raw_line)
            skipped += 1
            continue
        if not _VALID_ENV_KEY_RE.match(key):
            if key and key[0].isdigit():
                messages.append(f"  Skipping '{key}' - key must start with a letter")
            else:
                messages.append(f"  Skipping '{key}' - invalid key name")
            updated_lines.append(raw_line)
            skipped += 1
            continue

        valid_entries[key] = cleaned_value
        updated_lines.append(f"{prefix}{key}=NXD_VAULT::{key}")

    return updated_lines, valid_entries, messages, skipped


def migrate_env_to_vault_refs(project_dir: Path, out: TextIO | None = None) -> dict[str, int]:
    from nxd._crypto import chmod_private, load_fernet
    from nxd.vault import Vault

    out = out or sys.stdout
    env_path = project_dir / ".env"
    if not env_path.exists():
        return {"migrated": 0, "skipped": 0}

    original = env_path.read_text()
    updated_lines, values, messages, skipped = _analyze_env_migration(original)
    for message in messages:
        out.write(message + "\n")

    if not values:
        out.write("  Migrated: 0 credentials\n")
        out.write(f"  Skipped:  {skipped} (empty or invalid)\n")
        out.flush()
        return {"migrated": 0, "skipped": skipped}

    vault_path = project_dir / ".nxd_vault"
    backup_path = project_dir / ".env.backup.nxd"
    stage_dir = Path(tempfile.mkdtemp(prefix="nxd-vault-stage-", dir=project_dir))
    stage_vault = stage_dir / ".nxd_vault"
    stage_backup = stage_dir / ".env.backup.nxd"
    stage_env = stage_dir / ".env"

    try:
        if vault_path.exists():
            shutil.copytree(vault_path, stage_vault, dirs_exist_ok=True)
        vault = Vault(vault_dir=stage_vault, agent_id="nxd-init")
        for name, value in values.items():
            vault.store(name, value)

        write_private_bytes(stage_backup, load_fernet(stage_vault / "master.key").encrypt(original.encode()))
        stage_env.write_text("\n".join(updated_lines) + "\n")

        if vault_path.exists():
            shutil.rmtree(vault_path)
        shutil.move(str(stage_vault), str(vault_path))
        shutil.move(str(stage_backup), str(backup_path))
        shutil.move(str(stage_env), str(env_path))
    except Exception:
        shutil.rmtree(stage_dir, ignore_errors=True)
        raise

    shutil.rmtree(stage_dir, ignore_errors=True)
    out.write(f"  Migrated: {len(values)} credentials\n")
    out.write(f"  Skipped:  {skipped} (empty or invalid)\n")
    out.flush()
    return {"migrated": len(values), "skipped": skipped}


def load_env_file(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.exists():
        return data
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        data[name.strip()] = value.strip()
    return data


def _read_tty_secret(prompt: str) -> str:
    """Read from the controlling terminal only; refuse piped/non-interactive input."""
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        raise PermissionError("nxd reveal must be run by the operator in an interactive terminal")
    return getpass.getpass(prompt)


def run_reveal(
    reveal_id: str,
    out: TextIO | None = None,
    getpass_fn: Callable[[str], str] | None = None,
) -> int:
    from nxd.operator import reveal, validate_reveal_id

    out = out or sys.stdout
    try:
        validate_reveal_id(reveal_id)
        from nxd.keyd import socket_path

        if socket_path():  # nxd-keyd prompts on its own terminal; the phrase never enters this process
            payload = reveal(reveal_id)
        else:
            words = (getpass_fn or _read_tty_secret)("Operator re-authentication. 24-word key (invisible): ")
            payload = reveal(reveal_id, recovery_phrase=words)
    except (ValueError, PermissionError, FileNotFoundError, RuntimeError) as exc:
        print(f"nxd reveal: {exc}", file=sys.stderr)
        return 1
    out.write(json.dumps(payload, indent=2) + "\n")
    out.flush()
    return 0


def run_audit_recover(out: TextIO | None = None) -> int:
    from nxd import audit

    out = out or sys.stdout
    out.write("NXD Audit Recovery\n")
    out.write("Rebuilding audit manifest from existing log...\n")
    result = audit.recover()
    out.write(f"Status: {result['status']}\n")
    out.write(f"Entries recovered: {result['entries_recovered']}\n")
    out.write(f"Chain intact: {result.get('chain_intact', 'N/A')}\n")
    if "reason" in result:
        out.write(result["reason"] + "\n")
    else:
        out.write(result["message"] + "\n")
    out.flush()
    return 0 if result["status"] == "ok" else 1


def run_audit_reset(
    input_fn: Callable[[str], str] | None = None,
    out: TextIO | None = None,
) -> int:
    from nxd import audit

    input_fn = input_fn or input
    out = out or sys.stdout
    _writeln(out, "NXD Audit Reset")
    _writeln(out, "This clears the local audit log and manifest.")
    if input_fn("Type yes to continue: ").strip().lower() != "yes":
        _writeln(out, "Audit reset cancelled.")
        return 1
    audit.reset()
    _writeln(out, "Audit log reset.")
    return 0


def run_vault_setup(out: TextIO | None = None) -> int:
    from nxd.hosted import HostedVault

    out = out or sys.stdout
    addr = os.environ.get("VAULT_ADDR")
    token = os.environ.get("VAULT_TOKEN")
    if not addr or not token:
        out.write("VAULT_ADDR and VAULT_TOKEN must be set.\n")
        out.flush()
        return 1

    vault = HostedVault(agent_id="nxd-hosted-check", vault_addr=addr, vault_token=token)
    out.write(f"Hosted vault connected at {vault._addr}\n")
    out.write("Keys will never touch local disk\n")
    out.write("Next: nxd init --hosted to use it\n")
    out.flush()
    return 0


def run_init_operator(
    input_fn: Callable[[str], str] | None = None,
    getpass_fn: Callable[[str], str] | None = None,
    out: TextIO | None = None,
) -> int:
    from nxd import audit
    from nxd.operator_key import init_operator, is_initialized

    input_fn = input_fn or input
    getpass_fn = getpass_fn or getpass.getpass
    out = out or sys.stdout

    if is_initialized():
        _writeln(out, "ERROR: Operator key already exists.")
        _writeln(out, "Your vault is already protected.")
        _writeln(out, "If you lost your key: nxd recover-operator")
        return 1

    _writeln(out)
    _writeln(out, "╔══════════════════════════════════════════════╗")
    _writeln(out, "║     NXD OPERATOR KEY INITIALIZATION         ║")
    _writeln(out, "╠══════════════════════════════════════════════╣")
    _writeln(out, "║ NXD will generate your 24-word operator key.║")
    _writeln(out, "║ It will be shown once, then cleared.        ║")
    _writeln(out, "║ Write it down. There is no backdoor.        ║")
    _writeln(out, "╚══════════════════════════════════════════════╝")
    _writeln(out)

    if input_fn("Are you ready to generate your operator key? (yes/no): ").strip().lower() != "yes":
        _writeln(out, "Initialization cancelled.")
        return 1

    mnemonic = init_operator()
    audit.reset()
    words = mnemonic.split()

    _writeln(out)
    _writeln(out, "╔══════════════════════════════════════════════╗")
    _writeln(out, "║          YOUR 24-WORD OPERATOR KEY          ║")
    _writeln(out, "╠══════════════════════════════════════════════╣")
    for start in range(0, len(words), 2):
        left = f"{start + 1:2}. {words[start]}"
        right = ""
        if start + 1 < len(words):
            right = f"{start + 2:2}. {words[start + 1]}"
        _writeln(out, f"║ {left:<20}{right:<24}║")
    _writeln(out, "╠══════════════════════════════════════════════╣")
    _writeln(out, "║ THIS IS THE ONLY TIME THESE WORDS APPEAR.   ║")
    _writeln(out, "╚══════════════════════════════════════════════╝")
    _writeln(out)

    input_fn("I have written down all 24 words. Press ENTER to continue...")
    _clear_screen(out)
    _writeln(out, "Confirm your operator key to verify you recorded it correctly.")
    _writeln(out, "As you type, nothing will appear. This is correct.")
    _writeln(out)
    entered = ""
    try:
        entered = getpass_fn("Enter your 24 words (invisible): ")
    except (KeyboardInterrupt, EOFError):
        _zero_text(mnemonic)
        _writeln(out, "\nCancelled. Your key was generated but not confirmed.")
        return 1

    match = entered.strip().lower() == mnemonic.strip().lower()
    _zero_text(entered)
    _zero_text(mnemonic)
    _clear_screen(out)

    if match:
        _writeln(out)
        _writeln(out, "╔══════════════════════════════════════════════╗")
        _writeln(out, "║  Operator key confirmed and initialized.    ║")
        _writeln(out, "║  The key has been cleared from this screen. ║")
        _writeln(out, "║  To open your vault: nxd open               ║")
        _writeln(out, "╚══════════════════════════════════════════════╝")
        _writeln(out, "Audit log reset. New chain starts now.")
        return 0

    _writeln(out)
    _writeln(out, "╔══════════════════════════════════════════════╗")
    _writeln(out, "║  Words did not match.                       ║")
    _writeln(out, "║  Your key WAS generated and saved.          ║")
    _writeln(out, "║  Verify your written copy, then run nxd open║")
    _writeln(out, "╚══════════════════════════════════════════════╝")
    return 1


def run_open(out: TextIO | None = None) -> int:
    from nxd.operator_key import is_initialized, is_locked, open_vault

    out = out or sys.stdout
    if not is_initialized():
        _writeln(out, "Operator key not initialized.")
        _writeln(out, "Run: nxd init-operator")
        _writeln(out, "Or:  nxd recover-operator")
        return 1
    if not is_locked():
        _writeln(out, "Vault already open.")
        _writeln(out, "Run: nxd status to see time remaining.")
        _writeln(out, "Run: nxd lock to close immediately.")
        return 0

    _writeln(out)
    _writeln(out, "Opening NXD vault...")
    _writeln(out, "Your device may prompt for your password or Touch ID.")
    _writeln(out)
    try:
        open_vault()
    except RuntimeError as exc:
        _writeln(out, f"ERROR: {exc}")
        return 1

    _writeln(out, "╔══════════════════════════════════════════════╗")
    _writeln(out, "║  Vault open. Session active for 8 hours.    ║")
    _writeln(out, "║  Run: nxd lock to close immediately.        ║")
    _writeln(out, "╚══════════════════════════════════════════════╝")
    _writeln(out)
    return 0


def run_lock(out: TextIO | None = None) -> int:
    from nxd.operator_key import lock

    out = out or sys.stdout
    lock()
    _writeln(out, "Vault locked.")
    return 0


def run_migrate_vault(vault_dir: str | None = None, out: TextIO | None = None) -> int:
    from nxd.vault import migrate_legacy_store

    out = out or sys.stdout
    count = migrate_legacy_store(vault_dir)
    _writeln(out, f"Migrated {count} legacy entries." if count else "Nothing to migrate.")
    return 0


def run_recover_operator(
    getpass_fn: Callable[[str], str] | None = None,
    out: TextIO | None = None,
) -> int:
    from nxd.operator_key import recover_operator

    getpass_fn = getpass_fn or getpass.getpass
    out = out or sys.stdout

    _writeln(out)
    _writeln(out, "╔══════════════════════════════════════════════╗")
    _writeln(out, "║            NXD VAULT RECOVERY               ║")
    _writeln(out, "║ Enter your 24-word operator key.            ║")
    _writeln(out, "║ Nothing will appear as you type.            ║")
    _writeln(out, "╚══════════════════════════════════════════════╝")
    _writeln(out)

    mnemonic = ""
    try:
        mnemonic = getpass_fn("24-word key (invisible): ")
        recover_operator(mnemonic.strip().lower())
    except (KeyboardInterrupt, EOFError):
        _writeln(out, "\nCancelled.")
        return 1
    except RuntimeError as exc:
        _zero_text(mnemonic)
        _writeln(out, f"\n{exc}\n")
        return 1

    _zero_text(mnemonic)
    _writeln(out)
    _writeln(out, "╔══════════════════════════════════════════════╗")
    _writeln(out, "║  Recovery complete.                         ║")
    _writeln(out, "║  Vault key restored to device keychain.     ║")
    _writeln(out, "║  Run: nxd open                              ║")
    _writeln(out, "╚══════════════════════════════════════════════╝")
    _writeln(out)
    return 0


def run_status(out: TextIO | None = None) -> int:
    from nxd.operator_key import (
        KEYCHAIN_META_ENTRY,
        _keyring,
        _session_path,
        is_initialized,
        is_locked,
        keychain_service,
    )

    out = out or sys.stdout
    _writeln(out)
    _writeln(out, "NXD Status")
    _writeln(out, "──────────")

    if not is_initialized():
        _writeln(out, "Operator key: NOT SET UP")
        _writeln(out, "Run: nxd init-operator")
        return 0

    _writeln(out, "Operator key: initialized")
    _writeln(out, "Storage:      OS keychain")

    try:
        meta_raw = _keyring().get_password(keychain_service(), KEYCHAIN_META_ENTRY)
        meta = json.loads(meta_raw) if meta_raw else {}
        _writeln(out, f"Created:      {meta.get('created_at', 'unknown')}")
        _writeln(out, f"Last opened:  {meta.get('last_opened', 'never')}")
    except Exception:
        pass

    if is_locked():
        _writeln(out, "Vault:        LOCKED")
        _writeln(out, "Run: nxd open")
        return 0

    try:
        data = json.loads(_session_path().read_text())
        remaining = max(0, int(float(data.get("expires", 0)) - time.time()))
        hours, minutes = divmod(remaining // 60, 60)
        _writeln(out, "Vault:        OPEN")
        _writeln(out, f"Session:      {hours}h {minutes}m remaining")
    except Exception:
        _writeln(out, "Vault:        LOCKED")
    return 0


def run_init(
    project_dir: Path,
    input_fn: Callable[[], str] | None = None,
    out: TextIO | None = None,
    hosted: bool = False,
) -> int:
    input_fn = input_fn or (lambda: input())
    out = out or sys.stdout
    report = detect_project(project_dir)
    out.write("NXD Init - Nexplora Labs\n")
    out.write(f"Detected: {report['project_kind']}\n")
    out.write(f"Found: {format_found(report)}\n")
    if report["claude"]:
        out.write("Detected: Claude Code project\n")
    if report["cursor"]:
        out.write("Detected: Cursor project\n")
    out.flush()

    actions = {
        ".gitignore": "skipped",
        "CLAUDE.md": "skipped",
        "nx_protect.py": "skipped",
        "README.md": "skipped",
    }

    if prompt_yes_no("Add vault files to .gitignore?", input_fn, out):
        changed = append_unique_lines(project_dir / ".gitignore", IGNORE_LINES)
        actions[".gitignore"] = "updated" if changed or not report["gitignore"] else "updated"
    if prompt_yes_no("Add NXD protection to CLAUDE.md?", input_fn, out):
        changed = prepend_block(project_dir / "CLAUDE.md", CLAUDE_BLOCK)
        actions["CLAUDE.md"] = "updated" if changed or report["claude"] else "updated"
    if prompt_yes_no("Generate nx_protect.py for this project?", input_fn, out):
        write_nx_protect(project_dir / "nx_protect.py", list(report["env_names"]))
        actions["nx_protect.py"] = "created"
    if prompt_yes_no("Add NXD badge and usage to README.md?", input_fn, out):
        changed = append_block(project_dir / "README.md", README_BLOCK)
        actions["README.md"] = "updated" if changed or report["readme"] else "updated"
    if report["env_count"] and prompt_yes_no(
        "Migrate plaintext .env values into vault references with encrypted backup?",
        input_fn,
        out,
    ):
        if _prompt_operator_passphrase(out) is not None:
            migrate_env_to_vault_refs(project_dir, out=out)

    out.write("NXD initialized.\n")
    out.write(f"Credentials detected: {report['env_count']}\n")
    out.write(f".gitignore: {actions['.gitignore']}\n")
    out.write(f"CLAUDE.md: {actions['CLAUDE.md']}\n")
    out.write(f"nx_protect.py: {actions['nx_protect.py']}\n")
    out.write(f"README.md: {actions['README.md']}\n\n")
    if hosted:
        out.write("Hosted mode selected. Configure VAULT_ADDR and VAULT_TOKEN before running nx_protect.py.\n")
    out.write("Next: nxd open\n")
    out.write("Then: python3 nx_protect.py\n")
    out.write("Docs: https://nexplora.ai\n")
    out.flush()
    return 0


def _package_version() -> str:
    try:
        from importlib.metadata import version

        return version("nxd")
    except Exception:
        return "unknown"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nxd",
        description="NXD operator vault and project bootstrap",
        epilog="First use after install: nxd init-operator",
    )
    parser.add_argument("--version", action="version", version=f"nxd {_package_version()}")
    subparsers = parser.add_subparsers(dest="command")
    init_parser = subparsers.add_parser("init", help="Initialize NXD in the current project")
    init_parser.add_argument("--hosted", action="store_true", help="Generate project setup for HashiCorp Vault backed key custody")
    subparsers.add_parser("init-operator", help="Generate and store the operator key in the OS keychain")
    subparsers.add_parser("open", help="Open the NXD vault using the OS keychain")
    subparsers.add_parser("lock", help="Lock the NXD vault immediately")
    subparsers.add_parser("status", help="Show NXD vault status")
    subparsers.add_parser("recover-operator", help="Restore the operator key from the recorded 24 words")
    reveal_parser = subparsers.add_parser("reveal", help="Reveal operator-only plaintext from a queued NXD action")
    reveal_parser.add_argument("reveal_id")
    keyd_parser = subparsers.add_parser("keyd", help="Reveal-key service (run as the dedicated nxd-keyd user)")
    keyd_parser.add_argument("keyd_args", nargs=argparse.REMAINDER)
    subparsers.add_parser("audit-recover", help="Rebuild the audit manifest from the current audit log")
    subparsers.add_parser("audit-reset", help="Reset the local audit log and manifest after confirmation")
    migrate_parser = subparsers.add_parser("migrate-vault", help="Convert a legacy plaintext vault store to the encrypted format")
    migrate_parser.add_argument("--vault-dir", default=None)
    serve_parser = subparsers.add_parser("serve", help="Run the private NXD HTTP service")
    serve_parser.add_argument("--allow-remote", action="store_true", help="Allow non-loopback binding; requires a TLS proxy in front")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8787)
    subparsers.add_parser("vault-setup", help="Verify HashiCorp Vault connectivity for hosted mode")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "serve":
        from nxd.server import serve
        try:
            return serve(args.host, args.port, allow_remote=True) if args.allow_remote else serve(args.host, args.port)
        except RuntimeError:
            print("NXD service configuration unavailable", file=sys.stderr)
            return 1
    if args.command == "init-operator":
        return run_init_operator()
    if args.command == "open":
        return run_open()
    if args.command == "lock":
        return run_lock()
    if args.command == "status":
        return run_status()
    if args.command == "recover-operator":
        return run_recover_operator()
    if args.command == "init":
        return run_init(Path.cwd(), hosted=getattr(args, "hosted", False))
    if args.command == "keyd":
        from nxd.keyd import main as keyd_main

        return keyd_main(args.keyd_args)
    if args.command == "reveal":
        return run_reveal(args.reveal_id)
    if args.command == "audit-recover":
        return run_audit_recover()
    if args.command == "audit-reset":
        return run_audit_reset()
    if args.command == "migrate-vault":
        return run_migrate_vault(args.vault_dir)
    if args.command == "vault-setup":
        return run_vault_setup()
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
