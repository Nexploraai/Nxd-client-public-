"use strict";
// Thin launcher: keeps a private venv with the matching `nxd` PyPI version, then runs it.
const { spawn, spawnSync } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const VERSION = require("../package.json").version;
const isWin = process.platform === "win32";
const die = (msg) => { process.stderr.write(`nxd: ${msg}\n`); process.exit(1); };

function isExec(p) {
  try {
    if (!fs.statSync(p).isFile()) return false;
    if (!isWin) fs.accessSync(p, fs.constants.X_OK);
    return true;
  } catch (_) { return false; }
}

function resolveOnPath(cmd) {
  // Never resolve from the current directory or any relative PATH entry.
  if (path.isAbsolute(cmd)) return isExec(cmd) ? cmd : null;
  let cwd; try { cwd = fs.realpathSync(process.cwd()); } catch (_) { cwd = path.resolve(process.cwd()); }
  const exts = isWin ? [".exe"] : [""];
  for (const dir of (process.env.PATH || "").split(path.delimiter)) {
    if (!dir || !path.isAbsolute(dir)) continue;
    let real; try { real = fs.realpathSync(dir); } catch (_) { continue; }
    if (real === cwd || real.startsWith(cwd + path.sep)) continue;
    for (const ext of exts) {
      const p = path.join(dir, cmd + ext);
      if (isExec(p)) return p;
    }
  }
  return null;
}

function findPython() {
  const names = process.env.NXD_PYTHON ? [process.env.NXD_PYTHON]
    : isWin ? ["py", "python", "python3"] : ["python3", "python"];
  for (const n of names) {
    const cmd = resolveOnPath(n);
    if (!cmd) continue;
    const pre = /^py(\.exe)?$/i.test(path.basename(cmd)) ? ["-3"] : [];
    const r = spawnSync(cmd, pre.concat(["-I", "-c", "import sys;print('%d.%d'%sys.version_info[:2])"]), { encoding: "utf8" });
    if (r.status === 0) {
      const [maj, min] = r.stdout.trim().split(".").map(Number);
      if (maj === 3 && min >= 10) return { cmd, pre };
    }
  }
  return null;
}

function cacheRoot() {
  return process.env.NXD_NPM_HOME
    || (isWin ? path.join(process.env.LOCALAPPDATA || os.homedir(), "nxd-npm")
              : path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), ".cache"), "nxd-npm"));
}

function checkPrivate(dir) {
  // Run on EVERY start. POSIX: must be a real dir owned by us, not group/world writable.
  if (isWin) return; // Windows: per-user %LOCALAPPDATA% ACLs; no extra check (documented)
  const st = fs.lstatSync(dir);
  if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid() || (st.mode & 0o022)) {
    die(`refusing to use ${dir}: not a private directory owned by you`);
  }
}

function sleep(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }

function withLock(root, fn) {
  const lock = path.join(root, `.lock-${VERSION}`);
  const deadline = Date.now() + 10 * 60 * 1000;
  for (;;) {
    try { fs.mkdirSync(lock); break; } catch (e) {
      if (e.code !== "EEXIST") throw e;
      try { if (Date.now() - fs.statSync(lock).mtimeMs > 15 * 60 * 1000) { fs.rmdirSync(lock); continue; } } catch (_) {}
      if (Date.now() > deadline) die(`timed out waiting for install lock ${lock}`);
      sleep(500);
    }
  }
  try { return fn(); } finally { try { fs.rmdirSync(lock); } catch (_) {} }
}

function install(py, root, venv) {
  const tmp = fs.mkdtempSync(path.join(root, `.tmp-${VERSION}-`));
  const tbin = path.join(tmp, isWin ? "Scripts" : "bin");
  const io = { stdio: ["ignore", 2, 2] };
  process.stderr.write("nxd: first run, installing the nxd Python package (one time)...\n");
  let r = spawnSync(py.cmd, py.pre.concat(["-I", "-m", "venv", tmp]), io);
  if (r.status === 0) {
    const spec = process.env.NXD_PIP_SPEC || `nxd==${VERSION}`;
    r = spawnSync(path.join(tbin, isWin ? "python.exe" : "python"),
      ["-I", "-m", "pip", "install", "--disable-pip-version-check", "-q", "--only-binary=nxd", spec], io);
  }
  if (r.status !== 0) {
    fs.rmSync(tmp, { recursive: true, force: true });
    die("failed to install the nxd Python package (needs a published wheel for your platform and Python)");
  }
  fs.writeFileSync(path.join(tmp, ".nxd-ok"), VERSION);
  fs.rmSync(venv, { recursive: true, force: true }); // only reached under the lock with no marker
  try { fs.renameSync(tmp, venv); } catch (e) {
    fs.rmSync(tmp, { recursive: true, force: true });
    die(`could not finalize install in ${venv}: ${e.message}`);
  }
}

function run(entry) {
  const root = cacheRoot();
  const venv = path.join(root, VERSION);
  const marker = path.join(venv, ".nxd-ok");
  fs.mkdirSync(root, { recursive: true, mode: 0o700 });
  checkPrivate(root);
  if (!fs.existsSync(marker)) {
    withLock(root, () => {
      if (fs.existsSync(marker)) return; // another launcher finished while we waited
      const py = findPython();
      if (!py) die("Python 3.10+ is required. Install it from https://www.python.org/downloads/ and retry.");
      install(py, root, venv);
    });
  }
  checkPrivate(venv);
  // Run via the venv's python in isolated mode (-I: ignores cwd and PYTHON* env), not the
  // console script (the venv is built in a temp dir and renamed, so shebangs would be stale).
  const exe = path.join(venv, isWin ? "Scripts" : "bin", isWin ? "python.exe" : "python");
  if (!fs.existsSync(exe)) die(`cached install is broken; delete ${venv} and retry`);
  const mod = { "nxd": "nxd.cli", "nxd-mcp": "nxd.mcp_server" }[entry];
  const child = spawn(exe, ["-I", "-m", mod].concat(process.argv.slice(2)), { stdio: "inherit" });
  child.on("error", (e) => die(`could not start: ${e.message}`));
  const sigs = ["SIGINT", "SIGTERM", "SIGHUP"];
  const fwd = {};
  for (const s of sigs) { fwd[s] = () => { try { child.kill(s); } catch (_) {} }; process.on(s, fwd[s]); }
  child.on("exit", (code, signal) => {
    for (const s of sigs) process.removeListener(s, fwd[s]);
    if (signal) {
      process.exitCode = 128 + (os.constants.signals[signal] || 1);
      try { process.kill(process.pid, signal); } catch (_) {}
      setTimeout(() => process.exit(process.exitCode), 50);
    } else process.exit(code === null ? 1 : code);
  });
}

module.exports = { run };
