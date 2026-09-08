"""
sandbox.py — the /run code executor. Defense-in-depth, not true isolation
(no Docker/VM available on typical free hosts):
  1. Static AST check rejects known-dangerous imports/calls up front.
  2. Runs as a subprocess with a stripped-down environment (no secrets).
  3. CPU time, memory, and process-count limits applied to the child.
  4. Hard timeout as a final backstop.
  5. Output is capped so nothing can flood the chat or the server.

A determined attacker could still find bypasses (e.g. building forbidden
names dynamically at runtime) — this blocks the common, obvious escapes,
it doesn't claim full isolation.
"""

import ast
import os
import resource
import subprocess
from core import MAX_OUTPUT_CHARS

FORBIDDEN_MODULES = {
    "os", "subprocess", "sys", "shutil", "socket", "ctypes",
    "importlib", "multiprocessing", "threading", "signal",
    "pty", "resource", "pickle", "marshal", "code", "pdb",
}
FORBIDDEN_NAMES = {"eval", "exec", "__import__", "compile", "open", "globals", "vars"}
FORBIDDEN_ATTRS = {"system", "popen", "remove", "rmdir", "unlink", "kill", "fork"}


def is_code_safe(code: str) -> tuple[bool, str]:
    """Static AST check: reject code that imports or calls known-dangerous
    names before it ever runs."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return False, f"Syntax error: {e}"

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in FORBIDDEN_MODULES:
                    return False, f"🚫 Importing '{top}' isn't allowed in /run."
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            return False, f"🚫 Using '{node.id}(...)' isn't allowed in /run."
        if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_ATTRS:
            return False, f"🚫 Calling '.{node.attr}(...)' isn't allowed in /run."
    return True, ""


def _limit_child_resources():
    """Runs inside the child process, right before it executes user code.
    Caps CPU time, memory, and process count so nothing can hang the
    server, exhaust its RAM, or fork-bomb the container."""
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    mem_bytes = 64 * 1024 * 1024  # 64 MB
    resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NPROC, (10, 10))


def run_python_code(code: str) -> str:
    """Run Python code in the sandbox described above and return its output."""
    safe, reason = is_code_safe(code)
    if not safe:
        return reason

    clean_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}

    try:
        result = subprocess.run(
            ["python3", "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            env=clean_env,
            preexec_fn=_limit_child_resources,
        )
        output = result.stdout.strip()
        if result.returncode != 0:
            output = (output + "\n" + result.stderr.strip()).strip()
        if not output:
            return "(no output)"
        if len(output) > MAX_OUTPUT_CHARS:
            output = output[:MAX_OUTPUT_CHARS] + "\n... (truncated)"
        return output
    except subprocess.TimeoutExpired:
        return "⚠️ Code timed out (max 10 seconds)."
    except Exception as e:
        return f"⚠️ Execution failed: {e}"
