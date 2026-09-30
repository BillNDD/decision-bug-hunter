"""Check DBH archives and install the wheel without network or provider calls."""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile
import zipfile


def run(argv, cwd, *, expected=0):
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
    if result.returncode != expected:
        raise RuntimeError("distribution_command_failed")
    return result


def safe_names(names):
    for name in names:
        parts = PurePosixPath(name)
        if parts.is_absolute() or ".." in parts.parts or "\\" in name or ":" in name:
            raise RuntimeError("unsafe_archive_member")
        if any(part in {"acceptance", "__pycache__", "dbh_runs", "smoke-results", ".git"} for part in parts.parts):
            raise RuntimeError("unnecessary_archive_member")
        if name.endswith(("transport.py", "jev.py", ".pyc")):
            raise RuntimeError("unexpected_upstream_transport")


def main():
    dist = Path(sys.argv[1] if len(sys.argv) == 2 else "dist").resolve()
    wheels = list(dist.glob("decision_bug_hunter-*.whl"))
    archives = list(dist.glob("decision_bug_hunter-*.tar.gz"))
    if len(wheels) != 1 or len(archives) != 1:
        raise RuntimeError("expected_one_wheel_and_one_sdist")
    with zipfile.ZipFile(wheels[0]) as wheel:
        names = wheel.namelist()
        safe_names(names)
        for name in ("decision_bug_hunter/providers.py", "decision_bug_hunter/decisions.py",
                     "decision_bug_hunter/protocol.py", "decision_bug_hunter/question_pack.json"):
            if name not in names:
                raise RuntimeError("missing_runtime_resource")
        if not any(name.endswith("/LICENSE") for name in names):
            raise RuntimeError("missing_wheel_license")
    with tarfile.open(archives[0], "r:gz") as archive:
        members = archive.getmembers()
        safe_names([member.name for member in members])
        if any(not (m.isdir() or m.isfile()) for m in members):
            raise RuntimeError("unsupported_archive_member")
        names = {"/".join(PurePosixPath(m.name).parts[1:]) for m in members}
        for required in ("LICENSE", "README.md", "pyproject.toml", "tests/support.py",
                         "tests/test_provider_boundary.py", "tools/check_distribution.py"):
            if required not in names:
                raise RuntimeError("incomplete_source_distribution")
    with tempfile.TemporaryDirectory(prefix="dbh-distribution-") as temp:
        root = Path(temp)
        run([sys.executable, "-m", "venv", str(root / "venv")], root)
        python = root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run([str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheels[0])], root)
        code = ("import json; from importlib.resources import files; import decision_bug_hunter as p; "
                "from decision_bug_hunter.decisions import DecisionsProvider; "
                "from decision_bug_hunter.protocol import ProviderError; "
                "assert files('decision_bug_hunter').joinpath('question_pack.json').is_file(); "
                "print(json.dumps({'version':p.__version__,'package':p.__file__}))")
        installed = json.loads(run([str(python), "-I", "-c", code], root).stdout)
        if root / "venv" not in Path(installed["package"]).parents:
            raise RuntimeError("import_did_not_use_installed_wheel")
        help_result = run([str(python), "-I", "-m", "decision_bug_hunter", "--help"], root)
        if "decision-bug-hunter" not in help_result.stdout:
            raise RuntimeError("missing_cli_identity")
        failed = run([str(python), "-I", "-m", "decision_bug_hunter", "absent-source.py",
                      "--scope", "standalone", "--output-dir", "outputs"], root, expected=2)
        if "provider_unavailable" not in failed.stderr or failed.stdout or (root / "outputs").exists():
            raise RuntimeError("installed_provider_gate_failed")
    print("Distribution: wheel contents, sdist contents, fresh install, resource import, CLI help, unavailable gate passed.")


if __name__ == "__main__":
    main()
