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


#: Files the sdist's own test suite reads; their absence used to make tests
#: error or skip silently.
SDIST_REQUIRED = ("LICENSE", "README.md", "SECURITY.md", "pyproject.toml", "tests/support.py",
                  "tests/test_provider_boundary.py", "tools/check_distribution.py",
                  "tools/eval/catalog.py", "tools/eval/run_catalog.py",
                  "tools/bench/bench.py", "tools/bench/scenarios.py", "tools/bench/golden.json",
                  "tests/fixtures/openrouter/observed/2026-10-06/index.json",
                  "tests/fixtures/openrouter/observed/2026-10-06/S02.json")
#: The labeled catalog is a port; its MIT attribution must travel with it.
CATALOG_ATTRIBUTION = ("Copyright (c)", "MIT")


def run(argv, cwd, *, expected=0, timeout=120):
    env = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONSAFEPATH", "OPENAI_API_KEY", "OPENAI_ORG_ID",
                 "OPENAI_PROJECT_ID", "OPENROUTER_API_KEY", "DBH_PROVIDER"):
        env.pop(name, None)
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True,
                            timeout=timeout)
    if expected is not None and result.returncode != expected:
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
        inner = "/".join(parts.parts[1:])
        if parts.name == "live_probe.py" or inner == "tools/smoke" or inner.startswith(
                "tools/smoke/"):
            # Live smoke tooling is repository-only (D12).
            raise RuntimeError("unexpected_live_tooling")
        if parts.name == ".env" or parts.name.endswith((".pem", ".key")):
            raise RuntimeError("unexpected_private_file")


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
                     "decision_bug_hunter/openrouter.py", "decision_bug_hunter/hosted.py",
                     "decision_bug_hunter/exchange.py", "decision_bug_hunter/protocol.py",
                     "decision_bug_hunter/secret_scan.py",
                     "decision_bug_hunter/injection_markers.py",
                     "decision_bug_hunter/question_pack.json"):
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
        for required in SDIST_REQUIRED:
            if required not in names:
                raise RuntimeError("incomplete_source_distribution")
        catalog = next(m for m in members
                       if "/".join(PurePosixPath(m.name).parts[1:]) == "tools/eval/catalog.py")
        handle = archive.extractfile(catalog)
        header = handle.read(2048).decode("utf-8") if handle is not None else ""
        if not all(part in header for part in CATALOG_ATTRIBUTION):
            raise RuntimeError("missing_catalog_attribution")
    with tempfile.TemporaryDirectory(prefix="dbh-distribution-") as temp:
        root = Path(temp)
        unpacked = root / "sdist"
        with tarfile.open(archives[0], "r:gz") as archive:
            # Members were checked above: regular files and directories with
            # safe relative names only, so a plain copy is safe on 3.11.0+.
            for member in archive.getmembers():
                target = unpacked.joinpath(*PurePosixPath(member.name).parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                handle = archive.extractfile(member)
                target.write_bytes(handle.read() if handle is not None else b"")
        (source_root,) = [path for path in unpacked.iterdir() if path.is_dir()]
        # Driver pip installs into the fresh environment without bootstrapping pip.
        run([sys.executable, "-m", "venv", "--without-pip", str(root / "venv")], root)
        python = root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run([sys.executable, "-m", "pip", "--python", str(python), "install",
             "--no-index", "--no-deps", str(wheels[0])], root)
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
        scan = [str(python), "-I", "-m", "decision_bug_hunter", "absent-source.py",
                "--scope", "standalone", "--output-dir", "outputs"]
        for provider in ("openai", "openrouter"):
            failed = run(scan + ["--provider", provider], root, expected=2)
            if ("provider_unavailable" not in failed.stderr or failed.stdout
                    or (root / "outputs").exists()):
                raise RuntimeError("installed_provider_gate_failed")
        # No route selected: the caller must choose the data processor.
        unselected = run(scan, root, expected=3)
        if ("NEED_USER_INPUT provider" not in unselected.stderr or unselected.stdout
                or (root / "outputs").exists()):
            raise RuntimeError("installed_provider_selection_gate_failed")
        # The sdist's own offline suite must pass from the unpacked sdist,
        # importing the package from that tree (not the installed wheel).
        located = run([str(python), "-c", "import decision_bug_hunter as p; print(p.__file__)"],
                      source_root)
        if source_root.resolve() not in Path(located.stdout.strip()).resolve().parents:
            raise RuntimeError("sdist_tests_did_not_use_sdist_tree")
        suite = run([str(python), "-m", "unittest", "discover", "-s", "tests", "-t", "."],
                    source_root, expected=None, timeout=3600)
        if suite.returncode != 0:
            # unittest's summary names failing tests only; it holds no secret.
            print("\n".join(suite.stderr.splitlines()[-60:]), file=sys.stderr)
            raise RuntimeError("sdist_test_suite_failed")
    print("Distribution: wheel contents, sdist contents, fresh install, resource import, "
          "CLI help, provider selection and unavailable gates, and the sdist test suite "
          "passed.")


if __name__ == "__main__":
    main()
