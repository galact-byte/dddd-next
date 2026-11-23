"""Synchronize the locally patched httpx module with its required Go version."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time

MODULE = "github.com/projectdiscovery/httpx"
RECORD = "third_party/httpx-upstream.json"
WINDOWS = os.name == "nt"


def retry_windows(operation):
    for attempt in range(5):
        try:
            return operation()
        except PermissionError:
            if not WINDOWS or attempt == 4:
                raise
            time.sleep(0.02 * (attempt + 1))


def move_directory(source, target):
    source.chmod(stat.S_IMODE(source.stat().st_mode) | stat.S_IWUSR)
    retry_windows(lambda: source.rename(target))


def make_writable(root):
    for directory, _, files in os.walk(root):
        Path(directory).chmod(0o755)
        for name in files:
            path = Path(directory) / name
            path.chmod(stat.S_IMODE(path.stat().st_mode) | stat.S_IWUSR)


def version_tuple(version):
    if not re.fullmatch(r"v1\.(0|[1-9]\d*)\.(0|[1-9]\d*)", version):
        raise ValueError(f"unsupported httpx release: {version!r}")
    return tuple(map(int, version[1:].split(".")))


def required_version(repo):
    matches = re.findall(r"^\s*" + re.escape(MODULE) + r"\s+(\S+)",
                         (repo / "go.mod").read_text(encoding="utf-8"), re.MULTILINE)
    if len(matches) != 1:
        raise ValueError("go.mod must require exactly one httpx version")
    version_tuple(matches[0])
    return matches[0]


def source_record(repo):
    record = json.loads((repo / RECORD).read_text(encoding="utf-8"))
    if record.get("module") != MODULE:
        raise ValueError("unexpected httpx source module")
    version_tuple(record["version"])
    if not re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", record.get("sum", "")):
        raise ValueError("invalid httpx module checksum")
    return record


def check_version(repo):
    if required_version(repo) != source_record(repo)["version"]:
        raise ValueError("httpx source version differs from go.mod; synchronize source before merging")


def sync_httpx(repo, source, version, checksum):
    requested = version_tuple(version)
    record = source_record(repo)
    if required_version(repo) != version:
        raise ValueError("requested httpx version differs from go.mod")
    if requested < version_tuple(record["version"]):
        raise ValueError("httpx source downgrade requires manual review")
    if version == record["version"]:
        return False
    if not re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", checksum):
        raise ValueError("invalid httpx module checksum")
    manifest = (source / "go.mod").read_text(encoding="utf-8")
    if not re.search(r"^module\s+" + re.escape(MODULE) + r"\s*$", manifest, re.MULTILINE):
        raise ValueError("downloaded source is not the httpx module")
    if not (source / "LICENSE.md").is_file() or not (source / "runner/runner.go").is_file():
        raise ValueError("incomplete httpx module source")
    if any(path.is_symlink() for path in source.rglob("*")):
        raise ValueError("unexpected symlink in httpx module source")

    target = repo / "third_party/httpx"
    patch = (repo / "third_party/httpx-ratelimiter.patch").resolve()
    # Prepare and validate on the same filesystem before replacing any tracked source.
    temp = Path(tempfile.mkdtemp(prefix=".httpx-sync-", dir=target.parent))
    preserve_previous = False
    try:
        staging = temp / "source"
        shutil.copytree(source, staging)
        # Go's module cache is read-only; the working copy must support patching and tidy.
        make_writable(staging)
        environment = dict(os.environ, GIT_CEILING_DIRECTORIES=str(staging.parent.resolve()))

        def apply(*options):
            return subprocess.run(["git", "apply", *options, str(patch)], cwd=staging,
                                  env=environment, text=True, capture_output=True, timeout=30)

        result = apply("--check")
        if result.returncode == 0:
            result = apply()
            if result.returncode:
                raise ValueError("httpx patch failed: " + result.stderr)
        elif apply("--reverse", "--check").returncode:
            raise ValueError("httpx patch conflicts with upstream; manual review required: " + result.stderr)

        pending = temp / "upstream.json"
        pending.write_text(json.dumps({"module": MODULE, "version": version, "sum": checksum},
                                      indent=2) + "\n", encoding="utf-8")
        saved_record = temp / "previous.json"
        shutil.copy2(repo / RECORD, saved_record)
        previous = temp / "previous"
        os.replace(pending, repo / RECORD)
        try:
            move_directory(target, previous)
            move_directory(staging, target)
        except OSError:
            try:
                if previous.exists():
                    move_directory(previous, target)
            except OSError as error:
                preserve_previous = True
                raise OSError(f"httpx restore failed; previous source preserved at {previous}") from error
            finally:
                try:
                    os.replace(saved_record, repo / RECORD)
                except OSError as error:
                    preserve_previous = True
                    raise OSError(f"httpx metadata restore failed; original record preserved at {saved_record}") from error
            raise
    finally:
        if not preserve_previous:
            make_writable(temp)
            retry_windows(lambda: shutil.rmtree(temp))
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--check", action="store_true", help="check manifest/source version consistency only")
    args = parser.parse_args()
    repo = args.repo.resolve()
    if args.check:
        check_version(repo)
        print("httpx manifest and source versions match")
        return
    version = required_version(repo)
    if version == source_record(repo)["version"]:
        print("httpx source is already synchronized")
        return
    result = subprocess.run(["go", "mod", "download", "-json", f"{MODULE}@{version}"],
                            cwd=repo, text=True, capture_output=True, timeout=180)
    if result.returncode:
        raise ValueError("httpx module download failed: " + (result.stderr or result.stdout))
    module = json.loads(result.stdout)
    if module.get("Path") != MODULE or module.get("Version") != version:
        raise ValueError("downloaded module does not match the requested httpx release")
    sync_httpx(repo, Path(module["Dir"]), version, module["Sum"])
    print(f"httpx source synchronized to {version}; limiter patch retained")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error))
