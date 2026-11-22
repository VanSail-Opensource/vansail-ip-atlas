"""Stage or reconstruct the content-addressed browser index for the current release."""
from pathlib import Path
import subprocess

from tools.release_contract.contracts import ContractError, HASH, canonical_bytes, parse_canonical

ROOT = Path(__file__).resolve().parents[2]


def run_index(atlas: Path, *, verify: str | None = None) -> str:
    command = ["go", "run", "./cmd/atlas-browser-index", "-atlas", str(atlas), "-out", str(atlas / "browser")]
    if verify is not None:
        command.extend(["-verify", verify])
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, check=False, timeout=180)
    if result.returncode:
        raise ContractError("browser routing directory differs from the complete native release")
    return result.stdout.decode("ascii").strip()


def stage_browser_index(atlas: Path) -> None:
    pointer_path = atlas / "current.json"
    pointer = parse_canonical(pointer_path.read_bytes())
    if "browser_sha256" in pointer:
        return  # The full reconstruction check follows on the staged tree.
    if (atlas / "browser").exists():
        raise ContractError("unreferenced browser routing directory")
    digest = run_index(atlas)
    if not HASH.fullmatch(digest):
        raise ContractError("browser index compiler returned an invalid root")
    pointer_path.write_bytes(canonical_bytes({**pointer, "browser_sha256": digest}))


def verified_browser_files(atlas: Path, pointer: dict) -> set[str]:
    directory = atlas / "browser"
    if "browser_sha256" not in pointer:
        if directory.exists() or directory.is_symlink():
            raise ContractError("unbound browser index")
        return set()
    if directory.is_symlink() or not directory.is_dir():
        raise ContractError("missing browser index")
    run_index(atlas, verify=pointer["browser_sha256"])
    return {path.relative_to(atlas).as_posix() for path in directory.iterdir()}
