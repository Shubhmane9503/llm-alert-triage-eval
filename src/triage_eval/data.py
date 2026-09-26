from __future__ import annotations

import hashlib
import shutil
import urllib.request
import zipfile
from pathlib import Path

AIT_ADS_ZIP_URL = (
    "https://zenodo.org/records/8263181/files/ait_ads.zip?download=1"
)
AIT_ADS_ZIP_MD5 = "43db6b1f0996e0024befd617706c50e9"
LABELS_URL = "https://zenodo.org/records/8263181/files/labels.csv?download=1"
LABELS_MD5 = "60ff33796c77fd2136c4d1a4bc841bd9"


def _md5(path: Path) -> str:
    digest = hashlib.md5()  # noqa: S324 - published integrity checksum
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(url: str, destination: Path) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "llm-alert-triage-eval/0.1"},
    )
    with (
        urllib.request.urlopen(request, timeout=120) as response,
        destination.open("wb") as output,
    ):
        shutil.copyfileobj(response, output)


def _verify(path: Path, expected_md5: str) -> None:
    actual = _md5(path)
    if actual != expected_md5:
        raise ValueError(
            f"checksum mismatch for {path.name}: "
            f"expected {expected_md5}, got {actual}"
        )


def _safe_extract(
    archive: zipfile.ZipFile,
    destination: Path,
) -> None:
    root = destination.resolve()
    for member in archive.infolist():
        target = (destination / member.filename).resolve()
        if root not in target.parents and target != root:
            raise ValueError(f"unsafe zip member: {member.filename}")
    archive.extractall(destination)


def download_ait_ads(output_dir: Path) -> None:
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / "ait_ads.zip"
    labels_path = raw_dir / "labels.csv"

    if not archive_path.exists():
        _download(AIT_ADS_ZIP_URL, archive_path)
    _verify(archive_path, AIT_ADS_ZIP_MD5)

    if not labels_path.exists():
        _download(LABELS_URL, labels_path)
    _verify(labels_path, LABELS_MD5)

    with zipfile.ZipFile(archive_path) as archive:
        _safe_extract(archive, raw_dir)
