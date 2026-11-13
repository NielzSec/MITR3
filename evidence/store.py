"""Saved reproduction ledger for agent findings.

Each finding has one stable id derived from its category, target and summary.
The record stores the steps or command already used, the relevant output,
a timestamp and any artifact bytes. Status is ``claimed``, ``verified`` or
``rejected``.

Verification checks that this saved bundle is complete and still matches the
recorded SHA-256. It does not execute the command, open a network connection,
or decide that a target is vulnerable.
"""
from __future__ import annotations

import datetime as dt
import errno
import hashlib
import json
import os
from dataclasses import dataclass, replace
from pathlib import Path
import re
import stat
import unicodedata

SCHEMA = 1
OUTPUT_NAME = "output.txt"
MAX_OUTPUT = 32_768
MAX_ARTIFACT = 262_144
MAX_ARTIFACTS = 8
MAX_RECORD = 65_536
ID_RE = re.compile(r"evd-[0-9a-f]{20}\Z")
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
STAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")
STATUSES = {"claimed", "verified", "rejected"}
FIELDS = {
    "schema", "id", "category", "category_key", "target", "target_key",
    "summary", "summary_key", "steps", "command", "output_sha256", "artifacts",
    "status", "created_at", "updated_at", "verified_at", "rejected_reason",
}


class EvidenceError(ValueError):
    """Fail-closed ledger error. The message is a stable code, not a path."""


@dataclass(frozen=True)
class Artifact:
    name: str
    sha256: str
    ref: str


@dataclass(frozen=True)
class Record:
    id: str
    category: str
    category_key: str
    target: str
    target_key: str
    summary: str
    summary_key: str
    steps: tuple[str, ...]
    command: str
    output: str
    output_sha256: str
    artifacts: tuple[Artifact, ...]
    status: str
    created_at: str
    updated_at: str
    verified_at: str | None
    rejected_reason: str | None

    def refs(self) -> tuple[str, ...]:
        items = []
        if self.output_sha256:
            items.append(f"{self.id}/{OUTPUT_NAME}")
        items.extend(item.ref for item in self.artifacts)
        return tuple(items)


@dataclass(frozen=True)
class ClaimResult:
    record: Record
    deduped: bool


def _collapse(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).split())


def _bounded(value: str, code: str, limit: int, *, required: bool) -> str:
    if not isinstance(value, str):
        raise EvidenceError(code)
    text = _collapse(value)
    if (required and not text) or len(text) > limit:
        raise EvidenceError(code)
    return text


def canonical_category(value: str) -> str:
    return _bounded(value, "invalid_category", 80, required=True).casefold()


def canonical_target(value: str) -> str:
    return _bounded(value, "invalid_target", 500, required=False).casefold().rstrip("/")


def canonical_summary(value: str) -> str:
    return _bounded(value, "invalid_summary", 2000, required=True).casefold()


def stable_id(category_key: str, target_key: str, summary_key: str) -> str:
    payload = json.dumps(
        {"category": category_key, "target": target_key, "summary": summary_key},
        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )
    return "evd-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]


def _stamp(moment: dt.datetime) -> str:
    if not isinstance(moment, dt.datetime) or moment.tzinfo is None:
        raise EvidenceError("invalid_timestamp")
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _steps(steps) -> tuple[str, ...]:
    if isinstance(steps, (str, bytes)) or not isinstance(steps, (list, tuple)):
        raise EvidenceError("invalid_steps")
    if len(steps) > 20:
        raise EvidenceError("invalid_steps")
    cleaned = []
    for step in steps:
        text = _bounded(step, "invalid_steps", 500, required=True)
        cleaned.append(text)
    return tuple(cleaned)


def _command(command: str) -> str:
    return _bounded(command, "invalid_command", 500, required=False)


def _output(output: str) -> str:
    if not isinstance(output, str) or "\x00" in output:
        raise EvidenceError("invalid_output")
    if len(output.encode("utf-8")) > MAX_OUTPUT:
        raise EvidenceError("invalid_output")
    if any(unicodedata.category(ch) == "Cc" and ch not in "\n\t\r" for ch in output):
        raise EvidenceError("invalid_output")
    return output


def _artifacts(artifacts) -> tuple[tuple[str, bytes], ...]:
    if isinstance(artifacts, (str, bytes)) or not isinstance(artifacts, (list, tuple)):
        raise EvidenceError("invalid_artifact")
    if len(artifacts) > MAX_ARTIFACTS:
        raise EvidenceError("invalid_artifact")
    cleaned = []
    seen = set()
    for item in artifacts:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise EvidenceError("invalid_artifact")
        name, blob = item
        if not isinstance(name, str) or name == OUTPUT_NAME or NAME_RE.fullmatch(name) is None:
            raise EvidenceError("invalid_artifact")
        if not isinstance(blob, bytes) or not 0 < len(blob) <= MAX_ARTIFACT:
            raise EvidenceError("invalid_artifact")
        if name in seen:
            raise EvidenceError("invalid_artifact")
        seen.add(name)
        cleaned.append((name, blob))
    return tuple(cleaned)


def _digest(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _pairs(items):
    obj = {}
    for key, value in items:
        if key in obj:
            raise EvidenceError("duplicate_key")
        obj[key] = value
    return obj


def _reject_constant(_value):
    raise EvidenceError("non_finite")


def _read_regular(path: Path, limit: int) -> bytes:
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise EvidenceError("invalid_file")
        chunks = []
        remaining = limit + 1
        while remaining:
            block = os.read(fd, remaining)
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        if len(data) > limit:
            raise EvidenceError("invalid_file")
        return data
    except EvidenceError:
        raise
    except OSError:
        raise EvidenceError("invalid_file") from None
    finally:
        if fd is not None:
            os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise EvidenceError("invalid_store")
        view = view[written:]


def _open_new(path: Path) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        return os.open(path, flags, 0o600)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            raise FileExistsError(path) from None
        if exc.errno == errno.ELOOP:
            raise EvidenceError("symlink_rejected") from None
        raise EvidenceError("invalid_store") from None


def _write_new(path: Path, data: bytes) -> None:
    fd = _open_new(path)
    try:
        _write_all(fd, data)
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    except Exception:
        os.close(fd)
        path.unlink(missing_ok=True)
        raise
    os.close(fd)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class EvidenceStore:
    """Directory ledger. ``root/records`` holds JSON; ``root/artifacts/<id>/`` holds bytes."""

    def __init__(self, root: Path, now=None):
        self.root = Path(root)
        self.records = self.root / "records"
        self.artifacts = self.root / "artifacts"
        self._now = now or (lambda: dt.datetime.now(dt.timezone.utc))
        self._prepare(self.root)
        self._prepare(self.records)
        self._prepare(self.artifacts)

    def claim(self, *, category: str, summary: str, target: str = "") -> ClaimResult:
        category_text = _bounded(category, "invalid_category", 80, required=True)
        summary_text = _bounded(summary, "invalid_summary", 2000, required=True)
        target_text = _bounded(target, "invalid_target", 500, required=False)
        category_key = canonical_category(category_text)
        summary_key = canonical_summary(summary_text)
        target_key = canonical_target(target_text)
        evidence_id = stable_id(category_key, target_key, summary_key)
        existing = self.get(evidence_id)
        if existing is not None:
            return ClaimResult(existing, True)
        moment = self._moment()
        record = Record(
            id=evidence_id, category=category_text, category_key=category_key,
            target=target_text, target_key=target_key, summary=summary_text,
            summary_key=summary_key, steps=(), command="", output="", output_sha256="",
            artifacts=(), status="claimed", created_at=moment, updated_at=moment,
            verified_at=None, rejected_reason=None,
        )
        try:
            _write_new(self.record_path(evidence_id), self._payload(record))
            _fsync_dir(self.records)
        except FileExistsError:
            winner = self.get(evidence_id)
            if winner is None:
                raise EvidenceError("invalid_record")
            return ClaimResult(winner, True)
        return ClaimResult(record, False)

    def save_reproduction(self, evidence_id: str, *, steps=(), command: str = "",
                          output: str = "", artifacts=()) -> Record:
        record = self._require(evidence_id)
        if record.status == "rejected":
            raise EvidenceError("status_rejected")
        cleaned_steps = _steps(steps)
        cleaned_command = _command(command)
        cleaned_output = _output(output)
        cleaned_artifacts = _artifacts(artifacts)
        if (not cleaned_steps and not cleaned_command) or not cleaned_output.strip():
            raise EvidenceError("reproduction_incomplete")
        if record.output_sha256:
            if not self._same_bundle(record, cleaned_steps, cleaned_command, cleaned_output, cleaned_artifacts):
                raise EvidenceError("evidence_conflict")
            if not self.reproduction_intact(record):
                raise EvidenceError("evidence_hash_mismatch")
            return record
        if record.status != "claimed":
            raise EvidenceError("evidence_conflict")
        folder = self.artifacts / evidence_id
        self._prepare(folder)
        files = [(OUTPUT_NAME, cleaned_output.encode("utf-8"))]
        files.extend(cleaned_artifacts)
        created: list[Path] = []
        try:
            for name, blob in files:
                self._place(folder / name, blob, created)
            saved = replace(
                record,
                steps=cleaned_steps,
                command=cleaned_command,
                output=cleaned_output,
                output_sha256=_digest(cleaned_output.encode("utf-8")),
                artifacts=tuple(
                    Artifact(name, _digest(blob), f"{evidence_id}/{name}")
                    for name, blob in cleaned_artifacts
                ),
                updated_at=self._moment(),
            )
            self._replace_record(saved)
        except Exception:
            for path in created:
                path.unlink(missing_ok=True)
            raise
        return saved

    def verify(self, evidence_id: str) -> Record:
        record = self._require(evidence_id)
        if record.status == "rejected":
            raise EvidenceError("status_rejected")
        if not self.reproduction_intact(record):
            raise EvidenceError("reproduction_incomplete")
        if record.status == "verified":
            return record
        moment = self._moment()
        saved = replace(record, status="verified", verified_at=moment, updated_at=moment)
        self._replace_record(saved)
        return saved

    def reject(self, evidence_id: str, reason: str) -> Record:
        record = self._require(evidence_id)
        text = _bounded(reason, "invalid_reason", 500, required=True)
        if record.status == "rejected":
            return record
        saved = replace(
            record, status="rejected", rejected_reason=text, verified_at=None, updated_at=self._moment(),
        )
        self._replace_record(saved)
        return saved

    def get(self, evidence_id: str) -> Record | None:
        path = self.record_path(evidence_id)
        if path.is_symlink():
            raise EvidenceError("symlink_rejected")
        if not path.exists():
            return None
        try:
            raw = _read_regular(path, MAX_RECORD)
        except EvidenceError:
            raise EvidenceError("invalid_record") from None
        return self._parse(evidence_id, raw)

    def reproduction_intact(self, record: Record) -> bool:
        if record.status not in {"claimed", "verified"}:
            return False
        if not record.steps and not record.command:
            return False
        if not record.output.strip() or not HEX_RE.fullmatch(record.output_sha256 or ""):
            return False
        if _digest(record.output.encode("utf-8")) != record.output_sha256:
            return False
        try:
            blob = _read_regular(self.artifact_path(record.id, OUTPUT_NAME), MAX_OUTPUT)
        except EvidenceError:
            return False
        if blob != record.output.encode("utf-8") or _digest(blob) != record.output_sha256:
            return False
        for item in record.artifacts:
            if item.ref != f"{record.id}/{item.name}" or not HEX_RE.fullmatch(item.sha256):
                return False
            try:
                body = _read_regular(self.artifact_path(record.id, item.name), MAX_ARTIFACT)
            except EvidenceError:
                return False
            if _digest(body) != item.sha256:
                return False
        return True

    def record_path(self, evidence_id: str) -> Path:
        self._check_id(evidence_id)
        return self.records / f"{evidence_id}.json"

    def artifact_path(self, evidence_id: str, name: str) -> Path:
        self._check_id(evidence_id)
        if not isinstance(name, str) or NAME_RE.fullmatch(name) is None:
            raise EvidenceError("invalid_artifact")
        return self.artifacts / evidence_id / name

    def _require(self, evidence_id: str) -> Record:
        record = self.get(evidence_id)
        if record is None:
            raise EvidenceError("no_evidence_record")
        return record

    def _moment(self) -> str:
        return _stamp(self._now())

    def _check_id(self, evidence_id: str) -> None:
        if not isinstance(evidence_id, str) or ID_RE.fullmatch(evidence_id) is None:
            raise EvidenceError("invalid_id")

    def _prepare(self, path: Path) -> None:
        if path.is_symlink():
            raise EvidenceError("symlink_rejected")
        path.mkdir(mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
        if path.is_symlink() or not path.is_dir():
            raise EvidenceError("invalid_store")

    def _place(self, path: Path, blob: bytes, created: list[Path]) -> None:
        if path.is_symlink():
            raise EvidenceError("symlink_rejected")
        if path.exists():
            current = _read_regular(path, max(MAX_OUTPUT, MAX_ARTIFACT))
            if current != blob:
                raise EvidenceError("evidence_conflict")
            return
        _write_new(path, blob)
        created.append(path)

    def _same_bundle(self, record: Record, steps, command: str, output: str, artifacts) -> bool:
        if record.steps != steps or record.command != command or record.output != output:
            return False
        if _digest(output.encode("utf-8")) != record.output_sha256:
            return False
        if len(record.artifacts) != len(artifacts):
            return False
        for saved, (name, blob) in zip(record.artifacts, artifacts):
            if saved.name != name or saved.sha256 != _digest(blob) or saved.ref != f"{record.id}/{name}":
                return False
        return True

    def _payload(self, record: Record) -> bytes:
        body = {
            "schema": SCHEMA,
            "id": record.id,
            "category": record.category,
            "category_key": record.category_key,
            "target": record.target,
            "target_key": record.target_key,
            "summary": record.summary,
            "summary_key": record.summary_key,
            "steps": list(record.steps),
            "command": record.command,
            "output_sha256": record.output_sha256,
            "artifacts": [
                {"name": item.name, "sha256": item.sha256, "ref": item.ref}
                for item in record.artifacts
            ],
            "status": record.status,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
            "verified_at": record.verified_at,
            "rejected_reason": record.rejected_reason,
        }
        return (json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")

    def _replace_record(self, record: Record) -> None:
        path = self.record_path(record.id)
        temporary = self.records / f".{record.id}.{os.getpid()}.tmp"
        _write_new(temporary, self._payload(record))
        os.replace(temporary, path)
        _fsync_dir(self.records)

    def _parse(self, evidence_id: str, raw: bytes) -> Record:
        try:
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_reject_constant)
        except EvidenceError:
            raise
        except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError):
            raise EvidenceError("invalid_record") from None
        if type(data) is not dict or set(data) != FIELDS or data["schema"] != SCHEMA:
            raise EvidenceError("invalid_record")
        if data["id"] != evidence_id or data["status"] not in STATUSES:
            raise EvidenceError("invalid_record")
        try:
            category = _bounded(data["category"], "invalid_record", 80, required=True)
            target = _bounded(data["target"], "invalid_record", 500, required=False)
            summary = _bounded(data["summary"], "invalid_record", 2000, required=True)
            category_key = data["category_key"]
            target_key = data["target_key"]
            summary_key = data["summary_key"]
            if (category_key != category.casefold() or target_key != target.casefold().rstrip("/")
                    or summary_key != summary.casefold()
                    or stable_id(category_key, target_key, summary_key) != evidence_id):
                raise EvidenceError("invalid_record")
            steps = _steps(data["steps"])
            if list(steps) != data["steps"]:
                raise EvidenceError("invalid_record")
            command = _command(data["command"])
            if command != data["command"]:
                raise EvidenceError("invalid_record")
        except EvidenceError as exc:
            if str(exc) == "invalid_record":
                raise
            raise EvidenceError("invalid_record") from None
        output_sha256 = data["output_sha256"]
        if not isinstance(output_sha256, str) or (output_sha256 and HEX_RE.fullmatch(output_sha256) is None):
            raise EvidenceError("invalid_record")
        artifacts = self._parse_artifacts(evidence_id, data["artifacts"])
        status = data["status"]
        created_at = self._time_field(data["created_at"])
        updated_at = self._time_field(data["updated_at"])
        verified_at = data["verified_at"]
        rejected_reason = data["rejected_reason"]
        if status == "verified":
            if not isinstance(verified_at, str):
                raise EvidenceError("invalid_record")
            self._time_field(verified_at)
        elif verified_at is not None:
            raise EvidenceError("invalid_record")
        if status == "rejected":
            if not isinstance(rejected_reason, str):
                raise EvidenceError("invalid_record")
            rejected_reason = _bounded(rejected_reason, "invalid_record", 500, required=True)
            if rejected_reason != data["rejected_reason"]:
                raise EvidenceError("invalid_record")
        elif rejected_reason is not None:
            raise EvidenceError("invalid_record")
        output = self._load_output(evidence_id, output_sha256)
        return Record(
            id=evidence_id, category=category, category_key=category_key, target=target,
            target_key=target_key, summary=summary, summary_key=summary_key, steps=steps,
            command=command, output=output, output_sha256=output_sha256, artifacts=artifacts,
            status=status, created_at=created_at, updated_at=updated_at, verified_at=verified_at,
            rejected_reason=rejected_reason,
        )

    def _parse_artifacts(self, evidence_id: str, raw) -> tuple[Artifact, ...]:
        if type(raw) is not list or len(raw) > MAX_ARTIFACTS:
            raise EvidenceError("invalid_record")
        items = []
        seen = set()
        for item in raw:
            if type(item) is not dict or set(item) != {"name", "sha256", "ref"}:
                raise EvidenceError("invalid_record")
            name, digest, ref = item["name"], item["sha256"], item["ref"]
            if (not isinstance(name, str) or name == OUTPUT_NAME or NAME_RE.fullmatch(name) is None
                    or name in seen or not isinstance(digest, str) or HEX_RE.fullmatch(digest) is None
                    or ref != f"{evidence_id}/{name}"):
                raise EvidenceError("invalid_record")
            seen.add(name)
            items.append(Artifact(name, digest, ref))
        return tuple(items)

    def _load_output(self, evidence_id: str, output_sha256: str) -> str:
        if not output_sha256:
            return ""
        try:
            blob = _read_regular(self.artifact_path(evidence_id, OUTPUT_NAME), MAX_OUTPUT)
            text = blob.decode("utf-8")
        except (EvidenceError, UnicodeError):
            return ""
        if _digest(blob) != output_sha256 or _digest(text.encode("utf-8")) != output_sha256:
            return ""
        return text

    def _time_field(self, value: str) -> str:
        if not isinstance(value, str) or STAMP_RE.fullmatch(value) is None:
            raise EvidenceError("invalid_record")
        return value
