"""Unified diff generation, parsing and patch application for text files.

The module computes a minimal line diff with Myers' algorithm, renders it as a
unified diff, parses unified diffs back into structured hunks, and applies them
to text or to a directory tree. Application tolerates moved hunks (it searches
nearby positions for a match) but never edits a file unless every context and
removed line matches exactly.

Typical use::

    patch = unified_diff(old_text, new_text, "a/app.txt", "b/app.txt")
    patched = apply_patch_text(old_text, patch)
    assert patched == new_text
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import NamedTuple, Optional, Sequence

NO_NEWLINE_MARK = "\\ No newline at end of file"
DEV_NULL = "/dev/null"
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: (.*))?$")
DEFAULT_CONTEXT = 3
DEFAULT_MAX_OFFSET = 200
NO_EOL_KEY = "\x00no-eol"


class PatchError(ValueError):
    """Raised when a patch is malformed or does not apply."""

    def __init__(self, message: str, *, hunk: int = 0, line: int = 0) -> None:
        super().__init__(message)
        self.hunk = hunk
        self.line = line


class Opcode(NamedTuple):
    """A run of lines: ``tag`` is equal, replace, delete or insert."""

    tag: str
    a1: int
    a2: int
    b1: int
    b2: int


@dataclass
class HunkLine:
    """One line of a hunk body: kind is ' ', '-' or '+'."""

    kind: str
    text: str
    no_newline: bool = False


@dataclass
class Hunk:
    """A contiguous change with its surrounding context.

    ``old_start`` and ``new_start`` are the numbers printed in the header: the
    1-based first line, or the line before the hunk when the length is zero.
    """

    old_start: int
    old_len: int
    new_start: int
    new_len: int
    lines: list[HunkLine] = field(default_factory=list)
    heading: str = ""


@dataclass
class FilePatch:
    """All hunks for one file, with the paths from the diff header."""

    old_path: str
    new_path: str
    hunks: list[Hunk] = field(default_factory=list)


@dataclass(frozen=True)
class FileResult:
    """Outcome of applying a patch to one path of a tree."""

    path: str
    action: str
    added: int
    removed: int


def split_text(text: str) -> tuple[list[str], bool]:
    """Split on newlines; the flag says whether the text ends with one."""
    if text == "":
        return [], True
    ends = text.endswith("\n")
    lines = text.split("\n")
    if ends:
        lines.pop()
    return lines, ends


def join_text(lines: Sequence[str], final_newline: bool) -> str:
    """Inverse of :func:`split_text`."""
    if not lines:
        return ""
    return "\n".join(lines) + ("\n" if final_newline else "")


def _myers_matches(a: Sequence[str], b: Sequence[str]) -> list[tuple[int, int]]:
    """Return index pairs of lines kept by a shortest edit script."""
    n, m = len(a), len(b)
    if n == 0 or m == 0:
        return []
    frontier = {1: 0}
    trace: list[dict[int, int]] = []
    for d in range(n + m + 1):
        trace.append(dict(frontier))
        for k in range(-d, d + 1, 2):
            if k == -d or (k != d and frontier.get(k - 1, 0) < frontier.get(k + 1, 0)):
                x = frontier.get(k + 1, 0)
            else:
                x = frontier.get(k - 1, 0) + 1
            y = x - k
            while x < n and y < m and a[x] == b[y]:
                x += 1
                y += 1
            frontier[k] = x
            if x >= n and y >= m:
                return _backtrack(trace, n, m)
    return []


def _backtrack(trace: list[dict[int, int]], n: int, m: int) -> list[tuple[int, int]]:
    x, y = n, m
    matches: list[tuple[int, int]] = []
    for d in range(len(trace) - 1, -1, -1):
        before = trace[d]
        k = x - y
        if k == -d or (k != d and before.get(k - 1, 0) < before.get(k + 1, 0)):
            prev_k = k + 1
        else:
            prev_k = k - 1
        prev_x = before.get(prev_k, 0)
        prev_y = prev_x - prev_k
        while x > prev_x and y > prev_y:
            x -= 1
            y -= 1
            matches.append((x, y))
        if d > 0:
            if x == prev_x:
                y -= 1
            else:
                x -= 1
    matches.reverse()
    return matches


def compute_opcodes(a: Sequence[str], b: Sequence[str]) -> list[Opcode]:
    """Diff two sequences of comparison keys into ordered opcodes."""
    start = 0
    while start < len(a) and start < len(b) and a[start] == b[start]:
        start += 1
    end_a, end_b = len(a), len(b)
    while end_a > start and end_b > start and a[end_a - 1] == b[end_b - 1]:
        end_a -= 1
        end_b -= 1
    matches = [(i, i) for i in range(start)]
    middle = _myers_matches(a[start:end_a], b[start:end_b])
    matches.extend((i + start, j + start) for i, j in middle)
    matches.extend((end_a + t, end_b + t) for t in range(len(a) - end_a))
    opcodes: list[Opcode] = []
    i = j = 0
    k = 0
    while k < len(matches):
        mi, mj = matches[k]
        run = 1
        while k + run < len(matches) and matches[k + run] == (mi + run, mj + run):
            run += 1
        if mi > i or mj > j:
            opcodes.append(Opcode(_change_tag(i, mi, j, mj), i, mi, j, mj))
        opcodes.append(Opcode("equal", mi, mi + run, mj, mj + run))
        i, j = mi + run, mj + run
        k += run
    if i < len(a) or j < len(b):
        opcodes.append(Opcode(_change_tag(i, len(a), j, len(b)), i, len(a), j, len(b)))
    return opcodes


def _change_tag(a1: int, a2: int, b1: int, b2: int) -> str:
    if a1 == a2:
        return "insert"
    if b1 == b2:
        return "delete"
    return "replace"


def group_opcodes(opcodes: Sequence[Opcode], context: int) -> list[list[Opcode]]:
    """Cut opcodes into hunks, each change padded with ``context`` lines."""
    codes = list(opcodes)
    if not codes:
        return []
    first, last = codes[0], codes[-1]
    if first.tag == "equal":
        codes[0] = Opcode("equal", max(first.a1, first.a2 - context), first.a2,
                          max(first.b1, first.b2 - context), first.b2)
    if last.tag == "equal":
        codes[-1] = Opcode("equal", last.a1, min(last.a2, last.a1 + context),
                           last.b1, min(last.b2, last.b1 + context))
    groups: list[list[Opcode]] = []
    group: list[Opcode] = []
    for op in codes:
        if op.tag == "equal" and op.a2 - op.a1 > 2 * context:
            group.append(Opcode("equal", op.a1, min(op.a2, op.a1 + context),
                                op.b1, min(op.b2, op.b1 + context)))
            groups.append(group)
            group = []
            op = Opcode("equal", max(op.a1, op.a2 - context), op.a2,
                        max(op.b1, op.b2 - context), op.b2)
        group.append(op)
    if group and not (len(group) == 1 and group[0].tag == "equal"):
        groups.append(group)
    return groups


def _build_hunk(group: Sequence[Opcode], a: Sequence[str], b: Sequence[str],
                a_final_nl: bool, b_final_nl: bool) -> Hunk:
    first, last = group[0], group[-1]
    old_len = last.a2 - first.a1
    new_len = last.b2 - first.b1
    body: list[HunkLine] = []
    for op in group:
        if op.tag == "equal":
            for idx in range(op.a1, op.a2):
                body.append(HunkLine(" ", a[idx], idx == len(a) - 1 and not a_final_nl))
            continue
        for idx in range(op.a1, op.a2):
            body.append(HunkLine("-", a[idx], idx == len(a) - 1 and not a_final_nl))
        for idx in range(op.b1, op.b2):
            body.append(HunkLine("+", b[idx], idx == len(b) - 1 and not b_final_nl))
    return Hunk(
        old_start=first.a1 + 1 if old_len else first.a1,
        old_len=old_len,
        new_start=first.b1 + 1 if new_len else first.b1,
        new_len=new_len,
        lines=body,
    )


def _format_range(start: int, length: int) -> str:
    return str(start) if length == 1 else f"{start},{length}"


def render_hunk(hunk: Hunk) -> str:
    """Render one hunk, header included, with a trailing newline."""
    header = f"@@ -{_format_range(hunk.old_start, hunk.old_len)} +{_format_range(hunk.new_start, hunk.new_len)} @@"
    if hunk.heading:
        header += f" {hunk.heading}"
    out = [header]
    for line in hunk.lines:
        out.append(line.kind + line.text)
        if line.no_newline:
            out.append(NO_NEWLINE_MARK)
    return "\n".join(out) + "\n"


def render_patch(patches: Sequence[FilePatch]) -> str:
    """Render parsed file patches back to unified diff text."""
    out: list[str] = []
    for patch in patches:
        out.append(f"--- {patch.old_path}\n+++ {patch.new_path}\n")
        out.extend(render_hunk(hunk) for hunk in patch.hunks)
    return "".join(out)


def unified_diff(
    old_text: str,
    new_text: str,
    old_name: str = "a",
    new_name: str = "b",
    context: int = DEFAULT_CONTEXT,
    ignore_space: bool = False,
) -> str:
    """Return the unified diff turning ``old_text`` into ``new_text``.

    The result is empty when the texts are equal. With ``ignore_space`` runs of
    blanks and trailing blanks do not count as differences.
    """
    if context < 0:
        raise ValueError("context must not be negative")
    a, a_nl = split_text(old_text)
    a_keys = [_line_key(line, ignore_space) for line in a]
    if a_keys and not a_nl:
        a_keys[-1] += NO_EOL_KEY
    b, b_nl = split_text(new_text)
    b_keys = [_line_key(line, ignore_space) for line in b]
    if b_keys and not a_nl:
        b_keys[-1] += NO_EOL_KEY
    groups = group_opcodes(compute_opcodes(a_keys, b_keys), context)
    if not groups:
        return ""
    hunks = [_build_hunk(group, a, b, a_nl, b_nl) for group in groups]
    return render_patch([FilePatch(old_name, new_name, hunks)])


def _line_key(line: str, ignore_space: bool) -> str:
    if not ignore_space:
        return line
    return re.sub(r"[ \t]+", " ", line).strip()


def diff_stats(hunks: Sequence[Hunk]) -> tuple[int, int]:
    """Count added and removed lines across hunks."""
    added = sum(1 for h in hunks for line in h.lines if line.kind == "+")
    removed = sum(1 for h in hunks for line in h.lines if line.kind == "-")
    return added, removed


def _header_path(text: str) -> str:
    return text.split("\t")[0].strip()


def _is_body_line(lines: Sequence[str], index: int) -> bool:
    """True for a line that continues a hunk body rather than starting a new section."""
    text = lines[index]
    if text.startswith("--- ") and index + 1 < len(lines) and lines[index + 1].startswith("+++ "):
        return False
    return text not in ("-- ", "--") and text[:1] in (" ", "-", "+")


def _parse_hunk(lines: Sequence[str], index: int) -> tuple[Hunk, int]:
    match = HUNK_RE.match(lines[index])
    if match is None:
        raise PatchError(f"line {index + 1}: malformed hunk header", line=index + 1)
    old_len = 1 if match.group(2) is None else int(match.group(2))
    new_len = 1 if match.group(4) is None else int(match.group(4))
    hunk = Hunk(int(match.group(1)), old_len, int(match.group(3)), new_len, [], match.group(5) or "")
    old_seen = new_seen = 0
    index += 1
    while old_seen < old_len or new_seen < new_len:
        if index >= len(lines):
            raise PatchError(f"line {index}: hunk ends before its declared length", line=index)
        raw = lines[index]
        kind, text = (raw[:1], raw[1:]) if raw else (" ", "")
        if kind == "\\":
            if not hunk.lines:
                raise PatchError(f"line {index + 1}: marker before any hunk line", line=index + 1)
            hunk.lines[-1].no_newline = True
        elif kind in (" ", "-", "+"):
            old_seen += kind != "+"
            new_seen += kind != "-"
            hunk.lines.append(HunkLine(kind, text))
        else:
            raise PatchError(f"line {index + 1}: unexpected line in hunk", line=index + 1)
        index += 1
    while index < len(lines) and lines[index].startswith("\\") and hunk.lines:
        hunk.lines[-1].no_newline = True
        index += 1
    if index < len(lines) and _is_body_line(lines, index):
        raise PatchError(f"line {index + 1}: hunk body is longer than its header says", line=index + 1)
    if not hunk.lines:
        raise PatchError(f"line {index}: empty hunk", line=index)
    return hunk, index


def parse_unified(text: str) -> list[FilePatch]:
    """Parse unified diff text; lines outside file sections are ignored."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    patches: list[FilePatch] = []
    index = 0
    while index < len(lines):
        if lines[index].startswith("--- ") and index + 1 < len(lines) and lines[index + 1].startswith("+++ "):
            patch = FilePatch(_header_path(lines[index][4:]), _header_path(lines[index + 1][4:]))
            index += 2
            while index < len(lines) and lines[index].startswith("@@"):
                hunk, index = _parse_hunk(lines, index)
                patch.hunks.append(hunk)
            if not patch.hunks:
                raise PatchError(f"line {index}: file header without hunks", line=index)
            patches.append(patch)
        else:
            index += 1
    if not patches:
        raise PatchError("no file patches found")
    return patches


def reverse_hunk(hunk: Hunk) -> Hunk:
    """Swap the old and new sides of a hunk."""
    swapped = {" ": " ", "-": "+", "+": "-"}
    lines = [HunkLine(swapped[line.kind], line.text, line.no_newline) for line in hunk.lines]
    return Hunk(hunk.new_start, hunk.new_len, hunk.old_start, hunk.old_len, lines, hunk.heading)


def reverse_patch(patch: FilePatch) -> FilePatch:
    """Return the patch that undoes ``patch``."""
    return FilePatch(patch.new_path, patch.old_path, [reverse_hunk(h) for h in patch.hunks])


def _matches_at(lines: Sequence[str], block: Sequence[str], position: int) -> bool:
    return list(lines[position : position + len(block)]) == list(block)


def _locate(lines: Sequence[str], block: Sequence[str], target: int, floor: int, max_offset: int) -> Optional[int]:
    """Find where ``block`` matches, closest to ``target`` and not before ``floor``."""
    highest = len(lines) - len(block)
    if floor <= target <= highest and _matches_at(lines, block, target):
        return target
    for distance in range(1, max_offset + 1):
        for candidate in (target - distance, target + distance):
            if floor <= candidate <= highest and _matches_at(lines, block, candidate):
                return candidate
    return None


def apply_hunks(
    lines: Sequence[str],
    hunks: Sequence[Hunk],
    final_newline: bool = True,
    max_offset: int = DEFAULT_MAX_OFFSET,
) -> tuple[list[str], bool]:
    """Apply hunks in order; return the new lines and the final-newline flag."""
    result = list(lines)
    delta = 0
    drift = 0
    floor = 0
    last_old_start = -1
    new_final = final_newline
    for number, hunk in enumerate(hunks, start=1):
        old_side = [line for line in hunk.lines if line.kind != "+"]
        new_side = [line for line in hunk.lines if line.kind != "-"]
        old_block = [line.text for line in old_side]
        new_block = [line.text for line in new_side]
        expected = hunk.old_start - 1 if hunk.old_len else hunk.old_start
        if expected < last_old_start:
            raise PatchError(f"hunk {number} is out of order", hunk=number)
        last_old_start = expected
        position = _locate(result, old_block, expected + delta + drift, floor, max_offset)
        if position is None:
            raise PatchError(f"hunk {number} does not apply", hunk=number)
        if position + len(old_block) == len(result):
            if old_side and old_side[-1].no_newline == final_newline:
                raise PatchError(f"hunk {number}: end-of-file newline does not match", hunk=number)
            new_final = not new_side[-1].no_newline if new_side else True
        drift = position - (expected + delta)
        result[position : position + len(old_block)] = new_block
        delta += len(new_block) - len(old_block)
        floor = position + len(new_block)
    return result, new_final


def apply_file_patch(text: str, patch: FilePatch, max_offset: int = DEFAULT_MAX_OFFSET) -> str:
    """Apply one file patch to ``text`` and return the patched text."""
    lines, final_newline = split_text(text)
    new_lines, new_final = apply_hunks(lines, patch.hunks, final_newline, max_offset)
    return join_text(new_lines, new_final)


def apply_patch_text(text: str, patch_text: str, max_offset: int = DEFAULT_MAX_OFFSET) -> str:
    """Apply a diff that holds exactly one file patch."""
    patches = parse_unified(patch_text)
    if len(patches) != 1:
        raise PatchError(f"expected one file patch, found {len(patches)}")
    return apply_file_patch(text, patches[0], max_offset)


def strip_components(path: str, strip: int) -> str:
    """Drop the first ``strip`` directory components of a relative patch path."""
    if path.startswith("/"):
        raise PatchError(f"absolute path {path!r} in patch")
    parts = [part for part in path.split("/") if part not in ("", ".")]
    if strip > len(parts) - 1:
        raise PatchError(f"cannot strip {strip} components from {path!r}")
    return "/".join(parts[strip:])


def safe_join(root: Path, relative: str) -> Path:
    """Join a relative path to ``root``, refusing anything that escapes it."""
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts or "\\" in relative or ":" in relative:
        raise PatchError(f"unsafe path {relative!r}")
    target = root.joinpath(*pure.parts)
    if not target.resolve().is_relative_to(root.resolve()):
        raise PatchError(f"path {relative!r} leaves the tree")
    return target


def _target_path(patch: FilePatch, strip: int) -> str:
    chosen = patch.old_path if patch.new_path == DEV_NULL else patch.new_path
    return strip_components(chosen, strip)


def apply_to_tree(
    root: Path,
    patches: Sequence[FilePatch],
    *,
    strip: int = 1,
    dry_run: bool = False,
    reverse: bool = False,
) -> list[FileResult]:
    """Apply file patches below ``root``; nothing is written if any fails."""
    pending: dict[Path, Optional[str]] = {}
    results: list[FileResult] = []
    for patch in patches:
        if reverse:
            patch = reverse_patch(patch)
        rel = _target_path(patch, strip)
        path = safe_join(root, rel)
        if path in pending:
            raise PatchError(f"{rel} is patched twice")
        creating = patch.old_path == DEV_NULL
        deleting = patch.new_path == DEV_NULL
        if creating:
            if path.exists():
                raise PatchError(f"{rel} already exists")
            original = ""
        else:
            if not path.is_file():
                raise PatchError(f"{rel} does not exist")
            with path.open(encoding="utf-8", newline="") as handle:
                original = handle.read()
        updated = apply_file_patch(original, patch)
        if deleting and updated != "":
            raise PatchError(f"{rel} is not empty after the patch")
        pending[path] = None if deleting else updated
        added, removed = diff_stats(patch.hunks)
        action = "create" if creating else "delete" if deleting else "modify"
        results.append(FileResult(rel, action, added, removed))
    if not dry_run:
        for path, content in pending.items():
            if content is None:
                path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8", newline="")
    return results
