"""Client-side context for the Tile Sieve planner: an outline index, def-use
partners (``ast`` for Python, regex elsewhere) and the specification passages
a request shows.

No request is made here. Every output is plain, deterministic data.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import json
import re
import warnings

from .core import Span
from .handoff import passages

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_WORD = re.compile(r"[A-Za-z][a-z]+|[A-Z]+(?![a-z])|[0-9]+")
_DEF_RE = re.compile(r"^\s*(?:export\s+|public\s+|private\s+|static\s+|async\s+)*"
                     r"(?:function|def|class|func|fn|sub|struct|interface|enum|type|trait)\s+"
                     r"([A-Za-z_][A-Za-z0-9_]*)")
_CONST_RE = re.compile(r"^([A-Z][A-Z0-9_]{2,})\s*[:=]")
_KEYWORDS = frozenset("""False None True and as assert async await break class continue def del elif else
except finally for from global if import in is lambda nonlocal not or pass raise return try while with
yield self cls int str float bool list dict set tuple len range print isinstance super object type
function var let const new this void null undefined""".split())
MAX_SIG = 160
MAX_DOC = 100


@dataclass(frozen=True)
class Def:
    name: str
    kind: str
    start: int
    end: int
    signature: str
    doc: str


class CodeIndex:
    """Outline, identifier uses and def-use partners for one file."""

    def __init__(self, lines, name="subject.py"):
        self.lines = tuple(lines)
        self.n = len(self.lines)
        self.name = name
        self.defs: list[Def] = []
        self._uses: dict = {}          # name -> sorted list of lines where it is used
        self._line_idents: dict = {}   # line -> set of identifiers used on that line
        parsed = False
        if name.endswith(".py"):
            parsed = self._build_python()
        if not parsed:
            self._build_regex()
        self.defs.sort(key=lambda d: (d.start, d.end, d.name))
        self._by_name: dict = {}
        for d in self.defs:
            self._by_name.setdefault(d.name, []).append(d)

    # -- construction -----------------------------------------------------
    def _add_use(self, ident, line):
        if ident in _KEYWORDS or not 1 <= line <= self.n:
            return
        self._uses.setdefault(ident, set()).add(line)
        self._line_idents.setdefault(line, set()).add(ident)

    def _finish_uses(self):
        self._uses = {k: sorted(v) for k, v in self._uses.items()}

    def _build_python(self):
        text = "\n".join(self.lines)
        try:
            # A warning (an invalid escape sequence, say) must neither reach stderr nor, under
            # -W error, turn a valid file into a SyntaxError and so change the index.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return False
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start = node.lineno
                end = getattr(node, "end_lineno", start) or start
                body_first = node.body[0].lineno if node.body else start
                sig_end = max(start, body_first - 1)
                sig = " ".join(line.strip() for line in self.lines[start - 1:min(sig_end, start + 5)])
                doc = (ast.get_docstring(node) or "").strip().splitlines()
                self.defs.append(Def(node.name,
                                     "class" if isinstance(node, ast.ClassDef) else "def",
                                     start, end, sig[:MAX_SIG], (doc[0] if doc else "")[:MAX_DOC]))
            elif isinstance(node, ast.Assign) and node.col_offset == 0:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        end = getattr(node, "end_lineno", node.lineno) or node.lineno
                        self.defs.append(Def(target.id, "var", node.lineno, end,
                                             self.lines[node.lineno - 1].strip()[:MAX_SIG], ""))
            if isinstance(node, ast.Name):
                self._add_use(node.id, node.lineno)
            elif isinstance(node, ast.Attribute):
                self._add_use(node.attr, getattr(node, "end_lineno", node.lineno) or node.lineno)
        self._finish_uses()
        return True

    def _build_regex(self):
        starts = []
        for i, line in enumerate(self.lines, 1):
            m = _DEF_RE.match(line)
            if m:
                starts.append((i, m.group(1), line))
            else:
                c = _CONST_RE.match(line)
                if c:
                    self.defs.append(Def(c.group(1), "var", i, i, line.strip()[:MAX_SIG], ""))
        for k, (i, nm, line) in enumerate(starts):
            end = (starts[k + 1][0] - 1) if k + 1 < len(starts) else self.n
            while end > i and not self.lines[end - 1].strip():
                end -= 1
            self.defs.append(Def(nm, "def", i, max(i, end), line.strip()[:MAX_SIG], ""))
        defining = {d.start for d in self.defs}
        for i, line in enumerate(self.lines, 1):
            if i in defining and _DEF_RE.match(line):
                continue
            for ident in _IDENT.findall(line):
                self._add_use(ident, i)
        self._finish_uses()

    # -- queries ------------------------------------------------------------
    def idents_in(self, lo, hi):
        """Identifier -> number of lines of [lo, hi] that use it."""
        out: dict = {}
        for line in range(max(1, lo), min(self.n, hi) + 1):
            for ident in sorted(self._line_idents.get(line, ())):     # sorted: hash-seed independent
                out[ident] = out.get(ident, 0) + 1
        return out

    def uses_of(self, name):
        return self._uses.get(name, [])

    def defs_of(self, name):
        return self._by_name.get(name, [])

    def partners(self, lo, hi, halo, max_lines=80, per_partner=None):
        """Def-use partners of K = [lo, hi]: spans outside K +- halo, nearest first.

        Definitions of names used in K, and use sites of names defined in K.
        Returns [(distance, Span, label)]; the total line count is capped by
        *max_lines* (the list is cut at the first partner that no longer fits)."""
        shown = (max(1, lo - halo), min(self.n, hi + halo))
        found: dict = {}
        for ident in self.idents_in(lo, hi):
            for d in self.defs_of(ident):
                if shown[0] <= d.start <= shown[1] or d.end < 1:
                    continue
                if d.start <= hi and d.end >= lo:
                    continue
                span = (d.start, min(d.end, d.start + (per_partner or 40) - 1))
                found[span] = (min(abs(d.start - hi), abs(d.start - lo)), "def " + d.name)
        for d in self.defs:
            if d.end < lo or d.start > hi:
                continue
            for use in self.uses_of(d.name):
                if shown[0] <= use <= shown[1]:
                    continue
                if d.start <= use <= d.end:
                    continue
                span = (max(1, use - 1), min(self.n, use + 1))
                found.setdefault(span, (min(abs(use - hi), abs(use - lo)), "use " + d.name))
        ordered = sorted(found.items(), key=lambda kv: (kv[1][0], kv[0]))
        out, total = [], 0
        for (a, b), (dist, label) in ordered:
            size = b - a + 1
            if per_partner is not None and size > per_partner:
                b = a + per_partner - 1
                size = per_partner
            if total + size > max_lines:
                break
            out.append((dist, Span(a, b), label))
            total += size
        return out


def nearest_defs(index, lo, hi, count=2):
    """Fallback partners when need_context fired but no edge crosses K: the nearest defs."""
    outside = [d for d in index.defs if d.end < lo or d.start > hi]
    outside.sort(key=lambda d: min(abs(d.start - hi), abs(d.start - lo)))
    return [(min(abs(d.start - hi), abs(d.start - lo)), Span(d.start, min(d.end, d.start + 39)),
             "def " + d.name) for d in outside[:count]]


# -- specification passages -----------------------------------------------------------

def _entry_json(entry):
    return json.dumps(entry, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def spec_passages(spec_lines):
    """DBH's own passage splitter (handoff.passages): nonblank blocks, windows of 8."""
    if not spec_lines:
        return []
    return list(passages(tuple(spec_lines), Span(1, len(spec_lines))))


def words(text):
    out = set()
    for w in _WORD.findall(text):
        w = w.lower()
        if len(w) >= 3:
            out.add(w)
    return out


def ident_words(idents):
    out: set = set()
    for ident in idents:
        out |= words(ident.replace("_", " "))
    return out


def passage_score(spec_lines, passage, code_words):
    text = " ".join(spec_lines[passage.start - 1:passage.end])
    return len(words(text) & code_words)


def spec_slice(spec_lines, code_idents, budget, *, k_words=None, linked_only=False):
    """The spec lines handed to a request: highest-scoring passages first, whole,
    until *budget* bytes of {"line","text"} JSON are used; returned in line order.

    Returns (entries, passages_kept). With *linked_only*, each kept passage is cut
    to its lines that share a word with the code (the sentences linked to K).
    """
    found = spec_passages(spec_lines)
    if not found:
        return [], []
    code_words = ident_words(code_idents) if k_words is None else k_words
    scored = sorted(((passage_score(spec_lines, p, code_words), p.start, p) for p in found),
                    key=lambda t: (-t[0], t[1]))
    chosen, lines, size = [], {}, 2
    for _score, _start, p in scored:
        picks = list(range(p.start, p.end + 1))
        if linked_only:
            linked = [i for i in picks if words(spec_lines[i - 1]) & code_words]
            picks = linked or picks[:1]
        add = {i: {"line": i, "text": spec_lines[i - 1]} for i in picks if i not in lines}
        cost = sum(len(_entry_json(e)) + 1 for e in add.values())
        if size + cost > budget:
            if not chosen:
                # a single passage larger than the budget: keep the lines that fit
                for i, e in sorted(add.items()):
                    c = len(_entry_json(e)) + 1
                    if size + c > budget:
                        break
                    lines[i] = e
                    size += c
                if lines:
                    chosen.append(p)
            continue
        lines.update(add)
        size += cost
        chosen.append(p)
    return [lines[i] for i in sorted(lines)], sorted(chosen, key=lambda p: p.start)
