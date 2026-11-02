# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 NamiQ LLC
"""Read what a project DECLARES it depends on: requirements*.txt, pyproject.toml, package.json, Dockerfile*, docker-compose / compose files.

Standard library only (tomllib when the interpreter has it; a small reader for the few pyproject tables that matter when it does not).

Every component keeps the file and line it came from and the exact text that declared it. Only a pinned version (`==1.2.3`, a Docker tag like `16.2`, a bare
`1.2.3` in package.json) is reported as a version. A range or `latest` or no tag is reported as what it is, unpinned: it is never turned into a number,
because a declared `>=1.0` says nothing about what is installed. Nothing here talks to the network and nothing is executed.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

try:  # Python 3.11+
    import tomllib
except ImportError:  # 3.9 / 3.10
    tomllib = None  # type: ignore[assignment]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache", ".next", "dist", "build", "site-packages", ".impl-worktrees", ".claude", "runtime", "workspace"}
MAX_FILES = 400
MAX_BYTES = 2_000_000


@dataclass
class Component:
    name: str            # as the ecosystem names it, lower case
    ecosystem: str       # pypi | npm | image | apt
    spec: str            # exactly what was declared: "==2.1.0", "^4.2", "postgres:16.2", ""
    version: str | None  # only when the declaration pins one
    file: str            # path relative to the scanned root
    line: int


def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def parse_requirement(text: str) -> tuple[str, str, str | None] | None:
    """('name', 'spec as written', pinned version or None) for one PEP 508 requirement string, or None when it is not a plain named requirement."""
    text = text.split(";", 1)[0].split(" #", 1)[0].strip()   # environment markers and trailing comments are not part of the version
    if not text or text.startswith(("-", "git+", "http://", "https://", ".", "/")) or "@" in text.split("==")[0]:
        return None
    m = _REQ.match(text)
    if not m:
        return None
    name, rest = m.group(1), m.group(3).replace(" ", "")
    pin = re.fullmatch(r"===?(\d+(?:\.\d+)*(?:[A-Za-z0-9.+!_-]*))", rest)
    version = pin.group(1) if pin and "*" not in rest else None
    return _norm_py(name), rest, version


def requirements_txt(path: Path, root: Path, _seen: set | None = None) -> list[Component]:
    seen = _seen if _seen is not None else set()
    if path.resolve() in seen:
        return []
    seen.add(path.resolve())
    out: list[Component] = []
    lines = path.read_text(errors="replace").splitlines()
    i = 0
    while i < len(lines):
        raw, ln = lines[i], i + 1
        while raw.rstrip().endswith("\\") and i + 1 < len(lines):   # a continuation (typically --hash=...) belongs to the same requirement
            i += 1
            raw = raw.rstrip()[:-1] + " " + lines[i]
        i += 1
        s = raw.strip()
        if s.startswith(("-r ", "--requirement ")):
            inc = (path.parent / s.split(None, 1)[1].strip()).resolve()
            if inc.is_file() and inc.is_relative_to(root.resolve()):
                out += requirements_txt(inc, root, seen)
            continue
        r = parse_requirement(re.split(r"\s--", s, 1)[0])
        if r:
            out.append(Component(r[0], "pypi", r[1], r[2], str(path.relative_to(root)), ln))
    return out


def _line_of(text: str, needle: str) -> int:
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 0


def _toml(text: str) -> dict:
    if tomllib is not None:
        try:
            return tomllib.loads(text)
        except Exception:
            return {}
    # 3.9 / 3.10: only the tables that carry dependencies, read with patterns. Good enough to find them; never used to rewrite anything.
    d: dict = {"project": {}, "tool": {"poetry": {}}}
    m = re.search(r"^\[project\]\s*$(.*?)(?=^\[|\Z)", text, re.S | re.M)
    if m:
        a = re.search(r"^dependencies\s*=\s*\[(.*?)\]", m.group(1), re.S | re.M)
        if a:
            d["project"]["dependencies"] = re.findall(r'"([^"]+)"|\'([^\']+)\'', a.group(1)) and [x or y for x, y in re.findall(r'"([^"]+)"|\'([^\']+)\'', a.group(1))]
    m = re.search(r"^\[project\.optional-dependencies\]\s*$(.*?)(?=^\[|\Z)", text, re.S | re.M)
    if m:
        d["project"]["optional-dependencies"] = {k: [x or y for x, y in re.findall(r'"([^"]+)"|\'([^\']+)\'', v)]
                                                 for k, v in re.findall(r"^([A-Za-z0-9_.-]+)\s*=\s*\[(.*?)\]", m.group(1), re.S | re.M)}
    m = re.search(r"^\[tool\.poetry\.dependencies\]\s*$(.*?)(?=^\[|\Z)", text, re.S | re.M)
    if m:
        deps = {}
        for k, v in re.findall(r'^([A-Za-z0-9_.-]+)\s*=\s*(.+)$', m.group(1), re.M):
            vm = re.search(r'version\s*=\s*"([^"]+)"', v) or re.match(r'\s*"([^"]+)"', v)
            deps[k] = vm.group(1) if vm else ""
        d["tool"]["poetry"]["dependencies"] = deps
    return d


def pyproject_toml(path: Path, root: Path) -> list[Component]:
    text = path.read_text(errors="replace")
    d = _toml(text)
    rel = str(path.relative_to(root))
    out: list[Component] = []
    reqs = list((d.get("project") or {}).get("dependencies") or [])
    for grp in ((d.get("project") or {}).get("optional-dependencies") or {}).values():
        reqs += list(grp)
    for g in ((d.get("dependency-groups") or {}).values()):
        reqs += [x for x in g if isinstance(x, str)]
    for r in (d.get("build-system") or {}).get("requires") or []:
        reqs.append(r)
    for s in reqs:
        p = parse_requirement(s)
        if p:
            out.append(Component(p[0], "pypi", p[1], p[2], rel, _line_of(text, s.split(";")[0].strip()[:40])))
    for name, spec in (((d.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}).items():
        if name.lower() == "python":
            continue
        if isinstance(spec, dict):
            spec = spec.get("version", "")
        spec = str(spec).strip()
        pinned = spec if re.fullmatch(r"\d+(\.\d+)*", spec) else None   # poetry reads a bare version as exact; ^ ~ * and ranges are not pins
        out.append(Component(_norm_py(name), "pypi", ("==" + spec) if pinned else spec, pinned, rel, _line_of(text, name)))
    return out


def package_json(path: Path, root: Path) -> list[Component]:
    try:
        d = json.loads(path.read_text(errors="replace"))
    except ValueError:
        return []
    text = path.read_text(errors="replace")
    out = []
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (d.get(key) or {}).items():
            spec = str(spec).strip()
            pinned = spec.lstrip("=v") if re.fullmatch(r"=?v?\d+(\.\d+)*", spec) else None
            out.append(Component(name.lower(), "npm", spec, pinned, str(path.relative_to(root)), _line_of(text, f'"{name}"')))
    return out


def package_lock(path: Path, root: Path) -> list[Component]:
    """package-lock.json (lockfileVersion 2/3): every resolved package with its exact version. The lockfile is what is actually installed, so it pins what package.json only ranges."""
    try:
        d = json.loads(path.read_text(errors="replace"))
    except ValueError:
        return []
    rel = str(path.relative_to(root))
    out = []
    for key, v in (d.get("packages") or {}).items():
        if not key or not isinstance(v, dict) or not v.get("version") or v.get("link"):
            continue
        name = v.get("name") or key.rsplit("node_modules/", 1)[-1]
        out.append(Component(name.lower(), "npm", "==" + str(v["version"]), str(v["version"]), rel, 0))
    return out


def _image(ref: str, ecosystem_file: str, line: int, args: dict[str, str]) -> Component | None:
    ref = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}", lambda m: args.get(m.group(1), m.group(2) or m.group(0)), ref.strip().strip("\"'"))
    if not ref or ref == "scratch" or "$" in ref:
        return None
    ref = ref.split("@", 1)[0]
    name, _, tag = ref.rpartition(":") if ":" in ref.rsplit("/", 1)[-1] else (ref, "", "")
    base = name.rsplit("/", 1)[-1].lower()
    pinned = tag if re.fullmatch(r"v?\d+(\.\d+)*", tag) else None   # 16.2 and v1.4 pin a version; 16-alpine, latest, a digest do not
    return Component(base, "image", ref, pinned.lstrip("v") if pinned else None, ecosystem_file, line)


def dockerfile(path: Path, root: Path) -> list[Component]:
    rel = str(path.relative_to(root))
    out: list[Component] = []
    args: dict[str, str] = {}
    stages: set[str] = set()
    lines = path.read_text(errors="replace").splitlines()
    i = 0
    while i < len(lines):
        ln = i + 1
        raw = lines[i]
        while raw.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            raw = raw.rstrip()[:-1] + " " + lines[i]
        i += 1
        s = raw.strip()
        up = s.upper()
        if up.startswith("ARG "):
            k, _, v = s[4:].partition("=")
            args[k.strip()] = v.strip().strip("\"'")
        elif up.startswith("FROM "):
            toks = [t for t in s.split()[1:] if not t.startswith("--")]
            if toks:
                if toks[0] not in stages:
                    c = _image(toks[0], rel, ln, args)
                    if c:
                        out.append(c)
                if len(toks) >= 3 and toks[1].upper() == "AS":
                    stages.add(toks[2])
        elif up.startswith("RUN "):
            for m in re.finditer(r"pip3?\s+install\s+([^&|;]+)", s):
                for tok in m.group(1).split():
                    if tok.startswith("-"):
                        continue
                    p = parse_requirement(tok)
                    if p:
                        out.append(Component(p[0], "pypi", p[1], p[2], rel, ln))
            for m in re.finditer(r"apt(?:-get)?\s+install\s+([^&|;]+)", s):
                for tok in m.group(1).split():
                    if tok.startswith("-") or tok.startswith("$"):
                        continue
                    name, _, ver = tok.partition("=")
                    out.append(Component(name.lower(), "apt", ("=" + ver) if ver else "", ver or None, rel, ln))
    return out


def compose_file(path: Path, root: Path) -> list[Component]:
    rel = str(path.relative_to(root))
    out = []
    for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        m = re.match(r"^\s*image:\s*(.+?)\s*(?:#.*)?$", line)
        if m:
            c = _image(m.group(1), rel, n, {})
            if c:
                out.append(c)
    return out


def find_manifests(root: Path) -> tuple[list[Path], bool]:
    """(manifest files under root, whether the search stopped at MAX_FILES). Vendored and generated trees are skipped; a cut is reported, never silent."""
    found: list[Path] = []
    stack = [root]
    cut = False
    while stack:
        if len(found) >= MAX_FILES:
            cut = True
            break
        d = stack.pop()
        try:
            entries = sorted(d.iterdir())
        except OSError:
            continue
        for p in entries:
            if p.is_symlink():
                continue
            if p.is_dir():
                if p.name not in SKIP_DIRS and not p.name.startswith(".next"):
                    stack.append(p)
                continue
            n = p.name.lower()
            if (re.fullmatch(r"requirements[\w.-]*\.(txt|lock)", n) or n in ("pyproject.toml", "package.json", "package-lock.json") or n == "dockerfile" or n.startswith("dockerfile.")
                    or n.endswith(".dockerfile") or re.fullmatch(r"(docker-)?compose[\w.-]*\.ya?ml", n)):
                try:
                    if p.stat().st_size <= MAX_BYTES:
                        found.append(p)
                except OSError:
                    pass
    return sorted(found), cut


def read_project(root: Path) -> tuple[list[Component], list[str], bool]:
    """(components, files read, whether the file search was cut at MAX_FILES) for everything declared under root. A file that cannot be read is skipped, never fatal."""
    root = root.resolve()
    comps: list[Component] = []
    files: list[str] = []
    included: set[Path] = set()
    paths, cut = find_manifests(root)
    for p in paths:
        n = p.name.lower()
        try:
            if n.endswith((".txt", ".lock")):
                if p.resolve() in included:
                    continue
                got = requirements_txt(p, root, included)
            elif n == "pyproject.toml":
                got = pyproject_toml(p, root)
            elif n == "package.json":
                got = package_json(p, root)
            elif n == "package-lock.json":
                got = package_lock(p, root)
            elif "compose" in n:
                got = compose_file(p, root)
            else:
                got = dockerfile(p, root)
        except (OSError, UnicodeError):
            continue
        files.append(str(p.relative_to(root)))
        comps += got
    return comps, files, cut
