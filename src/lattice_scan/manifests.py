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

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache", ".next", "dist", "build", "site-packages", ".impl-worktrees", ".claude", "runtime", "workspace", "target", ".gradle", "cmake-build-debug", "cmake-build-release"}
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


def _split_top(s: str, sep: str = ",") -> list[str]:
    """Split on sep outside quotes and brackets."""
    out, depth, q, cur = [], 0, "", ""
    i = 0
    while i < len(s):
        ch = s[i]
        if q:
            cur += ch
            if ch == "\\" and q == '"' and i + 1 < len(s):
                cur += s[i + 1]
                i += 1
            elif ch == q:
                q = ""
        elif ch in "\"'":
            q = ch
            cur += ch
        elif ch in "[{":
            depth += 1
            cur += ch
        elif ch in "]}":
            depth -= 1
            cur += ch
        elif ch == sep and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
        i += 1
    if cur.strip():
        out.append(cur)
    return out


def _unquote_key(k: str) -> str:
    k = k.strip()
    return k[1:-1] if len(k) >= 2 and k[0] == k[-1] and k[0] in "\"'" else k


def _toml_value(v: str):
    v = v.strip()
    if v[:1] == '"' and v.endswith('"') and len(v) >= 2:
        return v[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    if v[:1] == "'" and v.endswith("'") and len(v) >= 2:
        return v[1:-1]
    if v.startswith("[") and v.endswith("]"):
        return [_toml_value(x) for x in _split_top(v[1:-1]) if x.strip()]
    if v.startswith("{") and v.endswith("}"):
        d: dict = {}
        for pair in _split_top(v[1:-1]):
            k, _, val = pair.partition("=")
            _set_path(d, [_unquote_key(x) for x in _split_top(k.strip(), ".")], _toml_value(val))
        return d
    if v in ("true", "false"):
        return v == "true"
    try:
        return int(v)
    except ValueError:
        try:
            return float(v)
        except ValueError:
            return v


def _set_path(d: dict, path: list[str], value) -> None:
    for k in path[:-1]:
        nxt = d.setdefault(k, {})
        d = nxt if isinstance(nxt, dict) else {}
    d[path[-1]] = value


def _strip_comment(line: str) -> str:
    q = ""
    for i, ch in enumerate(line):
        if q:
            if ch == q:
                q = ""
        elif ch in "\"'":
            q = ch
        elif ch == "#":
            return line[:i]
    return line


def _mini_toml(text: str) -> dict:
    """The part of TOML that dependency files use, for Pythons without tomllib (3.9, 3.10): tables, dotted keys, strings, numbers, booleans, arrays (also over several lines) and inline tables.
    Not a validator: a line it does not understand is skipped, which for this tool means a dependency not listed, never a wrong one."""
    root: dict = {}
    cur = root
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = _strip_comment(lines[i]).strip()
        i += 1
        if not line:
            continue
        if line.startswith("[["):
            cur = {}            # an array of tables ([[package]]): not needed for dependency declarations
            continue
        if line.startswith("["):
            path = [_unquote_key(x) for x in _split_top(line.strip().strip("[]"), ".")]
            cur = root
            for k in path:
                nxt = cur.setdefault(k, {})
                cur = nxt if isinstance(nxt, dict) else {}
            continue
        k, eq, v = line.partition("=")
        if not eq:
            continue
        v = v.strip()
        while (v.count("[") + v.count("{") > v.count("]") + v.count("}")) and i < len(lines):
            v += " " + _strip_comment(lines[i]).strip()
            i += 1
        _set_path(cur, [_unquote_key(x) for x in _split_top(k.strip(), ".")], _toml_value(v))
    return root


def _toml(text: str) -> dict:
    if tomllib is not None:
        try:
            return tomllib.loads(text)
        except Exception:
            return {}
    return _mini_toml(text)


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
    # 16.2 and v1.4.1-alpine pin a version (two or more numbers, any suffix after a dash); 16, 16-alpine, latest and a digest float, so they are not versions.
    m = re.fullmatch(r"v?(\d+(?:\.\d+)+)(?:[-_+][A-Za-z0-9._-]*)?", tag)
    pinned = m.group(1) if m else None
    return Component(base, "image", ref, pinned, ecosystem_file, line)


_TARBALL = re.compile(r"([A-Za-z][A-Za-z0-9_+]*(?:-[A-Za-z][A-Za-z0-9_+]*)*)[-_]v?(\d+(?:\.\d+)+)\.(?:tar\.(?:gz|xz|bz2|zst)|tgz|zip)\b")


def tarballs(text: str, eco: str, rel: str, line: int) -> list[Component]:
    """'zlib-1.2.13.tar.gz' in a download command or URL: a name and a version that were actually written down."""
    return [Component(m.group(1).lower(), eco, m.group(0), m.group(2), rel, line) for m in _TARBALL.finditer(text)]


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
            out += tarballs(s, "c", rel, ln)
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


def _xml_text(el, tag: str) -> str:
    for c in el:
        if c.tag.rsplit("}", 1)[-1] == tag:
            return (c.text or "").strip()
    return ""


def pom_xml(path: Path, root: Path) -> list[Component]:
    """pom.xml: dependencies and dependencyManagement, `${property}` resolved from <properties> (and the parent's version for ${project.version}); an unresolved property is no version."""
    import xml.etree.ElementTree as ET
    try:
        tree = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return []
    rel = str(path.relative_to(root))
    props = {"project.version": _xml_text(tree, "version")}
    for el in tree:
        if el.tag.rsplit("}", 1)[-1] == "properties":
            for p in el:
                props[p.tag.rsplit("}", 1)[-1]] = (p.text or "").strip()
    out = []
    for dep in tree.iter():
        if dep.tag.rsplit("}", 1)[-1] != "dependency":
            continue
        g, a, v = _xml_text(dep, "groupId"), _xml_text(dep, "artifactId"), _xml_text(dep, "version")
        if not a:
            continue
        v = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v)
        pinned = v if re.fullmatch(r"\d+(\.\d+)*([.-][A-Za-z0-9]+)*", v) and "$" not in v else None
        out.append(Component(f"{g}:{a}".lower() if g else a.lower(), "maven", v, pinned, rel, 0))
    return out


_GRADLE_DEP = re.compile(r"""(?:implementation|api|compile|compileOnly|runtimeOnly|testImplementation|testCompile|testRuntimeOnly|annotationProcessor|kapt|classpath|developmentOnly)\s*\(?\s*["']([\w.-]+):([\w.-]+)(?::([^"'):@]+))?""")


def gradle_build(path: Path, root: Path) -> list[Component]:
    rel = str(path.relative_to(root))
    out = []
    for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        for m in _GRADLE_DEP.finditer(line):
            v = (m.group(3) or "").strip()
            pinned = v if re.fullmatch(r"\d+(\.\d+)*([.-][A-Za-z0-9]+)*", v) else None
            out.append(Component(f"{m.group(1)}:{m.group(2)}".lower(), "maven", v, pinned, rel, n))
    return out


def gradle_lockfile(path: Path, root: Path) -> list[Component]:
    rel = str(path.relative_to(root))
    out = []
    for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        m = re.match(r"^([\w.-]+):([\w.-]+):([^=\s]+)=", line)
        if m:
            out.append(Component(f"{m.group(1)}:{m.group(2)}".lower(), "maven", m.group(3), m.group(3), rel, n))
    return out


def gradle_catalog(path: Path, root: Path) -> list[Component]:
    """gradle/libs.versions.toml: [versions] and [libraries] (module = "g:a", version or version.ref)."""
    text = path.read_text(errors="replace")
    d = _toml(text)
    versions = {k: (v if isinstance(v, str) else (v or {}).get("require") or (v or {}).get("strictly") or "") for k, v in (d.get("versions") or {}).items()}
    rel = str(path.relative_to(root))
    out = []
    for name, lib in (d.get("libraries") or {}).items():
        if isinstance(lib, str):
            g, _, rest = lib.partition(":")
            a, _, v = rest.partition(":")
        else:
            mod = lib.get("module") or f"{lib.get('group', '')}:{lib.get('name', '')}"
            g, _, a = mod.partition(":")
            ver = lib.get("version")
            v = versions.get((ver or {}).get("ref", ""), "") if isinstance(ver, dict) else (ver or "")
        if a:
            pinned = v if re.fullmatch(r"\d+(\.\d+)*([.-][A-Za-z0-9]+)*", v or "") else None
            out.append(Component(f"{g}:{a}".lower(), "maven", v, pinned, rel, _line_of(text, name)))
    return out


def cargo_toml(path: Path, root: Path) -> list[Component]:
    text = path.read_text(errors="replace")
    rel = str(path.relative_to(root))
    d = _toml(text)
    out = []

    def tables(node: dict):
        for k, v in node.items():
            if k in ("dependencies", "dev-dependencies", "build-dependencies") and isinstance(v, dict):
                yield v
            elif k == "workspace" and isinstance(v, dict):
                if isinstance(v.get("dependencies"), dict):
                    yield v["dependencies"]
            elif k == "target" and isinstance(v, dict):
                for t in v.values():
                    if isinstance(t, dict):
                        yield from tables(t)
    for tbl in tables(d):
        for name, spec in tbl.items():
            if isinstance(spec, dict):
                if "path" in spec or "git" in spec:
                    continue
                spec = spec.get("version", "")
            spec = str(spec).strip()
            pinned = spec[1:].strip() if spec.startswith("=") and re.fullmatch(r"\d+(\.\d+)*([-+][A-Za-z0-9.]+)?", spec[1:].strip()) else None   # a bare 1.2.3 in Cargo means ^1.2.3
            out.append(Component(name.lower(), "cargo", spec, pinned, rel, _line_of(text, name)))
    return out


def cargo_lock(path: Path, root: Path) -> list[Component]:
    text = path.read_text(errors="replace")
    rel = str(path.relative_to(root))
    return [Component(m.group(1).lower(), "cargo", "==" + m.group(2), m.group(2), rel, text.count("\n", 0, m.start()) + 1)
            for m in re.finditer(r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text)]


def conanfile(path: Path, root: Path) -> list[Component]:
    rel = str(path.relative_to(root))
    out = []
    sect = ""
    for n, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        s = line.split("#", 1)[0].strip()
        if path.suffix == ".py":
            refs = re.findall(r"""requires\s*(?:=|\()\s*\[?\s*["']([^"'\s]+)["']""", s) + re.findall(r"""["']([A-Za-z][\w.+-]*/[^"'\s@]+)(?:@[^"']*)?["']""", s if "requires" in s or "tool_requires" in s else "")
        else:
            if s.startswith("["):
                sect = s.strip("[]").lower()
                continue
            refs = [s.split("@", 1)[0]] if sect in ("requires", "tool_requires", "build_requires") and "/" in s else []
        for ref in refs:
            name, _, ver = ref.partition("/")
            ver = ver.split("@", 1)[0].strip()
            pinned = ver if re.fullmatch(r"\d+(\.\d+)*([.-][A-Za-z0-9]+)*", ver) else None
            if name:
                out.append(Component(name.lower(), "conan", ver, pinned, rel, n))
    return out


def vcpkg_json(path: Path, root: Path) -> list[Component]:
    try:
        d = json.loads(path.read_text(errors="replace"))
    except ValueError:
        return []
    rel = str(path.relative_to(root))
    overrides = {o.get("name"): o.get("version") or o.get("version-string") or o.get("version-semver") or "" for o in d.get("overrides", []) if isinstance(o, dict)}
    out = []
    for dep in d.get("dependencies", []):
        name = dep if isinstance(dep, str) else dep.get("name", "")
        if not name:
            continue
        floor = "" if isinstance(dep, str) else dep.get("version>=", "")
        ver = overrides.get(name, "")
        pinned = ver if re.fullmatch(r"\d+(\.\d+)*([.-][A-Za-z0-9]+)*", ver or "") else None
        out.append(Component(name.lower(), "vcpkg", (("==" + ver) if pinned else (">=" + floor if floor else "")), pinned, rel, 0))
    return out


_CMAKE_CMD = re.compile(r"(?is)\b(find_package|FetchContent_Declare|ExternalProject_Add|CPMAddPackage|CPMFindPackage|pkg_check_modules|pkg_search_module)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)")
_LIBNAME = {"ssl": "openssl", "crypto": "openssl", "z": "zlib", "xml2": "libxml2", "png": "libpng", "png16": "libpng", "jpeg": "libjpeg", "sqlite3": "sqlite",
            "curl": "curl", "yaml": "libyaml", "expat": "expat", "bz2": "bzip2", "lzma": "xz", "zstd": "zstd", "pcre": "pcre", "pcre2-8": "pcre2", "gcrypt": "libgcrypt",
            "gnutls": "gnutls", "tiff": "libtiff", "freetype": "freetype", "protobuf": "protobuf", "boost_system": "boost", "ffi": "libffi", "event": "libevent"}


def cmake_file(path: Path, root: Path) -> list[Component]:
    """CMakeLists.txt / *.cmake: find_package(Name 1.2 [EXACT]), FetchContent_Declare / ExternalProject_Add (GIT_TAG, URL), CPMAddPackage, pkg_check_modules. Only what is written."""
    text = re.sub(r"(?m)#.*$", "", path.read_text(errors="replace"))
    rel = str(path.relative_to(root))
    out = []
    for m in _CMAKE_CMD.finditer(text):
        cmd, body = m.group(1).lower(), " ".join(m.group(2).split())
        ln = text.count("\n", 0, m.start()) + 1
        toks = body.split()
        if cmd == "find_package" and toks:
            ver = toks[1] if len(toks) > 1 and re.fullmatch(r"\d+(\.\d+)*", toks[1]) else ""
            exact = "EXACT" in toks
            out.append(Component(toks[0].lower(), "cmake", (("==" if exact else ">=") + ver) if ver else "", ver if (ver and exact) else None, rel, ln))
        elif cmd in ("pkg_check_modules", "pkg_search_module"):
            for t in toks[2:] if len(toks) > 2 else []:
                pm = re.match(r"^([A-Za-z0-9_.+-]+)\s*(?:(>=|=|<=|>|<)\s*(\d[\w.]*))?$", t)
                if pm and pm.group(1).upper() not in ("REQUIRED", "QUIET", "IMPORTED_TARGET", "GLOBAL"):
                    out.append(Component(pm.group(1).lower(), "cmake", (pm.group(2) or "") + (pm.group(3) or ""), pm.group(3) if pm.group(2) == "=" else None, rel, ln))
        elif cmd in ("fetchcontent_declare", "externalproject_add") and toks:
            tag = re.search(r"\bGIT_TAG\s+(\S+)", body)
            url = re.search(r"\bURL\s+(\S+)", body)
            repo = re.search(r"\bGIT_REPOSITORY\s+(\S+)", body)
            ver = ""
            if tag:
                tm = re.fullmatch(r"(?:[A-Za-z_-]*?)v?(\d+(?:\.\d+)+)", tag.group(1).strip("\"'"))
                ver = tm.group(1) if tm else ""
            name = toks[0].lower()
            if url:
                got = tarballs(url.group(1), "c", rel, ln)
                if got:
                    name, ver = got[0].name, got[0].version or ver
            if not ver and repo and not tag:
                ver = ""
            out.append(Component(name, "cmake", (tag.group(1) if tag else (url.group(1) if url else "")), ver or None, rel, ln))
        elif cmd in ("cpmaddpackage", "cpmfindpackage"):
            nm = re.search(r"\bNAME\s+(\S+)", body)
            vr = re.search(r"\bVERSION\s+(\d+(?:\.\d+)*)", body)
            gh = re.search(r"\bGITHUB_REPOSITORY\s+\S*/(\S+)", body) or re.search(r"gh:[^/\s]+/([^#\s\"]+)(?:#v?(\d+(?:\.\d+)+))?", body)
            name = (nm.group(1) if nm else gh.group(1) if gh else "").lower()
            ver = vr.group(1) if vr else (gh.group(2) if gh and gh.lastindex and gh.lastindex >= 2 and gh.group(2) else "")
            if name:
                out.append(Component(name, "cmake", ver, ver or None, rel, ln))
    return out


def makefile(path: Path, root: Path) -> list[Component]:
    """Makefile / *.mk: `NAME_VERSION = 1.2.3`, tarball names in download commands, `pkg-config` constraints and `-lname` link flags (a link flag names a library, never a version)."""
    rel = str(path.relative_to(root))
    out = []
    seen = set()
    for n, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
        line = raw.split("#", 1)[0]
        m = re.match(r"^\s*([A-Za-z][A-Za-z0-9_]*?)_(?:VERSION|VER)\s*[:?+]?=\s*v?(\d+(?:\.\d+)+)\s*$", line)
        if m:
            out.append(Component(m.group(1).lower().replace("_", "-"), "make", m.group(2), m.group(2), rel, n))
        out += tarballs(line, "c", rel, n)
        for pm in re.finditer(r"pkg-config[^\n]*?--(?:atleast-version|exact-version|modversion|cflags|libs)[= ]*([0-9][\w.]*)?\s+([A-Za-z][\w.+-]*)", line):
            out.append(Component(pm.group(2).lower(), "make", ("==" if "exact" in pm.group(0) else ">=") + pm.group(1) if pm.group(1) else "", pm.group(1) if "exact" in pm.group(0) else None, rel, n))
        for lm in re.finditer(r"(?<![\w-])-l([A-Za-z][\w+.-]*)", line):
            name = _LIBNAME.get(lm.group(1).lower(), lm.group(1).lower())
            if name and name not in seen and not name.startswith(("m", "pthread", "dl", "rt", "c")) or name in _LIBNAME.values():
                seen.add(name)
                out.append(Component(name, "make", "", None, rel, n))
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
            if (re.fullmatch(r"requirements[\w.-]*\.(txt|lock)", n) or n in ("pyproject.toml", "package.json", "package-lock.json", "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
                                                                              "libs.versions.toml", "cargo.toml", "cargo.lock", "conanfile.txt", "conanfile.py", "vcpkg.json",
                                                                              "cmakelists.txt", "makefile", "gnumakefile") or n.endswith((".cmake", ".mk")) or n == "dockerfile" or n.startswith("dockerfile.")
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
            if re.fullmatch(r"requirements[\w.-]*\.(txt|lock)", n):
                if p.resolve() in included:
                    continue
                got = requirements_txt(p, root, included)
            elif n == "pyproject.toml":
                got = pyproject_toml(p, root)
            elif n == "package.json":
                got = package_json(p, root)
            elif n == "package-lock.json":
                got = package_lock(p, root)
            elif n == "pom.xml":
                got = pom_xml(p, root)
            elif n in ("build.gradle", "build.gradle.kts"):
                got = gradle_build(p, root)
            elif n == "gradle.lockfile":
                got = gradle_lockfile(p, root)
            elif n == "libs.versions.toml":
                got = gradle_catalog(p, root)
            elif n == "cargo.toml":
                got = cargo_toml(p, root)
            elif n == "cargo.lock":
                got = cargo_lock(p, root)
            elif n.startswith("conanfile."):
                got = conanfile(p, root)
            elif n == "vcpkg.json":
                got = vcpkg_json(p, root)
            elif n == "cmakelists.txt" or n.endswith(".cmake"):
                got = cmake_file(p, root)
            elif n in ("makefile", "gnumakefile") or n.endswith(".mk"):
                got = makefile(p, root)
            elif "compose" in n:
                got = compose_file(p, root)
            else:
                got = dockerfile(p, root)
        except (OSError, UnicodeError):
            continue
        files.append(str(p.relative_to(root)))
        comps += got
    return comps, files, cut
