#!/usr/bin/env python3
"""Сборка self-hosted бандла lk-unlock web.
Запуск: uv run python web/build.py
Сеть нужна ТОЛЬКО при сборке; рантайм полностью офлайн.
Результат: web/pyodide/, web/vendor/pyasn1-*.whl, web/gen/pyfiles.js, web/gen/vendor.json
"""

import json
import shutil
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"
CACHE = WEB / ".cache"
PYODIDE_VER = "0.28.3"
PYODIDE_TAR = (
    f"https://github.com/pyodide/pyodide/releases/download/"
    f"{PYODIDE_VER}/pyodide-{PYODIDE_VER}.tar.bz2"
)


def _liblk_root() -> Path:
    for p in (ROOT / "vendor/liblk/liblk", ROOT / "vendor/liblk"):
        if p.is_dir():
            return p
    raise SystemExit("не найден пакет liblk в vendor/ — поправьте _liblk_root()")


SOURCES = {"lk_unlock": ROOT / "src/lk_unlock", "liblk": _liblk_root()}
EXTRA = {"patcher_web.py": WEB / "python/patcher_web.py"}


def http_get(url: str, dest: Path):
    if dest.exists():
        print(f"  кэш: {dest.name}")
        return
    print(f"  GET {url}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as r, open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def step_pyodide():
    dist = WEB / "pyodide"
    if (dist / "pyodide.js").exists():
        print("pyodide/ уже на месте")
        return
    tb = CACHE / f"pyodide-{PYODIDE_VER}.tar.bz2"
    http_get(PYODIDE_TAR, tb)
    print("Распаковка Pyodide…")
    with tarfile.open(tb, "r:bz2") as t:
        t.extractall(CACHE, filter="data")
    shutil.rmtree(dist, ignore_errors=True)
    shutil.move(str(CACHE / "pyodide"), str(dist))


def step_pyasn1():
    vendor = WEB / "vendor"
    vendor.mkdir(exist_ok=True)
    if any(vendor.glob("pyasn1-*.whl")):
        print("pyasn1 wheel уже на месте")
        return
    meta = json.load(urllib.request.urlopen("https://pypi.org/pypi/pyasn1/json"))
    ver = meta["info"]["version"]
    url = next(
        u["url"] for u in meta["releases"][ver] if u["filename"].endswith("py3-none-any.whl")
    )
    wheel = f"pyasn1-{ver}-py3-none-any.whl"
    http_get(url, vendor / wheel)
    (WEB / "gen").mkdir(exist_ok=True)
    (WEB / "gen/vendor.json").write_text(json.dumps({"wheel": wheel}))


def step_pyfiles():
    files = {}
    for pkg, root in SOURCES.items():
        for p in sorted(root.rglob("*.py")):
            files[f"{pkg}/{p.relative_to(root).as_posix()}"] = p.read_text()
        for p in sorted(root.rglob("*.pem")):  # xiaomi.pem и др. данные ключей
            files[f"{pkg}/{p.relative_to(root).as_posix()}"] = p.read_text()
    for name, p in EXTRA.items():
        files[name] = p.read_text()
    gen = WEB / "gen"
    gen.mkdir(exist_ok=True)
    out = gen / "pyfiles.js"
    out.write_text(
        "// автогенерация web/build.py — не редактировать\n"
        "self.__PYFILES__ = " + json.dumps(files, ensure_ascii=False) + ";\n"
    )
    print(f"pyfiles.js: {len(files)} файлов, {out.stat().st_size // 1024} КБ")


if __name__ == "__main__":
    print("== build lk-unlock web ==")
    step_pyodide()
    step_pyasn1()
    step_pyfiles()
    (WEB / ".nojekyll").touch()
    print("Готово. Локальная проверка: uv run python -m http.server -d web 8000")
