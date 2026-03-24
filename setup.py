from __future__ import annotations

from pathlib import Path
from shutil import copy2

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py


class build_py(_build_py):
    def run(self) -> None:
        super().run()
        root = Path(__file__).resolve().parent
        source_dir = root / "docs"
        target_dir = Path(self.build_lib) / "open_range" / "_resources" / "docs"
        target_dir.mkdir(parents=True, exist_ok=True)
        source_docs = {path.name: path for path in source_dir.glob("*.md")}
        for path in target_dir.glob("*.md"):
            if path.name not in source_docs:
                path.unlink()
        for name, source_path in source_docs.items():
            copy2(source_path, target_dir / name)


setup(cmdclass={"build_py": build_py})
