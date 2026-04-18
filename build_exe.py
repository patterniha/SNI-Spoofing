from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from PIL import Image


def find_icon_file(icon_dir: Path) -> Path:
    ico_files = sorted(icon_dir.glob("*.ico"))
    if ico_files:
        return ico_files[0]

    image_files = []
    for pattern in ("*.png", "*.jpg", "*.jpeg", "*.bmp", "*.webp"):
        image_files.extend(sorted(icon_dir.glob(pattern)))

    if not image_files:
        raise FileNotFoundError("No icon file found in icon folder")

    src = image_files[0]
    out_dir = icon_dir / "_generated"
    out_dir.mkdir(parents=True, exist_ok=True)
    ico_path = out_dir / (src.stem + ".ico")

    with Image.open(src) as img:
        img = img.convert("RGBA")
        img.save(
            ico_path,
            format="ICO",
            sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)],
        )

    return ico_path


def run() -> None:
    root = Path(__file__).resolve().parent
    icon_dir = root / "icon"

    if not icon_dir.exists():
        raise FileNotFoundError("icon directory not found")

    icon_path = find_icon_file(icon_dir)

    dist_dir = root / "dist"
    build_dir = root / "build"
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    if build_dir.exists():
        shutil.rmtree(build_dir)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name",
        "SMART-FOX",
        "--icon",
        str(icon_path),
        "--hidden-import",
        "main",
        str(root / "gui.py"),
    ]

    print("Running:", " ".join(cmd))
    subprocess.run(cmd, check=True, cwd=root)

    exe_path = root / "dist" / "SMART-FOX.exe"
    if not exe_path.exists():
        raise FileNotFoundError("Build finished but SMART-FOX.exe was not found")

    config_src = root / "config.json"
    config_dst = root / "dist" / "config.json"
    shutil.copy2(config_src, config_dst)

    print("Build complete")
    print("EXE:", exe_path)
    print("CONFIG:", config_dst)


if __name__ == "__main__":
    run()
