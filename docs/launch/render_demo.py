# /// script
# requires-python = ">=3.12"
# dependencies = ["pillow==11.3.0", "imageio-ffmpeg==0.6.0"]
# ///
"""Render a paced replay of verified CLI results, never an invented AI session."""

from __future__ import annotations

import hashlib
import json
import subprocess
import textwrap
from pathlib import Path

import imageio_ffmpeg
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples/architecture"
OUT = Path(__file__).resolve().parent / "assets"
WIDTH, HEIGHT = 1280, 720
BG, PANEL, TEXT = "#0d1117", "#161b22", "#e6edf3"
MUTED, GREEN, RED, BLUE = "#b1bac4", "#7ee787", "#ff7b72", "#79c0ff"


def font(size: int) -> ImageFont.FreeTypeFont:
    candidates = (
        "/System/Library/Fonts/Menlo.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf",
    )
    for candidate in candidates:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size)
    raise RuntimeError("Install DejaVu Sans Mono or use macOS Menlo to render the demo")


def main() -> None:
    report = json.loads((EXAMPLE / "results.json").read_text())
    if not report["verified"] or len(report["commands"]) != 16:
        raise RuntimeError("Run the complete example verifier before rendering")
    current_sources = {
        str(path.relative_to(EXAMPLE))
        for path in (*EXAMPLE.glob("*/app/*.py"), *EXAMPLE.glob("*/pyproject.toml"))
    }
    if set(report["sources"]) != current_sources:
        raise RuntimeError("Recorded evidence is stale: example files were added or removed")
    for relative, digest in report["sources"].items():
        if hashlib.sha256((EXAMPLE / relative).read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"Recorded evidence is stale: {relative}")
    if (
        hashlib.sha256((EXAMPLE / "policy.toml").read_bytes()).hexdigest()
        != report["shared_policy_sha256"]
    ):
        raise RuntimeError("Recorded policy is stale")
    if any(item["actual_exit"] != item["expected_exit"] for item in report["commands"]):
        raise RuntimeError("A recorded check failed")

    def recorded(variant: str, command: list[str]) -> str:
        return next(
            item["output"].strip()
            for item in report["commands"]
            if item["variant"] == variant and item["command"] == command
        )

    policy = (EXAMPLE / "policy.toml").read_text()
    graph = policy.split("[tool.taut.allow]\n")[1].split("\n\n")[0]
    before_import = (EXAMPLE / "before/app/router.py").read_text().splitlines()[2]
    after_import = (EXAMPLE / "after/app/router.py").read_text().splitlines()[2]
    checks = [
        item
        for item in report["commands"]
        if item["variant"] == "before"
        and item["command"][0] in {"ruff", "mypy", "pyright", "python"}
    ]
    check_lines = []
    for item in checks:
        name = "HTTP request" if item["command"][0] == "python" else item["command"][0]
        check_lines.append(f"{name}: {item['output'].splitlines()[0]}")
    scenes = [
        (
            "1 / 6   The project's rule",
            "Routers access repositories through services.",
            "[tool.taut.allow]\n" + graph,
            BLUE,
        ),
        (
            "2 / 6   A change crosses the boundary",
            "before/app/router.py",
            before_import + "\n\n\ndef greeting() -> str:\n    return get_greeting()",
            TEXT,
        ),
        (
            "3 / 6   The endpoint still works",
            "Released tools, pinned versions and documented settings.",
            "\n\n".join(check_lines),
            GREEN,
        ),
        (
            "4 / 6   Taut reports the forbidden import",
            "$ cd examples/architecture/before",
            "$ taut check . --no-cache\n\n"
            + recorded("before", ["taut", "check", ".", "--no-cache"])
            + "\n\nexit 1",
            RED,
        ),
        (
            "5 / 6   Fix one import",
            "Keep the shared policy unchanged.",
            "-" + before_import + "\n+" + after_import,
            TEXT,
        ),
        (
            "6 / 6   Check the corrected code",
            "$ cd examples/architecture/after",
            "$ taut check . --no-cache\n\n"
            + recorded("after", ["taut", "check", ".", "--no-cache"])
            + "\n\nexit 0\n\ngithub.com/taewoo-dev/taut",
            GREEN,
        ),
    ]
    frames = []
    for title, subtitle, body, accent in scenes:
        frame = Image.new("RGB", (WIDTH, HEIGHT), BG)
        draw = ImageDraw.Draw(frame)
        draw.text((48, 28), "taut / Python architecture checks", font=font(25), fill=MUTED)
        draw.text((48, 88), title, font=font(34), fill=TEXT)
        draw.text((48, 146), subtitle, font=font(23), fill=MUTED)
        draw.rounded_rectangle((40, 200, 1240, 604), radius=16, fill=PANEL)
        y = 225
        for line in body.splitlines():
            color = RED if line.startswith("-") else GREEN if line.startswith("+") else accent
            for segment in textwrap.wrap(
                line, width=78, replace_whitespace=False, drop_whitespace=False
            ) or [""]:
                if y > 570:
                    raise RuntimeError(f"Scene overflows: {title}")
                draw.text((64, y), segment, font=font(24), fill=color)
                y += 31
        draw.text(
            (48, 635),
            "Hand-authored example | real CLI output | paced replay",
            font=font(20),
            fill=MUTED,
        )
        draw.text(
            (48, 671),
            "pytaut 0.10.0 | Python 3.12 | Same policy before and after",
            font=font(20),
            fill=MUTED,
        )
        frames.append(frame)

    OUT.mkdir(parents=True, exist_ok=True)
    frames[0].save(OUT / "poster.png")
    frames[0].save(
        OUT / "architecture-demo.gif",
        save_all=True,
        append_images=frames[1:],
        duration=3000,
        loop=0,
        optimize=True,
    )
    sheet = Image.new("RGB", (WIDTH, HEIGHT * 3 // 2), BG)
    for index, frame in enumerate(frames):
        sheet.paste(
            frame.resize((WIDTH // 2, HEIGHT // 2)),
            ((index % 2) * WIDTH // 2, (index // 2) * HEIGHT // 2),
        )
    # Three rows of two half-size frames.
    sheet.save(OUT / "contact-sheet.png")
    command = [
        imageio_ffmpeg.get_ffmpeg_exe(),
        "-y",
        "-loglevel",
        "error",
        "-f",
        "rawvideo",
        "-pix_fmt",
        "rgb24",
        "-s",
        f"{WIDTH}x{HEIGHT}",
        "-r",
        "10",
        "-i",
        "pipe:0",
        "-an",
        "-c:v",
        "libx264",
        "-pix_fmt",
        "yuv420p",
        "-movflags",
        "+faststart",
        str(OUT / "architecture-demo.mp4"),
    ]
    with subprocess.Popen(command, stdin=subprocess.PIPE) as process:
        assert process.stdin is not None
        for frame in frames:
            pixels = frame.tobytes()
            for _ in range(30):
                process.stdin.write(pixels)
        process.stdin.close()
        if process.wait() != 0:
            raise RuntimeError("Video encoding failed")
    print("Rendered 18-second GIF and MP4, poster, and QA contact sheet from verified results.")


if __name__ == "__main__":
    main()
