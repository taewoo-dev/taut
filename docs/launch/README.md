# Demo and visual assets

The [FastAPI example](../../examples/architecture/README.md) demonstrates a
project-specific dependency rule using the published pytaut 0.10.0 package.

## View the demo

- [18-second GIF](assets/architecture-demo.gif)
- [18-second MP4](assets/architecture-demo.mp4)
- [Poster](assets/poster.png) and [frame overview](assets/contact-sheet.png)
- [Commands, configuration, and comparison](../../examples/architecture/README.md)
- [Recorded verification results](../../examples/architecture/results.json)

The example is hand-authored, not a recording of an AI writing or repairing code.
The media replay real check results: six scenes, three seconds each. Playback
duration is reading time, not a performance measurement.

## Reproduce the results and media

Run from the repository root:

```bash
uv run --no-project --python 3.12 --locked examples/architecture/verify.py --report examples/architecture/results.json
uv run --no-project --python 3.12 --locked docs/launch/render_demo.py
```

The renderer checks the recorded results and source/policy hashes before
generating assets. Its Pillow and FFmpeg dependencies are isolated from Taut's
runtime dependencies. Rendering uses the macOS Menlo or Linux DejaVu Sans Mono /
Liberation Mono font. Review the frame overview after regeneration.

Both example variants return the same HTTP response and pass the documented
Ruff, strict mypy, and strict Pyright checks. Taut reports `ARCH001` before the
one-import repair and passes afterward under the same policy. This is not a
general accuracy benchmark or a claim that other tools cannot be configured
for architecture checks.

For an agent-assisted repair experiment, see the
[example instructions](../../examples/architecture/README.md#try-an-agent-assisted-repair).

## Logos

- [Light logo](assets/taut-logo-light.png)
- [Dark logo](assets/taut-logo-dark.png)

The README selects the appropriate PNG for the color scheme. Preserve aspect
ratio. These raster assets have opaque backgrounds and are not vector masters
or small favicon variants.
