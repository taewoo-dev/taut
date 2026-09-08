# Taut visual identity

Initial direction, 2026-09-08. This is a first logo treatment, not a claim that
the identity has been tested with users or cleared for trademark registration.

## References and decisions

Reviewed the projects' own assets and public pages:

- [FastAPI](https://github.com/fastapi/fastapi): a teal lightning symbol paired
  with a wordmark, prominently placed above the README introduction. Take the
  compact symbol-and-name layout, not the lightning or speed association.
- [Astral](https://astral.sh/) and [Ruff](https://github.com/astral-sh/ruff):
  distinctive block lettering on the company site; Ruff's README leads with
  its name, functional description, and performance evidence. Keep Taut's
  runnable evidence more prominent than decorative branding.
- [Pydantic](https://pydantic.dev/): a geometric pink symbol beside a readable
  wordmark. Take the consistent accent and separable symbol, not its geometry.
- [pytest's design assets](https://github.com/pytest-dev/design): a multicolored
  flute motif, with separate symbol-only and outlined-lettering versions.
  A future Taut asset set should likewise support small standalone usage.

These are visual references, not evidence that logos caused adoption. No
third-party logo is included in Taut's shipped assets or used as an endorsement.

## Direction

Taut means stretched tight. Two fixed posts and a straight connection suggest
an explicit dependency boundary; the central stem hints at a lowercase t.
The mark is paired with a bold, rounded lowercase wordmark: precise without
looking like a security product or an enterprise compliance seal.

Palette targets: cobalt `#2855D9`, midnight `#18243B`, white `#FFFFFF`, GitHub
dark `#0D1117`, and light ink `#F0F6FC`. The generated raster assets approximate
these colors; they are not color-exact vector masters.

The wordmark uses generated letterforms, not a bundled font. README body copy
uses GitHub's typography. Keep the header centered and the technical content
left-aligned. Use one logo, followed by the plain-language promise and two
entry links. Do not add a large decorative banner, fake adoption badges, or
security/AI imagery unrelated to the checks.

## Assets and usage

- [Light logo](assets/taut-logo-light.png)
- [Dark logo](assets/taut-logo-dark.png)

Both PNGs were generated and visually reviewed. The README selects a variant
with a `picture` element and displays it at 400 CSS pixels wide, including
the built-in margins. Alt text preserves the project name if images cannot load.
The backgrounds are opaque: the dark version targets GitHub's default dark
theme, not every custom theme. Preserve aspect ratio; do not stretch the mark.

Before extending this into favicons, stickers, or print, approve the direction
and create a clean vector master, transparent variants, and a simplified
symbol-only asset with a 16/32-pixel legibility check. The current PNG lockup
is for the README, not a finished favicon system.
