"""Render docs/demo.gif from a real bouncer session.

Every line of output in the GIF is produced by actually running the CLI
against a throwaway policy and database -- nothing here is mocked up or
retyped. Colour is applied by this renderer, the text is not.

    python scripts/record_demo.py

Requires Pillow and a monospace TTF; neither is a runtime dependency of
bouncer itself.
"""

from __future__ import annotations

import io
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bouncer.audit import AuditLog  # noqa: E402
from bouncer.cli import main  # noqa: E402
from bouncer.keys import OperatorKey  # noqa: E402

# -- terminal look ----------------------------------------------------------

COLS = 92
ROWS = 26
FONT_SIZE = 15
PAD = 18
TITLE_H = 30

BG = (13, 17, 23)
CHROME = (22, 27, 34)
FG = (201, 209, 217)
DIM = (110, 120, 132)
GREEN = (63, 185, 128)
RED = (248, 113, 113)
YELLOW = (219, 171, 70)
CYAN = (110, 168, 232)
PROMPT = (139, 148, 158)

FONT_REGULAR = r"C:\Windows\Fonts\consola.ttf"
FONT_BOLD = r"C:\Windows\Fonts\consolab.ttf"

# Frame timings, in milliseconds.
TYPE_MS = 55
LINE_MS = 260
BEAT_MS = 1100
HOLD_MS = 2600


@dataclass
class Line:
    text: str
    color: tuple[int, int, int] = FG
    bold: bool = False


@dataclass
class Frame:
    lines: list[Line] = field(default_factory=list)
    duration: int = LINE_MS


def _colour_for(raw: str) -> tuple[tuple[int, int, int], bool]:
    """Pick a colour from the content of a real output line."""
    if raw.startswith("ALLOW") or "approved by role" in raw or "chain intact" in raw:
        return GREEN, True
    if raw.startswith("DENY") or "CHAIN BROKEN" in raw or raw.startswith("refused"):
        return RED, True
    if raw.startswith("REQUIRE_APPROVAL") or "pending approval" in raw:
        return YELLOW, True
    if raw.lstrip().startswith(("mandate:", "resolve:", "requires role", "requested")):
        return DIM, False
    if raw.startswith("#"):
        return DIM, False
    return FG, False


def _fit(raw: str) -> str:
    if len(raw) <= COLS:
        return raw
    return raw[: COLS - 1] + "\u2026"


class Session:
    """Accumulates the visible screen and emits a frame per change."""

    def __init__(self) -> None:
        self.frames: list[Frame] = []
        self.screen: list[Line] = []

    def _snapshot(self, duration: int) -> None:
        self.frames.append(Frame(list(self.screen[-ROWS:]), duration))

    def type_command(self, command: str) -> None:
        """Reveal a prompt line a few characters at a time."""
        self.screen.append(Line("$ ", CYAN, True))
        step = 3
        for cut in range(0, len(command) + step, step):
            self.screen[-1] = Line("$ " + command[:cut], CYAN, True)
            self._snapshot(TYPE_MS)
        self.screen[-1] = Line("$ " + command, CYAN, True)
        self._snapshot(BEAT_MS)

    def comment(self, note: str) -> None:
        self.screen.append(Line(_fit("# " + note), DIM, False))
        self._snapshot(BEAT_MS)

    def output(self, blob: str, *, hold: int = BEAT_MS) -> None:
        lines = [ln.rstrip() for ln in blob.rstrip("\n").split("\n")]
        for raw in lines:
            colour, bold = _colour_for(raw.strip())
            self.screen.append(Line(_fit(raw), colour, bold))
            self._snapshot(LINE_MS)
        self.screen.append(Line(""))
        self._snapshot(hold)

    def blank(self) -> None:
        self.screen.append(Line(""))


def run_cli(home: Path, *args: str) -> str:
    """Run the real CLI, returning exactly what it printed."""
    buffer = io.StringIO()
    main(["--home", str(home), *args], out=buffer)
    return buffer.getvalue()


def build_session(home: Path, policy: Path) -> Session:
    shutil.copy(policy, home / "policy.yaml")
    run_cli(home, "keygen")

    session = Session()
    session.comment("bouncer -- a policy enforcement point for agent spending")
    session.blank()

    # 1. allowed
    cmd = "bouncer check --agent research-bot --merchant api.weather.example --amount 12.00"
    session.type_command(cmd)
    session.output(run_cli(
        home, "check", "--agent", "research-bot",
        "--merchant", "api.weather.example", "--amount", "12.00",
    ))

    # 2. blocked
    cmd = "bouncer check --agent research-bot --merchant lucky.casino.example --amount 5.00"
    session.type_command(cmd)
    session.output(run_cli(
        home, "check", "--agent", "research-bot",
        "--merchant", "lucky.casino.example", "--amount", "5.00",
    ))

    # 3. needs a human
    cmd = "bouncer check --agent research-bot --merchant api.data-vendor.example --amount 35.00"
    session.type_command(cmd)
    queued = run_cli(
        home, "check", "--agent", "research-bot",
        "--merchant", "api.data-vendor.example", "--amount", "35.00",
    )
    session.output(queued)

    match = re.search(r"pending approval id: ([0-9a-f]+)", queued)
    assert match is not None, "expected the check to queue an approval"
    item_id = match.group(1)

    session.type_command("bouncer pending --role finance")
    session.output(run_cli(home, "pending", "--role", "finance"))

    session.type_command(f"bouncer approve {item_id} --role finance")
    session.output(run_cli(home, "approve", item_id, "--role", "finance"))

    # 4. the audit chain
    session.type_command("bouncer verify")
    session.output(run_cli(home, "verify").split("\n\n")[0])

    session.comment("now tamper with one row directly in SQLite...")
    key = OperatorKey.load(home / "operator.pem")
    log = AuditLog(home / "bouncer.db", key)
    with log.sessions.begin() as db:
        db.execute(text("UPDATE audit_entries SET outcome='ALLOW' WHERE seq=2"))

    session.type_command("bouncer verify")
    session.output(run_cli(home, "verify"), hold=HOLD_MS)
    return session


def render(session: Session, destination: Path) -> None:
    regular = ImageFont.truetype(FONT_REGULAR, FONT_SIZE)
    bold = ImageFont.truetype(FONT_BOLD, FONT_SIZE)

    probe = Image.new("RGB", (10, 10))
    measure = ImageDraw.Draw(probe)
    char_w = measure.textlength("M", font=regular)
    line_h = FONT_SIZE + 7

    width = int(char_w * COLS) + PAD * 2
    height = TITLE_H + line_h * ROWS + PAD

    images: list[Image.Image] = []
    for frame in session.frames:
        canvas = Image.new("RGB", (width, height), BG)
        draw = ImageDraw.Draw(canvas)
        draw.rectangle([0, 0, width, TITLE_H], fill=CHROME)
        for i, dot in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
            cx = PAD + i * 18
            draw.ellipse([cx, 11, cx + 9, 20], fill=dot)
        draw.text(
            (width // 2 - 40, 8), "bouncer demo", font=regular, fill=PROMPT
        )
        for row, line in enumerate(frame.lines):
            draw.text(
                (PAD, TITLE_H + 6 + row * line_h),
                line.text,
                font=bold if line.bold else regular,
                fill=line.color,
            )
        images.append(canvas.convert("P", palette=Image.Palette.ADAPTIVE, colors=64))

    images[0].save(
        destination,
        save_all=True,
        append_images=images[1:],
        duration=[f.duration for f in session.frames],
        loop=0,
        optimize=True,
        disposal=2,
    )


def main_entry() -> int:
    root = Path(__file__).resolve().parent.parent
    destination = root / "docs" / "demo.gif"
    destination.parent.mkdir(parents=True, exist_ok=True)

    home = Path(tempfile.mkdtemp())
    try:
        session = build_session(home, root / "examples" / "policy.yaml")
        render(session, destination)
    finally:
        shutil.rmtree(home, ignore_errors=True)

    total = sum(f.duration for f in session.frames) / 1000
    size = destination.stat().st_size / 1_000_000
    print(f"wrote {destination}")
    print(f"  frames : {len(session.frames)}")
    print(f"  runtime: {total:.1f}s")
    print(f"  size   : {size:.2f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_entry())
