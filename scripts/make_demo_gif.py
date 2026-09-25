"""Render docs/demo.gif: a terminal session replaying real tfminder output.

Every line below was printed by tfminder 0.1.1 running `terraform plan` (Terraform 1.14.4,
google provider 6.50.0) against examples/gcp-lab. Only the request ids are shortened.
Run: python scripts/make_demo_gif.py
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 960, 400
PAD = 22
FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 15)
BOLD = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 15)
LINE = 21
BG, FG, DIM = (22, 24, 29), (215, 218, 224), (120, 126, 138)
GREEN, YELLOW, RED, CYAN = (120, 200, 120), (230, 190, 90), (240, 95, 95), (110, 180, 230)

# (text, color, bold, typed?)
SCENE_1 = [
    ("# An agent wants to create the lab. tfminder runs a real plan and reviews it.", DIM, False, False),
    ("$ tfminder plan lab -j \"create lab\"", FG, True, True),
    ("request  20260925-222911-42a552   status: reviewed", FG, False, False),
    ("workspace lab (lab)", FG, False, False),
    ("changes  create 4  update 0  delete 0  replace 0", FG, False, False),
    ("  create                           google_compute_firewall.iap_ssh", FG, False, False),
    ("  create                           google_compute_network.lab", FG, False, False),
    ("  create                           google_pubsub_topic.events", FG, False, False),
    ("  create                           google_storage_bucket.artifacts", FG, False, False),
    ("", FG, False, False),
    ("decision APPROVAL", YELLOW, True, False),
    ("  - policy requires human approval for every apply (auto_apply: false)", FG, False, False),
]
SCENE_2 = [
    ("# Now the agent \"fixes\" access by opening SSH to the whole internet.", DIM, False, False),
    ("$ tfminder plan lab -j \"open ssh\"", FG, True, True),
    ("request  20260925-222957-017b9a   status: denied", FG, False, False),
    ("changes  create 4  update 0  delete 0  replace 0", FG, False, False),
    ("", FG, False, False),
    ("CRITICAL GC006  Administrative or data port opened to the internet", RED, True, False),
    ("         google_compute_firewall.iap_ssh", FG, False, False),
    ("         Ingress from 0.0.0.0/0 now reaches 22/SSH", FG, False, False),
    ("", FG, False, False),
    ("decision DENY", RED, True, False),
    ("  - GC006 critical: Administrative or data port opened to the internet", FG, False, False),
    ("", FG, False, False),
    ("# Denied plans cannot be submitted, approved or applied. The agent has to change the code.", CYAN, False, False),
]


def frame(lines: list[tuple[str, tuple, bool]], cursor: bool) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 30], fill=(38, 41, 48))
    for i, c in enumerate(((237, 106, 94), (245, 191, 79), (98, 197, 84))):
        d.ellipse([14 + i * 20, 10, 26 + i * 20, 22], fill=c)
    d.text((W // 2 - 150, 7), "tfminder · terraform plan against GCP", font=FONT, fill=DIM)
    y = 30 + PAD
    for text, color, bold in lines:
        d.text((PAD, y), text, font=BOLD if bold else FONT, fill=color)
        y += LINE
    if cursor:
        x = PAD + int(FONT.getlength(lines[-1][0])) + 2 if lines else PAD
        cy = y - LINE if lines else y
        d.rectangle([x, cy + 2, x + 8, cy + 18], fill=FG)
    return img


def scene(script: list, frames: list, durations: list) -> None:
    shown: list[tuple[str, tuple, bool]] = []
    for text, color, bold, typed in script:
        if typed:
            for i in range(2, len(text) + 1, 2):
                frames.append(frame(shown + [(text[:i], color, bold)], True))
                durations.append(45)
            shown.append((text, color, bold))
            frames.append(frame(shown, False))
            durations.append(700)  # terraform plan running
        else:
            shown.append((text, color, bold))
            frames.append(frame(shown, False))
            durations.append(90)
    durations[-1] = 3200


def main() -> None:
    frames: list[Image.Image] = []
    durations: list[int] = []
    scene(SCENE_1, frames, durations)
    scene(SCENE_2, frames, durations)
    durations[-1] = 5000
    out = Path(__file__).resolve().parent.parent / "docs" / "demo.gif"
    frames[0].save(out, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True)
    print(f"wrote {out} ({out.stat().st_size // 1024} KB, {len(frames)} frames)")


if __name__ == "__main__":
    main()
