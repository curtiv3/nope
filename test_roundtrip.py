"""Smoke test for decode/encode round-trip behaviour using bundled sample."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import decode
import encode

SLOT_ID = 2878076


def test_roundtrip(tmp_path):
    sample_path = Path(__file__).with_name("localsave_sample.bytes")
    work_path = tmp_path / "localsave.bytes"
    shutil.copy2(sample_path, work_path)

    settings_path = tmp_path / "settings.json"
    decode.decode_file(work_path, settings_path, slot=SLOT_ID, brute_force=False, dry_run=False, debug=False)
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    settings["volumeMusic"] = 0.1
    settings_path.write_text(json.dumps(settings, indent=2), encoding="utf-8")

    args = encode.parse_args(
        [
            str(settings_path),
            "--out",
            str(work_path),
            "--orig",
            str(work_path.with_suffix(work_path.suffix + ".bak")),
            "--slot",
            str(SLOT_ID),
        ]
    )
    encode.encode_file(args)

    decoded_again_path = tmp_path / "settings_after.json"
    decode.decode_file(work_path, decoded_again_path, slot=SLOT_ID, brute_force=False, dry_run=False, debug=False)
    updated = json.loads(decoded_again_path.read_text(encoding="utf-8"))
    assert abs(updated["volumeMusic"] - 0.1) < 1e-6
