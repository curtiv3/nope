# Unity PlayerPrefs Decoder/Encoder Toolkit

This repository contains two complementary Python utilities for inspecting and editing
obfuscated Unity/IL2CPP `PlayerPrefs` save blobs such as the
`localsave.bytes` file used by **Blue Protocol – Star Resonance**.  The tools work as a
pair: `decode.py` produces human readable JSON from the binary blob and captures all
metadata required to rebuild the file, while `encode.py` performs the reverse
transformation.

> **Compatibility note:** The workflow has been tested against synthetic samples that
> follow the reverse-engineered format.  If your build differs, inspect the logs and the
> `debug/` artifacts to adjust the heuristics where needed.

## Features at a glance

* Automatic primary XOR removal and payload trimming.
* Secondary XOR handling via slot-id heuristics or brute force search.
* Compression auto-detection (Zstandard → LZ4 → raw) with verbose logging.
* MessagePack streaming parser that merges the largest dictionaries and produces both
  a clean `settings.json` and a type-preserving `settings_raw.json`.
* Metadata capture (`.meta.json` + `.header.bin`) for safe round-tripping.
* Robust backups (`.bak` from decode, `.bak2` from encode) plus optional `--dry-run` and
  `--debug` modes.

## Installation

Python 3.8+ is required.  Install dependencies into a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### Decoding a save blob

```bash
python decode.py localsave.bytes --slot 2878076 --out settings.json
```

This performs the following steps:

1. Create a safety copy `localsave.bytes.bak` (skipped when `--dry-run` is used).
2. Apply the primary XOR (`0xAA`) to the entire file.
3. Read the header length at offset 4 (little-endian `uint32`) and isolate the payload
   starting at `payload_off = 8 + hdr_len`.
4. Trim trailing `0xAA`, `0xAC`, and `0x00` bytes repeatedly.
5. Attempt secondary XOR keys in order:
   * Slot-derived key (`slot_id % 256`) when `--slot` is provided.
   * A no-key pass.
   * Brute force `1..255` (always performed when no slot is given or when
     `--bruteforce` is set).
6. Try to decompress the payload via Zstandard, then raw LZ4 blocks, then raw bytes.
7. Parse resulting MessagePack objects with a streaming unpacker and merge the largest
   dictionaries (later keys override earlier ones).
8. Emit `settings.json` (prettified and UTF-8) plus `settings_raw.json` that preserves
   numeric keys and binary blobs.
9. Store metadata (`localsave.bytes.meta.json`) and the clear header
   (`localsave.bytes.header.bin`) for the encoder.

Pass `--debug` to keep intermediate buffers in `./debug/` (e.g. `after_xor.bin`,
`after_key_124.bin`, `after_decomp_raw.bin`).  These files are invaluable when dealing
with unknown variants.  Use `--dry-run` to inspect logs without touching the file
system.

### Encoding back to `localsave.bytes`

```bash
python encode.py settings.json --slot 2878076 --out localsave.bytes --orig localsave.bytes.bak
```

`encode.py` looks for metadata in the following order: `--meta`, files derived from
`--orig`, `--out`, or the JSON path (first existing path wins).  The script then:

1. Loads `settings.json` (or `settings_raw.json`) and reconstructs the Python object
   graph.  Raw JSON uses the `{"__type__": ...}` format described below to retain
   integers and byte arrays.
2. Packs the structure with `msgpack.packb(use_bin_type=True)`.
3. Compresses the payload according to CLI (`--compress`) or metadata (`zstd`, `lz4`,
   or `raw`).
4. Applies the secondary XOR key derived from `--key`, `--slot`, or the metadata.
5. Prepends the original header bytes captured during decoding.
6. Applies the primary XOR (`0xAA`) to the complete buffer and writes `localsave.bytes`.
7. Creates a `.bak2` snapshot before overwriting the existing file.
8. Compares the resulting SHA-256 hash with the provided `--orig` backup and reports
   whether the blob matches.

`--dry-run` assembles the binary in memory and prints diagnostics without touching the
filesystem.  Use `--debug` to drop intermediate buffers such as `after_pack.msgpack` or
`final_encrypted.bin` into `./debug/`.

### Understanding the raw JSON format

`settings_raw.json` mirrors the MessagePack structure using explicit typing so that you
can recover original binary values.  Each map is represented as

```json
{
  "__type__": "dict",
  "entries": [
    {
      "key": {"__type__": "str", "value": "volumeMusic"},
      "value": {"__type__": "float", "value": 0.8}
    }
  ]
}
```

Supported `__type__` tags: `dict`, `list`, `bytes`, `str`, `bool`, `nil`, `int`, `float`,
and `repr` (fallback textual representation).  To convert edited raw JSON back into the
binary payload simply run `encode.py`—no additional flags are required.

### Editing tips & key mapping

Typical human-facing settings include keys such as:

```json
{
  "volumeMusic": 0.8,
  "volumeSfx": 0.6,
  "mouseSensitivity": 1.25,
  "cameraFov": 90,
  "uiScale": 1.0,
  "keybind_jump": 32
}
```

Some builds replace string keys with numeric identifiers.  In that case create a
`mapping.json` by changing one setting at a time, decoding both versions, and diffing the
resulting raw JSON.  Update `settings.json` using the discovered mapping before running
`encode.py`.

### Restoring from backups

* `localsave.bytes.bak` — copy this over `localsave.bytes` to revert to the original
  data captured before decoding.
* `localsave.bytes.bak2` — produced by `encode.py` prior to overwriting.  Useful for
  rolling back a failed encode attempt.

Both backups are standard binary files; simply rename them back to `localsave.bytes` (or
copy over the active file) to restore the previous state.

### Running the round-trip test

A small synthetic save file is provided for validation.

```bash
pytest -q
```

The test decodes `localsave_sample.bytes`, tweaks the `volumeMusic` setting, encodes the
file again, and verifies that decoding the new blob reflects the change.  Ensure all
requirements are installed before running the test suite.

## Troubleshooting

* **"msgpack is required"** – Install dependencies via `pip install -r requirements.txt`.
* **"No MessagePack found"** – Provide `--slot <folder_id>` or enable `--bruteforce` to
  try every XOR key.  Inspect `debug/` artifacts for the last successful intermediate.
* **Compression errors** – Specify `--compress raw` during encoding if the blob was not
  compressed, or supply the correct algorithm manually.
* **Metadata not found** – If you moved files around, pass `--meta /path/to/localsave.bytes.meta.json`.

## Safety checklist

* Always keep the automatically created `.bak`/`.bak2` files intact until you verify the
  game loads your edits.
* Use `--dry-run` when experimenting with unusual builds to avoid accidental writes.
* Enable `--debug` and attach relevant artifacts when sharing issues with other modders.

Enjoy reverse engineering!
