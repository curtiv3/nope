#!/usr/bin/env python3
"""Utility to decode Unity/IL2CPP PlayerPrefs blobs into JSON."""
from __future__ import annotations

import argparse
import base64
import json
import logging
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

try:
    import msgpack  # type: ignore
except ImportError as exc:  # pragma: no cover - exercised in runtime environments without deps
    raise SystemExit(
        "msgpack is required. Install dependencies via 'pip install -r requirements.txt'."
    ) from exc

try:
    import zstandard  # type: ignore
except ImportError:  # pragma: no cover
    zstandard = None  # type: ignore

try:
    import lz4.block as lz4_block  # type: ignore
except ImportError:  # pragma: no cover
    lz4_block = None  # type: ignore

LOGGER = logging.getLogger("decode")

TRIM_TRAILING = {0xAA, 0xAC, 0x00}
PRIMARY_XOR = 0xAA
DEBUG_DIR = Path("debug")


@dataclass
class DecodeResult:
    """Aggregated decode metadata used by encode.py."""

    compression: str
    secondary_key: Optional[int]
    header: bytes
    payload: bytes
    payload_decrypted: bytes
    raw_dict: Dict[object, object]


class DecodeError(RuntimeError):
    """Raised when the decoder cannot produce a valid payload."""


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Path to localsave.bytes file")
    parser.add_argument("--out", type=Path, default=Path("settings.json"), help="Output JSON path")
    parser.add_argument(
        "--slot",
        type=int,
        default=None,
        help="Slot/Folder identifier used to derive the secondary XOR key",
    )
    parser.add_argument(
        "--bruteforce",
        action="store_true",
        help="Force brute-force of secondary XOR keys (1..255) even if slot provided",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run through all heuristics without writing any files",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Write intermediate buffers to ./debug/ for manual inspection",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    return parser.parse_args(argv)


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s:%(name)s:%(message)s",
    )


def make_backup(path: Path, dry_run: bool) -> None:
    backup_path = path.with_suffix(path.suffix + ".bak")
    if backup_path.exists():
        LOGGER.info("Backup already exists at %s", backup_path)
        return
    if dry_run:
        LOGGER.info("[dry-run] Would create backup at %s", backup_path)
        return
    LOGGER.info("Creating backup %s", backup_path)
    import shutil

    shutil.copy2(path, backup_path)


def write_debug(name: str, data: bytes, enabled: bool, dry_run: bool) -> None:
    if not enabled:
        return
    if dry_run:
        LOGGER.info("[dry-run] Skipping debug dump %s", name)
        return
    DEBUG_DIR.mkdir(exist_ok=True)
    target = DEBUG_DIR / name
    LOGGER.debug("Writing debug buffer %s (%d bytes)", target, len(data))
    target.write_bytes(data)


def primary_decrypt(data: bytes) -> bytes:
    return bytes(b ^ PRIMARY_XOR for b in data)


def extract_header(decrypted: bytes) -> Tuple[bytes, bytes]:
    if len(decrypted) < 8:
        raise DecodeError("Input too small to contain header")
    hdr_len = struct.unpack_from("<I", decrypted, 4)[0]
    payload_off = 8 + hdr_len
    LOGGER.debug("Header length=%d payload_off=%d", hdr_len, payload_off)
    if payload_off > len(decrypted):
        raise DecodeError("Computed payload offset beyond end of file")
    header = decrypted[:payload_off]
    payload = decrypted[payload_off:]
    return header, payload


def trim_payload(payload: bytes) -> bytes:
    original_len = len(payload)
    while payload and payload[-1] in TRIM_TRAILING:
        payload = payload[:-1]
    if len(payload) != original_len:
        LOGGER.debug(
            "Trimmed payload from %d to %d bytes (removed trailing markers)",
            original_len,
            len(payload),
        )
    return payload


def apply_secondary_xor(payload: bytes, key: Optional[int]) -> bytes:
    if key is None:
        return payload
    return bytes(b ^ key for b in payload)


def candidate_keys(slot: Optional[int], brute_force: bool) -> Iterator[Optional[int]]:
    seen = set()
    if slot is not None:
        key = slot % 256
        if key not in seen:
            LOGGER.info("Trying slot-derived secondary XOR key: %d", key)
            seen.add(key)
            yield key
    # Always try no secondary XOR before brute forcing.
    if None not in seen:
        seen.add(None)
        LOGGER.info("Trying without secondary XOR key")
        yield None
    if brute_force or slot is None:
        LOGGER.info("Starting brute-force search of secondary XOR keys")
        for key in range(1, 256):
            if key in seen:
                continue
            seen.add(key)
            LOGGER.debug("Brute-forcing key %d", key)
            yield key


def attempt_decompressions(payload: bytes, debug: bool, dry_run: bool) -> Iterator[Tuple[str, bytes]]:
    attempts = ["zstd", "lz4", "raw"]
    for mode in attempts:
        try:
            if mode == "zstd":
                if zstandard is None:
                    raise RuntimeError("zstandard module not installed")
                decompressor = zstandard.ZstdDecompressor()
                data = decompressor.decompress(payload)
            elif mode == "lz4":
                if lz4_block is None:
                    raise RuntimeError("lz4 module not installed")
                data = lz4_block.decompress(payload, store_size=False)  # type: ignore[attr-defined]
            else:
                data = payload
        except Exception as exc:
            LOGGER.debug("Compression %s failed: %s", mode, exc)
            continue
        LOGGER.info("Decompression via %s succeeded (%d bytes)", mode, len(data))
        write_debug(f"after_decomp_{mode}.bin", data, debug, dry_run)
        yield mode, data


def unpack_msgpack_objects(buffer: bytes) -> List[object]:
    unpacker = msgpack.Unpacker(use_list=False, raw=True, strict_map_key=False)
    unpacker.feed(buffer)
    objects: List[object] = []
    for obj in unpacker:
        objects.append(_expand_bytes(obj))
    LOGGER.info("Parsed %d MessagePack object(s)", len(objects))
    return objects


def _expand_bytes(obj: object) -> object:
    if isinstance(obj, dict):
        return { _expand_bytes(key): _expand_bytes(value) for key, value in obj.items() }
    if isinstance(obj, (list, tuple)):
        return type(obj)(_expand_bytes(item) for item in obj)
    if isinstance(obj, bytes):
        try:
            nested = msgpack.unpackb(obj, use_list=False, raw=True, strict_map_key=False)
        except Exception:
            return obj
        else:
            return _expand_bytes(nested)
    return obj


def collect_dicts(objects: Iterable[object]) -> List[Dict[object, object]]:
    found: List[Dict[object, object]] = []
    def _walk(node: object) -> None:
        if isinstance(node, dict):
            found.append(node)
            for value in node.values():
                _walk(value)
        elif isinstance(node, (list, tuple)):
            for item in node:
                _walk(item)
    for obj in objects:
        _walk(obj)
    found.sort(key=lambda d: len(d), reverse=True)
    LOGGER.info("Collected %d candidate dict(s)", len(found))
    return found


def merge_dicts(dicts: List[Dict[object, object]]) -> Dict[object, object]:
    merged: Dict[object, object] = {}
    for mapping in dicts:
        LOGGER.debug("Merging dict with %d entries", len(mapping))
        merged.update(mapping)
    if not merged:
        raise DecodeError("No dictionary objects found in MessagePack payload")
    LOGGER.info("Merged dictionary contains %d keys", len(merged))
    return merged


def to_readable(obj: object) -> object:
    if isinstance(obj, dict):
        return { _convert_key_to_string(k): to_readable(v) for k, v in obj.items() }
    if isinstance(obj, (list, tuple)):
        return [to_readable(item) for item in obj]
    if isinstance(obj, bytes):
        for codec in ("utf-8", "latin-1"):
            try:
                return obj.decode(codec)
            except UnicodeDecodeError:
                continue
        return f"hex:{obj.hex()}"
    return obj


def _convert_key_to_string(key: object) -> str:
    if isinstance(key, str):
        return key
    if isinstance(key, bytes):
        for codec in ("utf-8", "latin-1"):
            try:
                return key.decode(codec)
            except UnicodeDecodeError:
                continue
        return key.hex()
    return str(key)


def to_raw_serializable(obj: object) -> object:
    if isinstance(obj, dict):
        return {
            "__type__": "dict",
            "entries": [
                {
                    "key": to_raw_serializable(key),
                    "value": to_raw_serializable(value),
                }
                for key, value in obj.items()
            ],
        }
    if isinstance(obj, (list, tuple)):
        return {
            "__type__": "list",
            "items": [to_raw_serializable(item) for item in obj],
        }
    if isinstance(obj, bytes):
        return {"__type__": "bytes", "hex": obj.hex()}
    if isinstance(obj, str):
        return {"__type__": "str", "value": obj}
    if isinstance(obj, bool):
        return {"__type__": "bool", "value": obj}
    if obj is None:
        return {"__type__": "nil"}
    if isinstance(obj, int):
        return {"__type__": "int", "value": obj}
    if isinstance(obj, float):
        return {"__type__": "float", "value": obj}
    return {"__type__": "repr", "value": repr(obj)}


def decode_file(path: Path, out_path: Path, slot: Optional[int], brute_force: bool, dry_run: bool, debug: bool) -> DecodeResult:
    if not path.exists():
        raise DecodeError(f"Input file {path} does not exist")
    make_backup(path, dry_run)
    encrypted = path.read_bytes()
    LOGGER.info("Loaded %d bytes", len(encrypted))
    decrypted = primary_decrypt(encrypted)
    write_debug("after_xor.bin", decrypted, debug, dry_run)
    header, payload = extract_header(decrypted)
    LOGGER.info("Header captured (%d bytes)", len(header))
    trimmed = trim_payload(payload)
    candidate_key_iter = list(candidate_keys(slot, brute_force))
    if not candidate_key_iter:
        raise DecodeError("No secondary XOR keys available for testing")

    last_error: Optional[Exception] = None
    for key in candidate_key_iter:
        decrypted_payload = apply_secondary_xor(trimmed, key)
        key_label = "none" if key is None else f"{key:03d}"
        write_debug(
            f"after_key_{key_label}.bin",
            decrypted_payload,
            debug,
            dry_run,
        )
        for compression, unpack_buffer in attempt_decompressions(decrypted_payload, debug, dry_run):
            try:
                objects = unpack_msgpack_objects(unpack_buffer)
                dicts = collect_dicts(objects)
                merged = merge_dicts(dicts)
            except Exception as exc:
                last_error = exc
                LOGGER.debug("MessagePack parsing failed for key %s (%s): %s", key, compression, exc)
                continue
            LOGGER.info(
                "Decoded successfully using key=%s compression=%s", key, compression
            )
            readable = to_readable(merged)
            raw_serializable = to_raw_serializable(merged)
            if not dry_run:
                json_kwargs = dict(ensure_ascii=False, indent=2, sort_keys=True)
                out_path.write_text(json.dumps(readable, **json_kwargs), encoding="utf-8")
                raw_path = out_path.with_name(out_path.stem + "_raw.json")
                raw_path.write_text(json.dumps(raw_serializable, **json_kwargs), encoding="utf-8")
                meta = {
                    "input": str(path),
                    "header_b64": base64.b64encode(header).decode(),
                    "compression": compression,
                    "secondary_key": key,
                    "slot": slot,
                    "payload_length": len(trimmed),
                }
                meta_path = path.with_suffix(path.suffix + ".meta.json")
                meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
                header_path = path.with_suffix(path.suffix + ".header.bin")
                header_path.write_bytes(header)
                LOGGER.info("Wrote %s, %s and %s", out_path, raw_path, meta_path)
            else:
                LOGGER.info("[dry-run] Would write JSON outputs and metadata")
            return DecodeResult(
                compression=compression,
                secondary_key=key if isinstance(key, int) else None,
                header=header,
                payload=trimmed,
                payload_decrypted=unpack_buffer,
                raw_dict=merged,
            )
    raise DecodeError(
        "Failed to decode payload. Last error: %s" % (last_error or "Unknown"),
    )


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    configure_logging(args.verbose)
    try:
        decode_file(args.input, args.out, args.slot, args.bruteforce, args.dry_run, args.debug)
    except DecodeError as exc:
        LOGGER.error("%s", exc)
        return 2
    except Exception as exc:  # pragma: no cover - safety net
        LOGGER.exception("Unexpected failure: %s", exc)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
