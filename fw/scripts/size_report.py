#!/usr/bin/env python3

import argparse
import json
import re
import subprocess
from pathlib import Path


SIZE_LINE_RE = re.compile(
    r"^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+([0-9a-fA-F]+)\s+(.+)$"
)
MAP_ENTRY_RE = re.compile(
    r"^\s*\.(text|rodata|data|bss)(?:\.[^\s]*)?\s+0x[0-9a-fA-F]+\s+0x([0-9a-fA-F]+)\s+(\S+\.o(?:\))?)\s*$",
    re.M,
)


def run_command(command):
    return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)


def parse_size_output(raw_output):
    for line in raw_output.splitlines():
        match = SIZE_LINE_RE.match(line)
        if not match:
            continue
        text, data, bss, dec, hex_size, _filename = match.groups()
        return {
            "text": int(text),
            "data": int(data),
            "bss": int(bss),
            "dec": int(dec),
            "hex": int(hex_size, 16),
        }
    raise ValueError("Unable to parse arm-none-eabi-size output.")


def collect_top_symbols(elf_path, top_count, max_symbol_size=None):
    nm_output = run_command(["arm-none-eabi-nm", "-S", "--size-sort", str(elf_path)])
    symbols = []
    for line in nm_output.splitlines():
        parts = line.strip().split()
        if len(parts) < 4:
            continue
        symbol_type = parts[2]
        if symbol_type not in {"T", "t", "R", "r", "D", "d", "B", "b"}:
            continue
        try:
            size = int(parts[1], 16)
        except ValueError:
            continue
        if size <= 0:
            continue
        if max_symbol_size is not None and size > max_symbol_size:
            continue
        symbols.append(
            {
                "address": parts[0],
                "size": size,
                "type": symbol_type,
                "name": " ".join(parts[3:]),
            }
        )
    return symbols[-top_count:]


def collect_object_totals(map_path):
    map_text = map_path.read_text(encoding="utf-8", errors="ignore")
    marker = "Linker script and memory map"
    marker_index = map_text.find(marker)
    if marker_index >= 0:
        map_text = map_text[marker_index:]

    object_totals = {}
    for _section, size_hex, object_path in MAP_ENTRY_RE.findall(map_text):
        object_totals.setdefault(object_path.strip(), 0)
        object_totals[object_path.strip()] += int(size_hex, 16)
    return object_totals


def collect_top_objects(object_totals, top_count):
    objects_sorted = sorted(object_totals.items(), key=lambda item: item[1], reverse=True)
    return [{"object": obj, "size": size} for obj, size in objects_sorted[:top_count]]


def write_summary_report(output_prefix, metrics):
    text_lines = []
    text_lines.append(f"=== Firmware size report ({metrics['board']}, RELEASE={metrics['release']}) ===")
    text_lines.append(f"pixljs.bin bytes: {metrics['bin_bytes']}")
    text_lines.append(
        "Sections (.text/.data/.bss/dec/hex): "
        f"{metrics['sections']['text']} / {metrics['sections']['data']} / "
        f"{metrics['sections']['bss']} / {metrics['sections']['dec']} / 0x{metrics['sections']['hex']:x}"
    )
    text_lines.append("")
    text_lines.append(f"Top {len(metrics['top_symbols'])} symbols by size:")
    for symbol in metrics["top_symbols"]:
        text_lines.append(
            f"{symbol['size']:8d}  {symbol['type']}  {symbol['name']}"
        )
    text_lines.append("")
    text_lines.append(f"Top {len(metrics['top_objects'])} object contributions (.text/.rodata/.data/.bss):")
    for item in metrics["top_objects"]:
        text_lines.append(f"{item['size']:8d}  {item['object']}")
    text_lines.append("")

    text_path = Path(f"{output_prefix}.txt")
    json_path = Path(f"{output_prefix}.json")
    text_path.write_text("\n".join(text_lines), encoding="utf-8")
    json_path.write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
    return text_path, json_path


def summarize(args):
    bin_path = Path(args.bin)
    elf_path = Path(args.elf)
    map_path = Path(args.map)

    sections_output = run_command(["arm-none-eabi-size", str(elf_path)])
    sections = parse_size_output(sections_output)
    top_symbols = collect_top_symbols(elf_path, args.top_symbols, max_symbol_size=sections["dec"])
    object_totals = collect_object_totals(map_path)
    top_objects = collect_top_objects(object_totals, args.top_objects)

    metrics = {
        "board": args.board,
        "release": args.release,
        "bin_bytes": bin_path.stat().st_size,
        "sections": sections,
        "top_symbols": top_symbols,
        "top_objects": top_objects,
        "object_totals": object_totals,
    }
    text_path, json_path = write_summary_report(args.out_prefix, metrics)
    print(f"Wrote summary report: {text_path}")
    print(f"Wrote metrics json: {json_path}")


def build_object_map(entries):
    if isinstance(entries, dict):
        return {str(key): int(value) for key, value in entries.items()}
    return {item["object"]: int(item["size"]) for item in entries}


def top_object_deltas(base_objects, head_objects, top_count):
    all_keys = set(base_objects) | set(head_objects)
    deltas = []
    for key in all_keys:
        base_size = int(base_objects.get(key, 0))
        head_size = int(head_objects.get(key, 0))
        delta = head_size - base_size
        if delta == 0:
            continue
        deltas.append(
            {
                "object": key,
                "base": base_size,
                "head": head_size,
                "delta": delta,
                "abs_delta": abs(delta),
            }
        )
    deltas.sort(key=lambda item: item["abs_delta"], reverse=True)
    return deltas[:top_count]


def compare(args):
    base_metrics = json.loads(Path(args.base).read_text(encoding="utf-8"))
    head_metrics = json.loads(Path(args.head).read_text(encoding="utf-8"))

    delta_bin = int(head_metrics["bin_bytes"]) - int(base_metrics["bin_bytes"])
    delta_text = int(head_metrics["sections"]["text"]) - int(base_metrics["sections"]["text"])
    delta_data = int(head_metrics["sections"]["data"]) - int(base_metrics["sections"]["data"])
    delta_bss = int(head_metrics["sections"]["bss"]) - int(base_metrics["sections"]["bss"])
    delta_dec = int(head_metrics["sections"]["dec"]) - int(base_metrics["sections"]["dec"])

    base_objects = build_object_map(base_metrics.get("object_totals", base_metrics.get("top_objects", [])))
    head_objects = build_object_map(head_metrics.get("object_totals", head_metrics.get("top_objects", [])))
    object_deltas = top_object_deltas(base_objects, head_objects, args.top_objects)

    lines = []
    lines.append(f"# Size Comparison ({head_metrics.get('board', 'unknown')})")
    lines.append("")
    lines.append("| Metric | Base | Head | Delta |")
    lines.append("|---|---:|---:|---:|")
    lines.append(
        f"| `pixljs.bin` bytes | {base_metrics['bin_bytes']} | {head_metrics['bin_bytes']} | {delta_bin:+d} |"
    )
    lines.append(
        f"| `.text` | {base_metrics['sections']['text']} | {head_metrics['sections']['text']} | {delta_text:+d} |"
    )
    lines.append(
        f"| `.data` | {base_metrics['sections']['data']} | {head_metrics['sections']['data']} | {delta_data:+d} |"
    )
    lines.append(
        f"| `.bss` | {base_metrics['sections']['bss']} | {head_metrics['sections']['bss']} | {delta_bss:+d} |"
    )
    lines.append(
        f"| `dec` | {base_metrics['sections']['dec']} | {head_metrics['sections']['dec']} | {delta_dec:+d} |"
    )

    lines.append("")
    lines.append("## Top Object Deltas (from map summary)")
    lines.append("")
    if object_deltas:
        lines.append("| Object | Base | Head | Delta |")
        lines.append("|---|---:|---:|---:|")
        for item in object_deltas:
            lines.append(
                f"| `{item['object']}` | {item['base']} | {item['head']} | {item['delta']:+d} |"
            )
    else:
        lines.append("No object-level deltas found in the compared summaries.")

    output_path = Path(args.output)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote comparison report: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate and compare firmware size reports.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    summarize_parser = subparsers.add_parser("summarize", help="Generate a size report from build artifacts.")
    summarize_parser.add_argument("--bin", required=True, help="Path to pixljs.bin")
    summarize_parser.add_argument("--elf", required=True, help="Path to pixljs.out")
    summarize_parser.add_argument("--map", required=True, help="Path to pixljs.map")
    summarize_parser.add_argument("--top-symbols", type=int, default=20, help="Top symbols to include")
    summarize_parser.add_argument("--top-objects", type=int, default=20, help="Top objects to include")
    summarize_parser.add_argument("--board", default="unknown", help="Board name for report metadata")
    summarize_parser.add_argument("--release", default="1", help="Release flag metadata")
    summarize_parser.add_argument("--out-prefix", required=True, help="Output prefix for .txt/.json")
    summarize_parser.set_defaults(func=summarize)

    compare_parser = subparsers.add_parser("compare", help="Compare two JSON size reports.")
    compare_parser.add_argument("--base", required=True, help="Baseline size_report_*.json")
    compare_parser.add_argument("--head", required=True, help="Head size_report_*.json")
    compare_parser.add_argument("--output", required=True, help="Output markdown file path")
    compare_parser.add_argument("--top-objects", type=int, default=20, help="Top object deltas to print")
    compare_parser.set_defaults(func=compare)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
