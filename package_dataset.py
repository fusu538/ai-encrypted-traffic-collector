"""Package the verified web-capture pilot without inventing flow ownership."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import struct
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parent
STAGE = ROOT / "staging_20261026"
OUTPUT = ROOT / "大模型"
FIXTURE = ROOT / "fixtures" / "red_circle_blue_square.png"
TOOLS = Path(r"C:\Program Files\Wireshark")
APPS = {"qwen": "千问", "yuanbao": "元宝", "doubao": "豆包"}
ELEMENTS = {
    "A1": "A1_简单对话.pcap",
    "A2": "A2_长文生成.pcap",
    "A3": "A3_图片生成.pcap",
    "A4": "A4_图片理解.pcap",
}
HOST_SUFFIXES = {
    "qwen": ("qianwen.com",),
    "yuanbao": (
        "yuanbao.tencent.com",
        "hunyuan-prod-1258344703.cos.ap-guangzhou.myqcloud.com",
    ),
    "doubao": ("doubao.com", "flow-imagex-sign.byteimg.com"),
}
FIELD_NAMES = [
    "frame.number", "frame.interface_id", "frame.time_epoch", "frame.len",
    "ip.src", "ipv6.src", "tcp.srcport", "udp.srcport",
    "ip.dst", "ipv6.dst", "tcp.dstport", "udp.dstport",
    "tcp.stream", "udp.stream", "http.host",
    "tls.handshake.extensions_server_name", "http.request.method",
    "dns.qry.name", "tcp.flags.syn", "tcp.flags.ack",
    "tcp.analysis.retransmission", "tcp.analysis.out_of_order",
    "tcp.analysis.lost_segment", "tcp.analysis.ack_lost_segment",
]


def invoke(exe: str, *args: object) -> str:
    result = subprocess.run(
        [str(TOOLS / exe), *(str(arg) for arg in args)],
        check=True, capture_output=True, text=True, encoding="utf-8",
        errors="replace",
    )
    return result.stdout


def parse_time(value: str) -> float:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def chosen_operations() -> dict[str, dict[str, tuple[Path, dict]]]:
    selected: dict[str, dict[str, tuple[Path, dict]]] = defaultdict(dict)
    for folder in sorted(STAGE.iterdir()):
        opfile = folder / "operation.json"
        if not folder.is_dir() or not opfile.exists():
            continue
        op = json.loads(opfile.read_text(encoding="utf-8-sig"))
        if op.get("success") is True and op.get("app") in APPS:
            previous = selected[op["app"]].get(op["element"])
            if previous is None or parse_time(op["send_started_at"]) > parse_time(
                previous[1]["send_started_at"]
            ):
                selected[op["app"]][op["element"]] = (folder, op)
    for app in APPS:
        missing = set(ELEMENTS) - set(selected[app])
        if missing:
            raise RuntimeError(f"{app}: missing successful activities {sorted(missing)}")
    return selected


def capture_path(folder: Path) -> Path:
    trimmed = folder / "capture_trimmed.pcapng"
    return trimmed if trimmed.exists() else folder / "capture.pcapng"


def valid_image(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size < 100:
        return False
    header = path.open("rb").read(12)
    return (
        header.startswith(b"\x89PNG\r\n\x1a\n")
        or header.startswith(b"\xff\xd8\xff")
        or (header[:4] == b"RIFF" and header[8:12] == b"WEBP")
    )


def validate_operation(folder: Path, op: dict) -> Path:
    source = capture_path(folder)
    if not source.is_file() or not op["prompt"].isascii():
        raise RuntimeError(f"{folder}: capture missing or prompt is not English ASCII")
    if op["element"] == "A2" and len(op.get("answer", "").split()) < 500:
        raise RuntimeError(f"{folder}: long-form answer has fewer than 500 words")
    if op["element"] in ("A1", "A2", "A4") and not op.get("answer"):
        raise RuntimeError(f"{folder}: text answer missing")
    if op["element"] == "A3":
        images = op.get("generated_files", [])
        if not images or any(not valid_image(folder / image) for image in images):
            raise RuntimeError(f"{folder}: generated image missing or empty")
    first = last = None
    for _, _, timestamp, _, _ in pcapng_packets(source):
        first = timestamp / 1_000_000_000 if first is None else first
        last = timestamp / 1_000_000_000
    sent = parse_time(op["send_started_at"])
    answered = parse_time(op["response_observed_at"])
    if op.get("capture_started_at") and op.get("capture_ended_at"):
        start = parse_time(op["capture_started_at"])
        end = parse_time(op["capture_ended_at"])
        if first is None or not start <= sent <= answered <= end:
            raise RuntimeError(f"{folder}: action timestamps lie outside capture window")
        if not start - 2 <= first <= end + 2 or last > end + 2:
            raise RuntimeError(f"{folder}: packet timestamps lie outside capture window")
    elif first is None or not first - 1 <= sent <= answered <= last + 1:
        raise RuntimeError(f"{folder}: action timestamps lie outside capture")
    return source


def pcapng_packets(path: Path):
    """Yield (frame number, link type, timestamp in ns, bytes) from one section."""
    with path.open("rb") as stream:
        endian = "<"
        interfaces: list[tuple[int, int]] = []
        frame_number = 0
        while header := stream.read(8):
            if len(header) != 8:
                raise ValueError(f"Truncated pcapng header: {path}")
            block_type, block_size = struct.unpack(endian + "II", header)
            if block_size < 12 or block_size > 32_000_000:
                raise ValueError(f"Invalid pcapng block size {block_size}: {path}")
            body_and_tail = stream.read(block_size - 8)
            if len(body_and_tail) != block_size - 8:
                raise ValueError(f"Truncated pcapng block: {path}")
            body = body_and_tail[:-4]
            if struct.unpack(endian + "I", body_and_tail[-4:])[0] != block_size:
                raise ValueError(f"Invalid pcapng trailer: {path}")
            if block_type == 0x0A0D0D0A:
                magic = body[:4]
                endian = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
                interfaces = []
            elif block_type == 1:
                linktype = struct.unpack_from(endian + "H", body)[0]
                unit_ns = 1000  # pcapng default: microseconds
                offset = 8
                while offset + 4 <= len(body):
                    code, length = struct.unpack_from(endian + "HH", body, offset)
                    if code == 0:
                        break
                    value = body[offset + 4:offset + 4 + length]
                    if code == 9 and value:
                        resolution = value[0]
                        unit_ns = (
                            round(1_000_000_000 / (2 ** (resolution & 0x7F)))
                            if resolution & 0x80
                            else 10 ** (9 - resolution)
                        )
                    offset += 4 + ((length + 3) // 4) * 4
                interfaces.append((linktype, unit_ns))
            elif block_type == 6:
                interface, hi, lo, captured, original = struct.unpack_from(
                    endian + "IIIII", body
                )
                frame_number += 1
                linktype, unit_ns = interfaces[interface]
                timestamp = ((hi << 32) | lo) * unit_ns
                packet = body[20:20 + captured]
                if len(packet) != captured:
                    raise ValueError(f"Truncated packet {frame_number}: {path}")
                yield frame_number, linktype, timestamp, packet, original


def write_pcap(source: Path, destination: Path, wanted: set[int] | None = None) -> int:
    """Write a single-link-type pcap, retaining the captured interface format."""
    packets = pcapng_packets(source)
    first = next(packets, None)
    if first is None:
        raise ValueError(f'No packets in {source}')
    linktype = first[1]
    count = 0
    from itertools import chain
    with destination.open('wb') as out:
        out.write(struct.pack('<IHHIIII', 0xA1B23C4D, 2, 4, 0, 0, 262144, linktype))
        for number, packet_linktype, timestamp, packet, original in chain([first], packets):
            if packet_linktype != linktype:
                raise ValueError(f'Mixed link types in {source}; cannot write a single pcap')
            if wanted is not None and number not in wanted:
                continue
            seconds, nanoseconds = divmod(timestamp, 1_000_000_000)
            out.write(struct.pack('<IIII', seconds, nanoseconds, len(packet), original))
            out.write(packet)
            count += 1
    return count


def norm_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if host.endswith(":443") or host.endswith(":80"):
        host = host.rsplit(":", 1)[0]
    return host


def matching_host(host: str, app: str) -> bool:
    return any(
        host == suffix or host.endswith("." + suffix)
        for suffix in HOST_SUFFIXES[app]
    )


def analyze_flows(pcap: Path, app: str):
    args = ["-r", pcap, "-T", "fields", "-E", "separator=/t",
            "-E", "occurrence=f"]
    for field in FIELD_NAMES:
        args.extend(("-e", field))
    raw = invoke("tshark.exe", *args)
    flows: dict[tuple, dict] = {}
    frame_keys: dict[int, tuple] = {}
    signals: dict[tuple, set[str]] = defaultdict(set)
    methods: dict[tuple, set[str]] = defaultdict(set)
    counters = Counter()
    for line in raw.splitlines():
        parts = line.split("\t")
        if len(parts) < len(FIELD_NAMES):
            parts.extend([""] * (len(FIELD_NAMES) - len(parts)))
        d = dict(zip(FIELD_NAMES, parts))
        frame = int(d["frame.number"])
        proto = "TCP" if d["tcp.stream"] else "UDP" if d["udp.stream"] else ""
        if not proto:
            continue
        src = d["ip.src"] or d["ipv6.src"]
        dst = d["ip.dst"] or d["ipv6.dst"]
        sport = d["tcp.srcport"] or d["udp.srcport"]
        dport = d["tcp.dstport"] or d["udp.dstport"]
        stream_id = d["tcp.stream"] or d["udp.stream"]
        key = (d["frame.interface_id"], proto, stream_id)
        if key not in flows:
            flows[key] = {
                "proto": proto, "a_ip": src, "a_port": int(sport or 0),
                "b_ip": dst, "b_port": int(dport or 0),
                "pkts": 0, "bytes": 0,
                "first_ts": float(d["frame.time_epoch"]),
                "last_ts": float(d["frame.time_epoch"]),
                "pid": None, "proc": None, "label": "unattributed",
                "via": "host_not_observed",
            }
        row = flows[key]
        row["pkts"] += 1
        row["bytes"] += int(d["frame.len"] or 0)
        row["last_ts"] = float(d["frame.time_epoch"])
        frame_keys[frame] = key
        for field in ("http.host", "tls.handshake.extensions_server_name"):
            if d[field]:
                signals[key].add(norm_host(d[field]))
                methods[key].add("http_connect" if field == "http.host" else "tls_sni")
        if d["dns.qry.name"]:
            counters["dns_queries"] += 1
        for name, field in (
            ("retransmission", "tcp.analysis.retransmission"),
            ("out_of_order", "tcp.analysis.out_of_order"),
            ("lost_segment", "tcp.analysis.lost_segment"),
            ("ack_lost_segment", "tcp.analysis.ack_lost_segment"),
        ):
            if d[field]:
                counters[name] += 1
        if proto == "TCP":
            if d["tcp.flags.syn"] == "1" and d["tcp.flags.ack"] == "0":
                counters[("syn", key)] = 1
            if d["tcp.flags.syn"] == "1" and d["tcp.flags.ack"] == "1":
                counters[("synack", key)] = 1
    for key, row in flows.items():
        hosts = sorted(signals[key])
        target_hosts = [host for host in hosts if matching_host(host, app)]
        if target_hosts:
            row["label"] = "target"
            row["via"] = "+".join(sorted(methods[key])) + ":" + target_hosts[0]
        elif hosts:
            row["label"] = "background"
            row["via"] = "+".join(sorted(methods[key])) + ":" + hosts[0]
    target_frames = {
        number for number, key in frame_keys.items()
        if flows[key]["label"] == "target"
    }
    rows = sorted(flows.values(), key=lambda row: row["first_ts"])
    tcp_keys = [key for key in flows if key[1] == "TCP"]
    syn_complete = sum(
        bool(counters[("syn", key)] and counters[("synack", key)])
        for key in tcp_keys
    )
    return rows, target_frames, counters, len(tcp_keys), syn_complete


def json_dump(path: Path, data: object):
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def package_one(app: str, operations: dict[str, tuple[Path, dict]]):
    destination = OUTPUT / APPS[app]
    media = destination / "media"
    elements = destination / "elements"
    media.mkdir(parents=True, exist_ok=True)
    elements.mkdir(parents=True, exist_ok=True)
    sources = [
        validate_operation(*operations[element]) for element in ELEMENTS
    ]
    invoke("mergecap.exe", "-w", destination / "capture.pcapng", *sources)
    source_rows = []
    element_counts = {}
    event_lines = []
    for index, element in enumerate(ELEMENTS, start=1):
        folder, op = operations[element]
        source = validate_operation(folder, op)
        count = write_pcap(source, elements / ELEMENTS[element])
        element_counts[element] = count
        if count == 0:
            raise RuntimeError(f"{app} {element}: no captured packets")
        input_image = None
        if element == "A4":
            fixture = FIXTURE
            shutil.copy2(fixture, media / fixture.name)
            input_image = "media/" + fixture.name
        response_files = []
        for image in op.get("generated_files", []):
            image_path = folder / image
            if not image_path.exists():
                raise RuntimeError(f"Missing generated image: {image_path}")
            target_name = element + "_" + image_path.name
            shutil.copy2(image_path, media / target_name)
            response_files.append("media/" + target_name)
        record = {
            "app": app, "app_display": APPS[app],
            "element": element, "activity": op["activity"],
            "prompt": op["prompt"], "prompt_group": op.get("prompt_group"),
            "answer": None if element == "A3" else op.get("answer", ""),
            "response_type": "image" if element == "A3" else "text",
            "collector_observation": op.get("answer") if element == "A3" else None,
            "input_image": input_image, "response_files": response_files,
            "send_started_at": op["send_started_at"],
            "response_observed_at": op["response_observed_at"],
            "chat_url": op.get("chat_url"),
            "success": True, "source_capture": f"elements/{ELEMENTS[element]}",
            "attempts": 2 if op.get("retry_at") else 1,
        }
        source_rows.append(record)
        for action, timestamp in (
            ("chat_send", record["send_started_at"]),
            ("response_complete", record["response_observed_at"]),
        ):
            event_lines.append(json.dumps({
                "ts": round(parse_time(timestamp), 3),
                "action": action,
                "taxonomy_path": "llm/chat/" + action,
                "url": record["chat_url"] or "",
                "title": app + "/" + element,
                "detail": record["activity"],
                "seg": index,
                "element": element,
            }, ensure_ascii=False))
    (destination / "events.jsonl").write_text(
        "\n".join(event_lines) + "\n", encoding="utf-8"
    )
    json_dump(destination / "prompts_answers_labeled.json", source_rows)
    rows, target_frames, counts, tcp_streams, syn_complete = analyze_flows(
        destination / "capture.pcapng", app
    )
    pure_count = write_pcap(
        destination / "capture.pcapng", destination / "pure.pcap", target_frames
    )
    by_label = Counter()
    distribution = defaultdict(lambda: {"flows": 0, "bytes": 0})
    for row in rows:
        by_label[row["label"]] += row["bytes"]
        bucket = distribution[row["proto"].lower() + "/" + row["label"]]
        bucket["flows"] += 1
        bucket["bytes"] += row["bytes"]
    total = sum(by_label.values())
    metadata = {
        "pcap": "capture.pcapng", "timeline": "events.jsonl", "legacy": "",
        "target_pids": [], "poll_interval_s": None, "tolerance_s": None,
        "generated_at": dt.datetime.now().astimezone().isoformat(),
        "pcap_stats": {"source_activities": len(ELEMENTS), "pure_packets": pure_count},
        "etw_pass2": None,
    }
    summary = {
        "total_bytes": total,
        "bytes_by_label": {
            label: by_label[label]
            for label in ("target", "background", "unattributed")
        },
        "unattributed_ratio": round(by_label["unattributed"] / total, 6)
        if total else None,
        "top_processes": [],
        "pid_reuse_downgraded": 0, "etw_rescued": 0,
        "udp_pass25": None, "etw_phase2_trigger": None,
    }
    json_dump(destination / "flows_labeled.json", {
        "meta": metadata, "flows": rows, "summary": summary
    })
    checks = {
        "noise_domain_hits": None,
        "dns_noise_queries": counts["dns_queries"],
        "non_ip_frames": None,
        "tcp_streams": tcp_streams,
        "syn_complete": syn_complete,
        "midstream": tcp_streams - syn_complete,
        "syn_rate": round(syn_complete / tcp_streams, 4) if tcp_streams else None,
        "retransmission": counts["retransmission"],
        "out_of_order": counts["out_of_order"],
        "lost_segment": counts["lost_segment"],
        "ack_lost_segment": counts["ack_lost_segment"],
        "flow_distribution": dict(distribution),
        "quic_note": "QUIC ownership was not verified in this pilot.",
        "flows_labeled_target": sum(row["label"] == "target" for row in rows),
        "pure_stream_delta": None,
    }
    defects = [
        "WLAN capture alone does not prove that traffic bypassed proxies or VPNs.",
        "No PID or process timeline was collected; unmatched flows remain unattributed.",
        "Element pcaps include all WLAN traffic in each activity window, including background traffic.",
        "Host-based matching may miss QUIC, reused connections, CDN domains, and encrypted SNI.",
        "The strict training-ready purity gate was not run.",
    ]
    json_dump(destination / "pcap_quality.json", {
        "ok": False, "pcap": "pure.pcap", "checks": checks,
        "defects": defects, "denylist_size": None,
        "blacklist_version": None,
    })
    quality = [
        f"# 出厂合格证 (QUALITY) — {APPS[app]} pilot",
        "",
        "状态: 本应用所选活动的试采完成；本目录仍是 pilot，不是训练集成品。",
        f"生成时间: {metadata['generated_at']}",
        "",
        "## 抓包和标注",
        f"- 原始会话: capture.pcapng；所选活动各有一个 elements PCAP。",
        f"- pure.pcap: {pure_count} 个通过 HTTP Host/TLS SNI 域名匹配到目标的包（可能遗漏目标流量）。",
        f"- 目标流字节: {by_label['target']}；未归属流字节: {by_label['unattributed']}。",
        f"- TCP SYN 完整流: {syn_complete}/{tcp_streams}。",
        "",
        "## 限制",
        *[f"- {item}" for item in defects],
        "- 提示词长度只是请求要求；服务端可能返回超出指定字数的长文。",
        "",
        "## 要素包",
        *[f"- {ELEMENTS[element]}: {element_counts[element]} packets"
          for element in ELEMENTS],
    ]
    (destination / "QUALITY.md").write_text(
        "\n".join(quality) + "\n", encoding="utf-8"
    )
    manifest = [
        f"app: {APPS[app]}",
        f"session: '{OUTPUT.parent.name}'",
        f"generated: '{metadata['generated_at']}'",
        "status: pilot_only",
        "files:",
        "  capture.pcapng: WLAN 原始抓包合并文件",
        "  pure.pcap: 基于可见域名初步筛选的 WLAN 流量",
        "  elements/: 所选活动的 WLAN 数据包，含可能的背景流量",
        "  events.jsonl: 活动操作时间线",
        "  flows_labeled.json: 每条流的五元组和归属标签",
        "  pcap_quality.json: 质量检查结果",
        "  QUALITY.md: 人工阅读的质量报告",
        "  prompts_answers_labeled.json: 英文提示词、回答和活动标签",
        "  media/: 输入测试图与实际生成图片",
    ]
    (destination / "MANIFEST.yaml").write_text(
        "\n".join(manifest) + "\n", encoding="utf-8"
    )
    for name in ("capture.pcapng", "pure.pcap"):
        invoke("capinfos.exe", destination / name)
    for filename in ELEMENTS.values():
        invoke("capinfos.exe", elements / filename)
    print(f"{app}: {len(rows)} flows, {pure_count} target packets")


def main():
    global STAGE, OUTPUT, FIXTURE, APPS, ELEMENTS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging", type=Path, default=STAGE)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--fixture", type=Path, default=FIXTURE)
    parser.add_argument("--apps", nargs="+", choices=list(APPS), default=list(APPS))
    parser.add_argument("--activities", nargs="+", choices=list(ELEMENTS), default=list(ELEMENTS))
    parser.add_argument("--zip", type=Path, help="Optional archive path outside output")
    args = parser.parse_args()
    STAGE, OUTPUT, FIXTURE = args.staging, args.output, args.fixture
    APPS = {name: APPS[name] for name in args.apps}
    ELEMENTS = {name: ELEMENTS[name] for name in args.activities}
    operations = chosen_operations()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for app in APPS:
        package_one(app, operations[app])
    if args.zip:
        archive = args.zip.resolve()
        if archive == OUTPUT.resolve() or OUTPUT.resolve() in archive.parents:
            raise RuntimeError("Archive must be outside the output directory")
        archive.parent.mkdir(parents=True, exist_ok=True)
        with ZipFile(archive, "w", ZIP_DEFLATED, compresslevel=1) as zipped:
            for file in OUTPUT.rglob("*"):
                if file.is_file():
                    zipped.write(file, file.relative_to(OUTPUT.parent))
        with ZipFile(archive) as zipped:
            bad = zipped.testzip()
            if bad:
                raise RuntimeError(f"Archive CRC failed: {bad}")
        print(f"archive: {archive}")


if __name__ == "__main__":
    main()
