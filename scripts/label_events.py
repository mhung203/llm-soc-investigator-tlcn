#!/usr/bin/env python3
import json
from pathlib import Path
from collections import Counter

BASE = Path.home() / "llm-soc/dataset/runs"

ATTACKER = "192.168.186.185"
ENDPOINT = "192.168.186.186"
SOC = "192.168.186.160"

def classify_wazuh(e, scenario, run_id):
    rule = str(e.get("rule", {}).get("id", ""))
    path = e.get("syscheck", {}).get("path", "")
    log = e.get("full_log", "").lower()
    agent = e.get("agent", {}).get("name", "")
    decoder = e.get("decoder", {}).get("name", "")

    if scenario == "EX":
        expected = (
            "/home/kali/exfil-lab/EX-001-retry-01.txt"
            if run_id == "EX-001"
            else f"/home/kali/exfil-lab/{run_id}.txt"
        )

        if path == expected and (
            rule == "554" or e.get("syscheck", {}).get("event") == "added"
        ):
            return "supporting_evidence", "FIM ghi nhận tạo file nguồn"

        if (
            agent == "Linux-01"
            and decoder in {"sshd", "pam", "systemd"}
            and SOC in log
        ):
            return "noise", "Hoạt động SSH điều khiển từ Ubuntu SOC"

        if decoder in {"sshd", "pam", "systemd"}:
            return "noise", "Hoạt động hệ thống hoặc phiên SSH, không chứng minh HTTP POST"

        return "uncertain", "Chưa đủ căn cứ từ sự kiện Wazuh"

    if agent == "Linux-01":
        if (
            ATTACKER in log
            and ("authentication failure" in log
                 or "failed password" in log
                 or "authentication failed" in log)
        ):
            return "attack_evidence", "SSH xác thực thất bại từ Kali"

        if rule in {"5760", "5557", "5503", "2502"}:
            return "supporting_evidence", "Cảnh báo xác thực thất bại trong cửa sổ BF"

        if ATTACKER in log and decoder == "sshd":
            return "supporting_evidence", "Hoạt động phiên SSH từ Kali"

    return "uncertain", "Chưa đủ căn cứ xác định liên quan Brute Force"

def classify_suricata(e, scenario, run_id):
    typ = e.get("event_type", "")
    src = e.get("src_ip")
    dst = e.get("dest_ip")

    if scenario == "BF":
        if typ == "ssh" and {src, dst} == {ATTACKER, ENDPOINT}:
            return "supporting_evidence", "Suricata quan sát giao thức SSH"
        if typ == "alert":
            return "uncertain", "Cần kiểm tra chữ ký Suricata"
        if typ == "stats":
            return "noise", "Thống kê hoạt động cảm biến"
        return "uncertain", "Không đủ căn cứ liên hệ với thử mật khẩu"

    port = 8080 if run_id == "EX-001" else 8081
    fwd = (
        src == ENDPOINT and dst == ATTACKER
        and e.get("dest_port") == port
    )
    rev = (
        src == ATTACKER and dst == ENDPOINT
        and e.get("src_port") == port
    )

    http = e.get("http", {})
    method_post = http.get("http_method") == "POST"
    upload = http.get("url") == "/upload"

    if fwd and typ == "http" and method_post and upload:
        return "attack_evidence", "HTTP POST /upload từ Linux-01 sang Kali"

    if fwd and typ == "fileinfo" and method_post and upload:
        size = e.get("fileinfo", {}).get("size")
        if size in (89, "89"):
            return "attack_evidence", "Suricata ghi nhận payload 89 byte"
        return "uncertain", "Fileinfo chiều gửi, cần xác minh kích thước"

    if rev and typ == "fileinfo":
        return "supporting_evidence", "Dữ liệu phản hồi từ receiver"

    if typ == "alert" and e.get("alert", {}).get("signature_id") == 2034635:
        return "noise", "Python HTTP ServerBanner, không phát hiện exfiltration"

    return "uncertain", "Chưa đủ căn cứ phân loại sự kiện mạng"

TOTAL = Counter()

for scenario, category in [
    ("BF", "brute_force"),
    ("EX", "data_exfiltration"),
]:
    for n in range(1, 11):
        run_id = f"{scenario}-{n:03d}"
        folder = BASE / category / run_id
        if run_id == "EX-001":
            folder = folder / "retry-01"

        output = folder / "event_labels.jsonl"
        if output.exists():
            raise SystemExit(f"STOP: {output} đã tồn tại, không ghi đè.")

        labeled = []
        counts = Counter()

        for source, filename in [
            ("wazuh_alert", "alerts.json"),
            ("wazuh_raw", "archives.json"),
            ("suricata", "suricata_eve.json"),
        ]:
            path = folder / filename
            if not path.exists():
                continue

            with path.open() as f:
                for index, line in enumerate(f, 1):
                    if not line.strip():
                        continue

                    e = json.loads(line)
                    if source == "suricata":
                        label, reason = classify_suricata(e, scenario, run_id)
                    else:
                        label, reason = classify_wazuh(e, scenario, run_id)

                    record = {
                        "run_id": run_id,
                        "source": source,
                        "source_file": filename,
                        "source_line": index,
                        "event_id": e.get("id"),
                        "timestamp": e.get("timestamp"),
                        "label": label,
                        "reason": reason,
                        "label_method": "rule_based_provisional",
                    }
                    labeled.append(record)
                    counts[label] += 1

        with output.open("w") as f:
            for record in labeled:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

        TOTAL.update(counts)
        print(
            f"{run_id}: {len(labeled)} events | "
            + " | ".join(f"{k}={counts[k]}" for k in (
                "attack_evidence",
                "supporting_evidence",
                "noise",
                "uncertain",
            ))
        )

print("\nTOTAL:", dict(TOTAL))
