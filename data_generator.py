# data_generator.py

import csv
import random
import json
import os
from datetime import datetime, timedelta

# ---------- CONFIG (edit these to control generation) ----------
OUT_CSV = "iot_traffic.csv"
OUT_META = OUT_CSV + ".meta.json"

N_ROWS = 5000

# Fraction of events that are attacks (approx). 0.0 = none, 1.0 = all.
ATTACK_RATE = 0.0  # default: 12% of events are attacks (reasonable for many IoT setups)

# Among attack events, how many are DoS vs Probe
DOS_SHARE = 0.40     # 65% of attacks are DoS, 35% are Probe

# Burst settings: with probability BURST_PROB we emit a short burst of attacks
BURST_PROB = 0.08           # 8% of the time we create a burst instead of a single event
BURST_LEN_RANGE = (3, 7)    # burst length between 3 and 7 attack packets

# Timing: inter-arrival spacing (rough)
MAX_NORMAL_INTERVAL = 2.0   # seconds added after normal packets (random up to this)
MAX_BURST_INTERVAL = 0.8    # seconds between packets inside a burst

# Other packet parameter ranges
PROTOCOLS = ["TCP", "UDP", "ICMP"]
MIN_PKT_LEN = 40
MAX_PKT_LEN = 1500
MIN_SRC_PORT = 1000
MAX_SRC_PORT = 65535

# Destination port choices for DoS (common services) and normal
COMMON_SERVICE_PORTS = [80, 443, 8080, 1883]

# ----------------------------------------------------------------

def gen_normal_packet(now):
    return {
        "timestamp": now.isoformat(),
        "src_port": random.randint(MIN_SRC_PORT, MAX_SRC_PORT),
        "dst_port": random.randint(20, 8080),
        "protocol": random.choices(PROTOCOLS, weights=[0.7, 0.25, 0.05])[0],
        "packet_size": random.randint(40, 600),
        "label": 0
    }

def gen_dos_packet(now):
    return {
        "timestamp": now.isoformat(),
        "src_port": random.randint(MIN_SRC_PORT, MAX_SRC_PORT),
        "dst_port": random.choice(COMMON_SERVICE_PORTS),
        "protocol": random.choice(["UDP", "TCP"]),
        "packet_size": random.randint(1000, MAX_PKT_LEN),
        "label": 1
    }

def gen_probe_packet(now):
    return {
        "timestamp": now.isoformat(),
        "src_port": random.randint(MIN_SRC_PORT, MAX_SRC_PORT),
        "dst_port": random.randint(1, 1024),
        "protocol": "TCP",
        "packet_size": random.randint(40, 200),
        "label": 2
    }

def write_csv(rows, out_file):
    os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
    with open(out_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "src_port", "dst_port", "protocol", "packet_size", "label"])
        for r in rows:
            writer.writerow([r["timestamp"], r["src_port"], r["dst_port"], r["protocol"], r["packet_size"], r["label"]])

def write_meta(meta, out_file):
    with open(out_file, "w") as f:
        json.dump(meta, f, indent=2)

def generate_mixed_rows(n_rows):
    rows = []
    now = datetime.now()
    generated = 0
    while generated < n_rows:
        # Decide if we should produce a burst or a single event
        if random.random() < BURST_PROB:
            # Burst of attacks
            burst_len = random.randint(*BURST_LEN_RANGE)
            # For realism, choose attack type for whole burst
            attack_type = "dos" if random.random() < DOS_SHARE else "probe"
            for _ in range(burst_len):
                if generated >= n_rows:
                    break
                if attack_type == "dos":
                    pkt = gen_dos_packet(now)
                else:
                    pkt = gen_probe_packet(now)
                rows.append(pkt)
                generated += 1
                # advance time by a small amount inside burst
                now += timedelta(seconds=random.random() * MAX_BURST_INTERVAL)
            # after burst, add a slightly longer gap
            now += timedelta(seconds=random.random() * MAX_NORMAL_INTERVAL)
            continue

        # Non-burst: decide if this single event is attack or normal
        if random.random() < ATTACK_RATE:
            # single attack
            if random.random() < DOS_SHARE:
                pkt = gen_dos_packet(now)
            else:
                pkt = gen_probe_packet(now)
        else:
            pkt = gen_normal_packet(now)

        rows.append(pkt)
        generated += 1
        # advance time after each event
        now += timedelta(seconds=random.random() * MAX_NORMAL_INTERVAL)

    return rows[:n_rows]

if __name__ == "__main__":
    print(f"[+] Generating {N_ROWS} rows -> {OUT_CSV}")
    print(f"    ATTACK_RATE={ATTACK_RATE}, DOS_SHARE={DOS_SHARE}, BURST_PROB={BURST_PROB}, BURST_LEN_RANGE={BURST_LEN_RANGE}")
    rows = generate_mixed_rows(N_ROWS)
    write_csv(rows, OUT_CSV)
    meta = {
        "rows": N_ROWS,
        "attack_rate": ATTACK_RATE,
        "dos_share": DOS_SHARE,
        "burst_prob": BURST_PROB,
        "burst_len_range": BURST_LEN_RANGE,
        "timestamp": datetime.now().isoformat()
    }
    write_meta(meta, OUT_META)
    print(f"[✓] Saved {OUT_CSV} and metadata {OUT_META}")
