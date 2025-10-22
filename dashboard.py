# dashboard.py
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import time
import os
import json
from datetime import datetime
import plotly.express as px
from streamlit_autorefresh import st_autorefresh

# ------------------------------
# Helper: discover CSV datasets in the project folder
# ------------------------------
def discover_csvs(folder="."):
    csvs = [f for f in os.listdir(folder) if f.lower().endswith(".csv")]
    # sort to keep stable order
    csvs.sort()
    return csvs

# ------------------------------
# Load model & artifacts
# ------------------------------
MODEL_DIR = "model_assets"
model = joblib.load(os.path.join(MODEL_DIR, "rf_model.joblib"))
scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib"))
encoders = joblib.load(os.path.join(MODEL_DIR, "encoders.joblib"))  # {"proto": LabelEncoder(...)}

st.set_page_config(page_title="IoT NIDS Dashboard (synced)", layout="wide", page_icon="🛰️")

# ------------------------------
# Sidebar: dataset + controls
# ------------------------------
st.sidebar.header("Controls")

# dataset discovery
csv_files = discover_csvs(".")
if not csv_files:
    st.sidebar.error("No CSV datasets found in the project folder.")
dataset_choice = st.sidebar.selectbox("Choose dataset (for reference only)", csv_files or ["(none)"])

# attempt to load metadata for the selected dataset (optional)
meta_injection = None
if dataset_choice and os.path.exists(dataset_choice + ".meta.json"):
    try:
        with open(dataset_choice + ".meta.json", "r") as mf:
            meta = json.load(mf)
            meta_injection = int(meta.get("injection_interval")) if meta.get("injection_interval") else None
    except Exception:
        meta_injection = None

# injection interval: if metadata exists, default to it, but allow override via slider
if "injection_interval" not in st.session_state:
    st.session_state.injection_interval = int(meta_injection) if meta_injection is not None else 20

# show meta information and allow override
if meta_injection is not None:
    st.sidebar.markdown(f"**Dataset metadata found:** injection_interval = **{meta_injection}** (from `{dataset_choice}.meta.json`)")

st.session_state.injection_interval = st.sidebar.number_input(
    "Injection interval (packets) — guarantee 1 attack every N packets",
    min_value=2, max_value=1000, value=int(st.session_state.injection_interval), step=1
)

# recent window and update interval
update_interval = st.sidebar.slider("Update interval (seconds)", 1, 5, 2)
recent_window = st.sidebar.slider("Recent traffic window (packets) for trend chart", 10, 500, 50, step=10)

# autorefresh
st_autorefresh(interval=update_interval * 1000, limit=None, key="auto_refresh")

# ------------------------------
# Page title & description
# ------------------------------
st.title("IoT Network Intrusion Detection System (NIDS)")
st.markdown(
    """This dashboard monitors **IoT network traffic** in real-time and detects potential **cyber intrusions**.
It uses a trained **Random Forest Machine Learning model** to classify network activity as:
- 🟢 Normal
- 🟡 Probe Attack
- 🔴 DoS (Denial of Service)"""
)

# ------------------------------
# Session state init
# ------------------------------
if "data" not in st.session_state:
    st.session_state.data = pd.DataFrame(columns=["timestamp","src_port","dst_port","protocol","packet_size","label"])
if "threat_history" not in st.session_state:
    st.session_state.threat_history = pd.DataFrame(columns=["timestamp","src_port","dst_port","protocol","packet_size","prediction"])
if "simulation_running" not in st.session_state:
    st.session_state.simulation_running = False
if "packet_counter" not in st.session_state:
    st.session_state.packet_counter = 0
if "last_dataset" not in st.session_state:
    st.session_state.last_dataset = dataset_choice

# ------------------------------
# Start/Stop buttons (paused by default)
# ------------------------------
c1, c2 = st.columns([1, 1])
if c1.button("▶️ Start Simulation", key="start"):
    st.session_state.simulation_running = True
    st.success("Simulation started ✅")
if c2.button("⏸️ Stop Simulation", key="stop"):
    st.session_state.simulation_running = False
    st.warning("Simulation paused ⏸️")

# If user changed dataset selection, reset the dashboard (so dataset metadata takes effect)
if dataset_choice != st.session_state.last_dataset:
    st.session_state.data = pd.DataFrame(columns=st.session_state.data.columns)
    st.session_state.threat_history = pd.DataFrame(columns=st.session_state.threat_history.columns)
    st.session_state.simulation_running = False
    st.session_state.packet_counter = 0
    st.session_state.last_dataset = dataset_choice
    st.experimental_rerun()

# ------------------------------
# Packet generation helpers (bursty + deterministic injection)
# ------------------------------
NORMAL_PROB = 0.7
DOS_PROB = 0.15
PROBE_PROB = 0.15

def generate_normal_packet():
    protocols = ["TCP","UDP","ICMP"]
    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "src_port": np.random.randint(1000, 65535),
        "dst_port": np.random.randint(20,8080),
        "protocol": np.random.choice(protocols, p=[0.7,0.25,0.05]),
        "packet_size": np.random.randint(40,600),
        "label": 0
    }

def generate_dos_packet():
    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "src_port": np.random.randint(1000,65535),
        "dst_port": np.random.choice([80,443,8080,1883]),
        "protocol": np.random.choice(["UDP","TCP"], p=[0.6,0.4]),
        "packet_size": np.random.randint(1000,1500),
        "label": 1
    }

def generate_probe_packet():
    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "src_port": np.random.randint(1000,65535),
        "dst_port": np.random.randint(1,1024),
        "protocol": "TCP",
        "packet_size": np.random.randint(40,120),
        "label": 2
    }

def simulate_bursty_packets():
    r = np.random.rand()
    packets = []
    if r < NORMAL_PROB:
        packets.append(generate_normal_packet())
    elif r < NORMAL_PROB + DOS_PROB:
        burst_len = np.random.randint(3,8)
        for _ in range(burst_len):
            packets.append(generate_dos_packet())
    else:
        burst_len = np.random.randint(3,8)
        for _ in range(burst_len):
            packets.append(generate_probe_packet())
    return pd.DataFrame(packets)

def simulate_with_forced_injection(injection_interval_local):
    # generate bursty set
    df_new = simulate_bursty_packets()
    current_count = st.session_state.packet_counter
    need_force = False
    force_index = None
    for k in range(1, len(df_new)+1):
        if (current_count + k) % injection_interval_local == 0:
            need_force = True
            force_index = k - 1
            break
    if need_force:
        attack_type = np.random.choice([1,2], p=[0.7,0.3])
        if attack_type == 1:
            df_new.iloc[force_index] = pd.Series(generate_dos_packet())
        else:
            df_new.iloc[force_index] = pd.Series(generate_probe_packet())
    return df_new

# ------------------------------
# Prediction with safe encoding
# ------------------------------
def predict_intrusion(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df.copy()
    df_encoded = df.copy()
    proto_le = encoders.get("proto")
    if proto_le is None:
        raise RuntimeError("Encoder key 'proto' not found in encoders joblib.")
    known = set(proto_le.classes_.astype(str))
    df_encoded["protocol"] = df_encoded["protocol"].astype(str)
    df_encoded["protocol"] = df_encoded["protocol"].apply(lambda x: x if x in known else proto_le.classes_[0])
    df_encoded["protocol"] = proto_le.transform(df_encoded["protocol"])
    features = df_encoded[["src_port","dst_port","protocol","packet_size"]]
    features_scaled = scaler.transform(features)
    df["prediction"] = model.predict(features_scaled)
    return df

# ------------------------------
# Append new packets only when simulation_running
# ------------------------------
if st.session_state.simulation_running:
    new_packets = simulate_with_forced_injection(st.session_state.injection_interval)
    st.session_state.data = pd.concat([st.session_state.data, new_packets], ignore_index=True)
    st.session_state.packet_counter += len(new_packets)

    # predict only on the newly added packets and append new attacks uniquely
    new_pred = predict_intrusion(new_packets.copy())
    attacks = new_pred[new_pred["prediction"] != 0]
    if not attacks.empty:
        st.session_state.threat_history = pd.concat([st.session_state.threat_history, attacks], ignore_index=True)

# ------------------------------
# Full predictions for metrics & visuals
# ------------------------------
if len(st.session_state.data) > 0:
    pred_df = predict_intrusion(st.session_state.data.copy())
else:
    pred_df = pd.DataFrame(columns=["timestamp","src_port","dst_port","protocol","packet_size","label","prediction"])

# ------------------------------
# Metrics
# ------------------------------
total_packets = len(pred_df)
normal_packets = int((pred_df["prediction"] == 0).sum()) if total_packets > 0 else 0
attack_packets = total_packets - normal_packets
attack_rate = (attack_packets / total_packets) * 100 if total_packets > 0 else 0.0

c1, c2, c3 = st.columns(3)
c1.metric("Total Packets", total_packets)
c2.metric("Detected Attacks", attack_packets)
c3.metric("Attack Rate (%)", f"{attack_rate:.2f}")

# ------------------------------
# Visualizations
# ------------------------------
fig_hist = px.histogram(pred_df, x="prediction", color="prediction",
                        labels={"prediction":"Class"},
                        color_discrete_map={0:"green",1:"red",2:"orange"},
                        title="Threat Type Distribution")
st.plotly_chart(fig_hist, use_container_width=True)

recent_n = int(recent_window)
fig_trend = px.line(pred_df.tail(recent_n), x="timestamp", y="packet_size", color="prediction",
                    labels={"timestamp":"Time","packet_size":"Packet Size"},
                    title=f"Recent Traffic (last {recent_n} packets)")
st.plotly_chart(fig_trend, use_container_width=True)

# ------------------------------
# Logs & Threat history
# ------------------------------
st.subheader("Latest Packet Logs")
st.dataframe(pred_df.tail(10).reset_index(drop=True), use_container_width=True)

st.subheader("Threat History (last entries)")
st.dataframe(st.session_state.threat_history.tail(10).reset_index(drop=True), use_container_width=True)

csv = st.session_state.threat_history.to_csv(index=False).encode("utf-8")
st.download_button("📥 Download Threat History CSV", data=csv,
                   file_name=f"threat_history_{int(time.time())}.csv",
                   mime="text/csv",
                   key=f"download_{int(time.time())}")

# Reset dashboard
if st.button("🔄 Reset Dashboard", key="reset_dashboard"):
    st.session_state.data = pd.DataFrame(columns=["timestamp","src_port","dst_port","protocol","packet_size","label"])
    st.session_state.threat_history = pd.DataFrame(columns=["timestamp","src_port","dst_port","protocol","packet_size","prediction"])
    st.session_state.simulation_running = False
    st.session_state.packet_counter = 0
    st.success("Dashboard reset — simulation paused (default).")

# Small footer
st.markdown(
    f"<small>Dataset: <b>{dataset_choice}</b> &nbsp;|&nbsp; Injection interval (N): <b>{st.session_state.injection_interval}</b> &nbsp;|&nbsp; Recent window: <b>{recent_n}</b></small>",
    unsafe_allow_html=True
)
