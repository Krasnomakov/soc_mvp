# pages/machine_traffic.py
import streamlit as st
import queue
import threading
import time
from collections import deque
from common import ssh_stream_tcpdump, prettify_tcpdump
import paramiko

REFRESH_INTERVAL = 0.25  # seconds
THREAD_NAME = "tcpdump-tail" # Changed thread name for clarity

st.set_page_config(page_title="VM Traffic", layout="wide")
st.title("Network Traffic")
st.caption("This is a live view of the network traffic on the target VM.")

# ─── Credential guard ─────────────────────────────────────────────────────────
if not (
    st.session_state.get("username")
    and st.session_state.get("ip")
    and st.session_state.get("password")
):
    st.warning("Fill in credentials on **Login** first.")
    st.stop()

user = st.session_state["username"]
ip_addr = st.session_state["ip"] # Renamed to avoid conflict with common 'ip' module
passwd = st.session_state["password"]

# ─── Session State Initialization ───────────────────────────────────────────
if "mt_q" not in st.session_state: # mt for machine_traffic
    st.session_state.mt_q = queue.Queue()
if "mt_streaming" not in st.session_state:
    st.session_state.mt_streaming = False
if "mt_thread_started" not in st.session_state:
    st.session_state.mt_thread_started = False

q: queue.Queue = st.session_state.mt_q

# Forward declaration for callbacks
_stop_mt_streamer_thread = None
_start_mt_streamer_thread = None

# ─── Helper callbacks for inputs ────────────────────────────────────────────
def _restart_mt_stream_on_settings_change(): # Combined for both filter and interface
    was_streaming = st.session_state.mt_streaming
    if _stop_mt_streamer_thread: _stop_mt_streamer_thread()
    time.sleep(0.2) # allow thread to stop
    if was_streaming and _start_mt_streamer_thread: _start_mt_streamer_thread()
    st.rerun()

def _update_mt_deque_max_lines():
    st.rerun()

# ─── User-tunable limits ──────────────────────────────────────────────────────
st.sidebar.header("VM Traffic Settings")
bpf_filter_input = st.sidebar.text_input(
    "BPF Filter (e.g., 'host 1.2.3.4 and port 80', blank = all)", 
    key="mt_bpf_filter_val",
    on_change=_restart_mt_stream_on_settings_change,
    value=st.session_state.get("mt_bpf_filter_val", "")
)
max_lines_mt_input = st.sidebar.number_input(
    "Lines to keep in log display", 1, 500, 50, 
    key="mt_max_lines_val",
    on_change=_update_mt_deque_max_lines,
)

# ─── Deque Management ─────────────────────────────────────────────────────────
def _ensure_mt_deque(name: str, maxlen: int):
    old = st.session_state.get(name)
    if old is None or old.maxlen != maxlen:
        st.session_state[name] = deque(list(old or [])[:maxlen], maxlen=maxlen)
    return st.session_state[name]

recent_mt_logs = _ensure_mt_deque("mt_recent_logs", st.session_state.get("mt_max_lines_val", 50))

# ─── Background Streamer Thread ───────────────────────────────────────────────
def _stream_tcpdump_worker(out_q: queue.Queue, stop_event: threading.Event, bpf_filter: str):
    try:
        ssh_stream_tcpdump(user, ip_addr, passwd, bpf_filter, out_q)
    except paramiko.AuthenticationException as auth_exc:
        out_q.put(f"!!ERROR!! SSH Authentication Failed: {auth_exc!s}")
    except paramiko.SSHException as ssh_exc:
        out_q.put(f"!!ERROR!! SSH Connection Error: {ssh_exc!s}")
    except Exception as exc:
        out_q.put(f"!!ERROR!! VM Traffic Thread error: {exc!s}")
    finally:
        filter_desc = bpf_filter if bpf_filter else "all traffic"
        iface_desc = "ens192 (hardcoded)"
        if not stop_event.is_set():
             out_q.put(f"!!INFO!! TCPDump stream for filter '{filter_desc}' on interface '{iface_desc}' ended.")
        st.session_state.mt_thread_started = False

def _is_mt_thread_alive() -> bool:
    return any(t.name == THREAD_NAME and t.is_alive() for t in threading.enumerate())

def _start_mt_streamer_thread_impl() -> bool:
    if not _is_mt_thread_alive():
        st.session_state.mt_stop_event = threading.Event()
        current_bpf_filter = st.session_state.get("mt_bpf_filter_val", "")
        threading.Thread(
            target=_stream_tcpdump_worker,
            args=(q, st.session_state.mt_stop_event, current_bpf_filter),
            daemon=True,
            name=THREAD_NAME,
        ).start()
        st.session_state.mt_thread_started = True
        return True
    return False

def _stop_mt_streamer_thread_impl():
    if st.session_state.get("mt_stop_event"):
        st.session_state.mt_stop_event.set()
    thread_to_join = None
    for t in threading.enumerate():
        if t.name == THREAD_NAME: thread_to_join = t; break
    if thread_to_join and thread_to_join.is_alive(): thread_to_join.join(timeout=1.5)

_start_mt_streamer_thread = _start_mt_streamer_thread_impl
_stop_mt_streamer_thread = _stop_mt_streamer_thread_impl

# ─── UI Placeholders and Control Buttons ──────────────────────────────────────
status_ph = st.empty()
log_ph = st.empty()
col1, col2, _ = st.columns([1, 1, 3])
if col1.button("▶ Start / Resume Traffic Stream", use_container_width=True, key="mt_start_button"):
    if _start_mt_streamer_thread(): status_ph.caption("Starting VM traffic stream…")
    else: status_ph.caption("Attempting to resume VM traffic stream…")
    st.session_state.mt_streaming = True
    st.rerun()
if col2.button("⏹️ Stop Traffic Stream", use_container_width=True, key="mt_stop_button"):
    st.session_state.mt_streaming = False
    _stop_mt_streamer_thread()
    status_ph.info("VM traffic streaming stopped by user.")
    st.rerun()

# ─── Data Ingestion and Display Loop ──────────────────────────────────────────
if st.session_state.mt_streaming:
    new_data = False
    while not q.empty():
        try:
            raw = q.get_nowait(); new_data = True
            if isinstance(raw, str) and raw.startswith("!!"):
                tag, msg = raw.split("!!", 2)[1:]
                if tag == "ERROR":
                    st.error(msg.strip()); st.session_state.mt_streaming = False; st.session_state.mt_thread_started = False; _stop_mt_streamer_thread()
                elif tag == "INFO":
                    st.info(msg.strip())
                    if "ended" in msg or "stopped" in msg: st.session_state.mt_streaming = False
                break
            recent_mt_logs.appendleft(raw)
        except queue.Empty: break
    if not recent_mt_logs and not new_data: status_ph.caption("VM traffic streaming… waiting for data…")
    elif not new_data: status_ph.caption(f"VM traffic streaming… last update {time.strftime('%H:%M:%S')}…")
    else: status_ph.caption(f"VM traffic streaming… updated {time.strftime('%H:%M:%S')}")
    if recent_mt_logs: log_ph.text("\n".join([prettify_tcpdump(x) for x in recent_mt_logs]))
    elif st.session_state.mt_streaming: log_ph.caption("No traffic data yet…")
    else: log_ph.caption("Log is empty and streaming is stopped.")
    time.sleep(REFRESH_INTERVAL); st.rerun()
elif not st.session_state.mt_streaming and not _is_mt_thread_alive():
    status_ph.info("VM traffic stream is stopped.")
    if not recent_mt_logs: log_ph.caption("Log is empty and streaming is stopped.")
    else: log_ph.text("\n".join([prettify_tcpdump(x) for x in recent_mt_logs]))
else:
    status_ph.caption("VM traffic stream is currently inactive.")
    if not recent_mt_logs: log_ph.caption("Log is empty.")
    else: log_ph.text("\n".join([prettify_tcpdump(x) for x in recent_mt_logs]))
