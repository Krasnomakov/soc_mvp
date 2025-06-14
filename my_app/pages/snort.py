# pages/snort.py
import streamlit as st
import queue
import threading
import time
from collections import deque
from common import ssh_stream_snort, prettify_tcpdump

REFRESH_INTERVAL = 0.25  # seconds
THREAD_NAME = "snort-tail"

st.set_page_config(page_title="Snort Sniffer", layout="wide")
st.title("Snort Intrusion Detection System")

# ─── Credential guard ─────────────────────────────────────────────────────────
if not (
    st.session_state.get("username")
    and st.session_state.get("ip")
    and st.session_state.get("password")
):
    st.warning("Fill in credentials on **Login** first.")
    st.stop()

user = st.session_state["username"]
ip = st.session_state["ip"]
passwd = st.session_state["password"]

# ─── Session State Initialization ───────────────────────────────────────────
if "snort_q" not in st.session_state:
    st.session_state.snort_q = queue.Queue()
if "snort_streaming" not in st.session_state:
    st.session_state.snort_streaming = False
if "snort_thread_started" not in st.session_state:
    st.session_state.snort_thread_started = False

q: queue.Queue = st.session_state.snort_q

# Forward declaration for callbacks
_stop_streamer_thread = None
_start_streamer_thread = None

# ─── Helper callbacks for inputs ────────────────────────────────────────────
def _restart_stream_on_filter_change():
    was_streaming = st.session_state.snort_streaming
    if _stop_streamer_thread: _stop_streamer_thread()
    time.sleep(0.2) # allow thread to stop
    if was_streaming and _start_streamer_thread: _start_streamer_thread()
    st.rerun()

def _update_deque_max_lines():
    # This will be handled by _ensure_deque on rerun
    st.rerun()

# ─── User-tunable limits ──────────────────────────────────────────────────────
st.sidebar.header("Snort Settings")
host_filter_input = st.sidebar.text_input(
    "BPF Filter (e.g., 'host 1.2.3.4', blank = all)", 
    key="snort_host_filter_val",
    on_change=_restart_stream_on_filter_change,
    value=st.session_state.get("snort_host_filter_val", "") # Persist value
)

max_lines_input = st.sidebar.number_input(
    "Lines to keep in log display", 1, 500, 50, 
    key="snort_max_lines_val",
    on_change=_update_deque_max_lines,
)

# ─── Deque Management ─────────────────────────────────────────────────────────
def _ensure_deque(name: str, maxlen: int):
    old = st.session_state.get(name)
    if old is None or old.maxlen != maxlen:
        st.session_state[name] = deque(list(old or [])[:maxlen], maxlen=maxlen)
    return st.session_state[name]

recent_logs = _ensure_deque("snort_recent_logs", st.session_state.get("snort_max_lines_val", 50))

# ─── Background Streamer Thread ───────────────────────────────────────────────
def _stream_snort_worker(out_q: queue.Queue, stop_event: threading.Event, bpf_filter: str):
    try:
        # ssh_stream_snort expects user, ip, pw, host (bpf_filter), queue
        ssh_stream_snort(user, ip, passwd, bpf_filter, out_q)
    except Exception as exc:
        out_q.put(f"!!ERROR!! Thread error: {exc!s}")
    finally:
        # Signal that the thread has finished, whether normally or by exception/stop_event
        filter_desc = bpf_filter if bpf_filter else "any" # Pre-evaluate filter description
        if not stop_event.is_set(): # If not already stopped by explicit call
             out_q.put(f"!!INFO!! Streamer thread for filter '{filter_desc}' ended.")
        st.session_state.snort_thread_started = False

def _is_snort_thread_alive() -> bool:
    return any(t.name == THREAD_NAME and t.is_alive() for t in threading.enumerate())

def _start_streamer_thread_impl() -> bool:
    if not _is_snort_thread_alive():
        st.session_state.snort_stop_event = threading.Event()
        current_bpf_filter = st.session_state.get("snort_host_filter_val", "")
        threading.Thread(
            target=_stream_snort_worker,
            args=(q, st.session_state.snort_stop_event, current_bpf_filter),
            daemon=True,
            name=THREAD_NAME,
        ).start()
        st.session_state.snort_thread_started = True
        return True
    return False

def _stop_streamer_thread_impl():
    if st.session_state.get("snort_stop_event"):
        st.session_state.snort_stop_event.set()
    
    thread_to_join = None
    for t in threading.enumerate():
        if t.name == THREAD_NAME:
            thread_to_join = t
            break
    if thread_to_join and thread_to_join.is_alive():
        thread_to_join.join(timeout=1.5)
    # The worker's finally block sets snort_thread_started = False

# Assign to global names after definition
_start_streamer_thread = _start_streamer_thread_impl
_stop_streamer_thread = _stop_streamer_thread_impl

# ─── UI Placeholders and Control Buttons ──────────────────────────────────────
status_ph = st.empty()
log_ph = st.empty()

col1, col2, _ = st.columns([1, 1, 3])

if col1.button("▶ Start / Resume Stream", use_container_width=True):
    if _start_streamer_thread():
        status_ph.caption("Starting Snort stream…")
    else:
        status_ph.caption("Attempting to resume Snort stream display…")
    st.session_state.snort_streaming = True
    st.rerun()

if col2.button("⏹️ Stop Stream", use_container_width=True):
    st.session_state.snort_streaming = False
    _stop_streamer_thread()
    status_ph.info("Snort streaming stopped by user.")
    st.rerun()

# ─── Data Ingestion and Display Loop ──────────────────────────────────────────
if st.session_state.snort_streaming:
    new_data_processed = False
    while not q.empty():
        try:
            raw = q.get_nowait()
            new_data_processed = True
            if isinstance(raw, str) and raw.startswith("!!"):
                tag, msg = raw.split("!!", 2)[1:]
                if tag == "ERROR":
                    st.error(msg.strip())
                    st.session_state.snort_streaming = False
                    st.session_state.snort_thread_started = False # Ensure this is reset
                    _stop_streamer_thread() # Attempt to clean up thread if error originated there
                elif tag == "INFO":
                    st.info(msg.strip())
                    if "ended" in msg or "stopped" in msg: # If thread signals its end
                         st.session_state.snort_streaming = False 
                break # Exit while loop on control message
            recent_logs.appendleft(raw)
        except queue.Empty:
            break # Should not happen with q.get_nowait() in loop but good for safety

    # Update status message
    if not recent_logs and not new_data_processed:
        status_ph.caption("Snort streaming… waiting for initial data…")
    elif not new_data_processed:
        status_ph.caption(f"Snort streaming… last update {time.strftime('%H:%M:%S')} – waiting for new events…")
    else:
        status_ph.caption(f"Snort streaming… updated {time.strftime('%H:%M:%S')}")

    # Display logs
    if recent_logs:
        log_ph.text("\n".join([prettify_tcpdump(x) for x in recent_logs]))
    elif st.session_state.snort_streaming: # Still streaming but no logs yet
        log_ph.caption("No Snort alerts yet…")
    else: # Not streaming and no logs
        log_ph.caption("Log is empty and streaming is stopped.")
    
    time.sleep(REFRESH_INTERVAL)
    st.rerun()

elif not st.session_state.snort_streaming and not _is_snort_thread_alive():
    status_ph.info("Snort stream is stopped.")
    if not recent_logs: log_ph.caption("Log is empty and streaming is stopped.")
    else: log_ph.text("\n".join([prettify_tcpdump(x) for x in recent_logs])) # Show last known logs
else: # Not streaming, but thread might still be shown as alive or in intermediate state
    status_ph.caption("Snort stream is currently inactive.")
    if not recent_logs: log_ph.caption("Log is empty.")
    else: log_ph.text("\n".join([prettify_tcpdump(x) for x in recent_logs]))
