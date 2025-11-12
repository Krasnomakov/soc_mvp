# pages/wazuh.py
import streamlit as st
import streamlit.components.v1 as components # Added for HTML components
import queue
import threading
import time
import json
from collections import deque
from common import open_ssh_client, summarise_wazuh, generate_graph, plot_graph, get_figure_as_json # Added get_figure_as_json

# ─── Constants ────────────────────────────────────────────────────────────────
REFRESH_INTERVAL = 0.5  # seconds
_JSON_PATH = "/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.json"
THREAD_NAME = "wazuh-tail"
MAX_FULL_HISTORY_SIZE = 1000 # Max items to keep in the full history for the graph

st.set_page_config(page_title="Wazuh Alerts (Plotly.js)", layout="wide")
st.title("Wazuh Alerts (Plotly.js)")

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

# ─── Helper callbacks ─────────────────────────────────────────────────────────
def _restart_stream_on_lines_change():
    """When the user changes the 'Lines to keep' value, restart the streamer
    *only if it was running*, so the new -n value is used immediately.
    """
    was_streaming_before_change = st.session_state.wazuh_streaming
    _stop_streamer_thread()  # Attempts to stop and join the thread

    # Give a brief moment for the thread's finally block (which sets wazuh_thread_started=False) to execute.
    # This helps ensure _is_thread_alive and wazuh_thread_started are consistent before trying to restart.
    time.sleep(0.2) # Increased sleep slightly

    if was_streaming_before_change:
        # Try to start a new thread. _start_streamer_thread returns True if successful.
        if _start_streamer_thread():
            st.session_state.wazuh_streaming = True # Confirm streaming is on
            # status_ph.caption("Restarting stream with new line limit...") # Optional immediate feedback
        else:
            # If starting failed (e.g., old thread still alive despite join timeout),
            # ensure streaming is marked as off and inform user.
            st.session_state.wazuh_streaming = False
            status_ph.warning(
                "Failed to restart stream immediately. The previous stream might still be shutting down. "
                "Please try starting the stream manually again in a moment."
            )
    else:
        # If it wasn't streaming before, ensure it's still marked as not streaming.
        # This handles cases where _stop_streamer_thread might have been called on a non-streaming but existent thread.
        st.session_state.wazuh_streaming = False

    st.rerun()


def _refresh_graph_on_nodes_change():
    """Force a graph refresh when the 'Nodes in graph' value changes."""
    st.session_state.wz_graph_ctr = st.session_state.get("wz_graph_ctr", 0) + 1
    st.rerun()


# ─── User-tunable limits ──────────────────────────────────────────────────────
st.sidebar.header("Display limits")
st.sidebar.caption("Change on the fly – no restart needed.")

st.number_input(
    "Lines to keep",
    1,
    200,
    50,
    key="wazuh_max_events",
    on_change=_restart_stream_on_lines_change,
)

st.number_input(
    "Nodes in graph",
    1,
    300,
    30,
    key="wazuh_max_nodes",
    on_change=_refresh_graph_on_nodes_change,
)

# ─── Core buffers (persist in session_state) ──────────────────────────────────
if "wazuh_q" not in st.session_state:
    st.session_state.wazuh_q = queue.Queue()
q: queue.Queue = st.session_state.wazuh_q

if "wazuh_streaming" not in st.session_state:
    st.session_state.wazuh_streaming = False
if "wazuh_thread_started" not in st.session_state:
    st.session_state.wazuh_thread_started = False
if "log_expanded" not in st.session_state:
    st.session_state.log_expanded = True  # default: expanded
if "wazuh_FULL_history" not in st.session_state: # New: Full history for graph data
    st.session_state.wazuh_FULL_history = deque(maxlen=MAX_FULL_HISTORY_SIZE)

def _ensure_recent_deque(maxlen: int): # Changed to specifically manage 'wazuh_recent'
    """Resize (or create) the 'wazuh_recent' deque in session_state while preserving data."""
    name = "wazuh_recent"
    old = st.session_state.get(name)
    if old is None or old.maxlen != maxlen:
        # For wazuh_recent (appendleft), preserve newest items from the start
        st.session_state[name] = deque(list(old or [])[:maxlen], maxlen=maxlen)
    return st.session_state[name]


recent = _ensure_recent_deque(st.session_state["wazuh_max_events"])
# The 'all_events' deque that was previously managed by _ensure_deque is removed.
# Graph data will now be derived from 'wazuh_FULL_history'.

# ─── Background streamer ──────────────────────────────────────────────────────
def _stream_wazuh(out_q: queue.Queue, stop_event: threading.Event, num_lines: int):
    """SSH-tail the Wazuh alerts file, pushing each line onto *out_q*."""
    client = None
    try:
        client = open_ssh_client(ip, user, passwd)
        cmd = f"sudo -S tail -n {num_lines} -F {_JSON_PATH}"
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
        stdin.write(passwd + "\n")
        stdin.flush()

        # catch sudo auth errors early
        time.sleep(0.5)
        if stderr.channel.recv_stderr_ready():
            err = stderr.channel.recv_stderr(1024).decode(errors="ignore")
            if "try again" in err.lower() or "incorrect password" in err.lower():
                out_q.put("!!ERROR!! Sudo password incorrect or other sudo issue.")
                return

        for line in stdout:
            if stop_event.is_set():
                out_q.put("!!INFO!! Streamer thread stopped.")
                break
            out_q.put(line.strip())
    except Exception as exc:
        out_q.put(f"!!ERROR!! {exc!s}")
    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass
        st.session_state.wazuh_thread_started = False


def _is_thread_alive(name: str) -> bool:
    return any(t.name == name and t.is_alive() for t in threading.enumerate())


def _start_streamer_thread() -> bool:
    """Start the tail-streamer thread if it isn't already running."""
    if not _is_thread_alive(THREAD_NAME):
        st.session_state.wazuh_stop_event = threading.Event()
        threading.Thread(
            target=_stream_wazuh,
            args=(
                q,
                st.session_state.wazuh_stop_event,
                st.session_state["wazuh_max_events"],
            ),
            daemon=True,
            name=THREAD_NAME,
        ).start()
        st.session_state.wazuh_thread_started = True
        return True
    return False


def _stop_streamer_thread():
    if st.session_state.get("wazuh_stop_event"):
        st.session_state.wazuh_stop_event.set()

    # Attempt to find and join the thread by its name
    thread_to_join = None
    for t in threading.enumerate():
        if t.name == THREAD_NAME:
            thread_to_join = t
            break
    
    if thread_to_join and thread_to_join.is_alive():
        thread_to_join.join(timeout=1.5) # Wait up to 1.5 seconds for the thread to terminate
        # The _stream_wazuh thread's finally block handles setting wazuh_thread_started = False.
        # If the join times out, _is_thread_alive in _start_streamer_thread
        # should prevent a new thread from starting if the old one is genuinely stuck.

# ─── UI placeholders ──────────────────────────────────────────────────────────
graph_ph = st.empty()
log_container_ph = st.empty()
status_ph = st.empty()

# ─── Control Buttons ──────────────────────────────────────────────────────────
col1, col2, _ = st.columns([1, 1, 3])

if col1.button("▶ Start / Resume", use_container_width=True):
    if _start_streamer_thread():
        status_ph.caption("Starting stream…")
    else:
        status_ph.caption("Resuming stream display…")
    st.session_state.wazuh_streaming = True
    st.rerun()

if col2.button("⏹️ Stop Stream", use_container_width=True):
    st.session_state.wazuh_streaming = False
    _stop_streamer_thread()
    status_ph.info("Streaming stopped by user.")
    st.rerun()

# ─── Data ingestion loop ──────────────────────────────────────────────────────
new_data_processed = False
while not q.empty():
    try:
        raw = q.get_nowait()
        new_data_processed = True

        if isinstance(raw, str) and raw.startswith("!!"):
            # control messages
            tag, msg = raw.split("!!", 2)[1:]  # ["ERROR", " ..."] or ["INFO", " ..."]
            if tag == "ERROR":
                st.error(msg.strip())
                st.session_state.wazuh_streaming = False
                st.session_state.wazuh_thread_started = False
                _stop_streamer_thread()
            elif tag == "INFO":
                st.info(msg.strip())
                if "Streamer thread stopped" in msg:
                    st.session_state.wazuh_streaming = False
            break

        # treat as JSON log line; fall back to raw if parse fails
        try:
            json.loads(raw) # Validate that raw is a valid JSON
            recent.appendleft(raw)
            st.session_state.wazuh_FULL_history.append(raw) # Add to full history
        except json.JSONDecodeError:
            truncated = raw if len(raw) < 200 else f"{raw[:200]}…"
            recent.appendleft(f"Non-JSON log line: {truncated}") # Non-JSON only to recent log
    except queue.Empty:
        break  # shouldn't happen

# Derive graph_source_items from wazuh_FULL_history based on user's selection
current_max_nodes_for_graph = st.session_state.get("wazuh_max_nodes", 30)
# Ensure wazuh_FULL_history is available, even if it's empty initially
_full_history_deque = st.session_state.get("wazuh_FULL_history", deque(maxlen=MAX_FULL_HISTORY_SIZE))
graph_source_items = list(_full_history_deque)[-current_max_nodes_for_graph:]

# ─── Status message ───────────────────────────────────────────────────────────
if st.session_state.wazuh_streaming:
    if not graph_source_items and not new_data_processed: # Use graph_source_items
        status_ph.caption("Streaming… waiting for initial data…")
    elif not new_data_processed:
        status_ph.caption(
            f"Streaming… last update {time.strftime('%H:%M:%S')} – waiting for new events…"
        )
    else:
        status_ph.caption(f"Streaming… updated {time.strftime('%H:%M:%S')}")
elif not st.session_state.wazuh_streaming and not _is_thread_alive(THREAD_NAME):
    status_ph.info("Streamer is stopped.")

# ─── Graph ────────────────────────────────────────────────────────────────────
if graph_source_items: # Use derived graph_source_items
    # Tooltips are built from graph_source_items (which are assumed to be valid JSON strings)
    tooltips = [summarise_wazuh(item) for item in graph_source_items]
    
    # json_graph_data is effectively graph_source_items
    G, pos = generate_graph(len(graph_source_items))
    
    # Pass graph_source_items to include event details for coloring
    figure_json_str = get_figure_as_json(G, pos, tooltips, graph_source_items)
    
    # Unique ID for the div to host the Plotly graph
    graph_div_id = f"plotly_js_graph_div_{st.session_state.get('wz_graph_ctr', 0)}"

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
</head>
<body>
    <div id="{graph_div_id}" style="width:100%;height:600px;"></div>
    <script>
        var figData = {figure_json_str};
        var graphDiv = document.getElementById('{graph_div_id}');
        
        // Ensure the div is available before plotting
        if (graphDiv) {{
            Plotly.newPlot(graphDiv, figData.data, figData.layout, figData.config || {{}});
            
            // Example: log clicks to console (can be expanded for interactivity)
            graphDiv.on('plotly_click', function(data){{
                var point = data.points[0];
                console.log('Plotly.js Click Event: Node #', point.pointNumber, 'Data:', point);
                // To send data back to Streamlit (more advanced):
                // Streamlit.setComponentValue({{clicked_node: point.pointNumber, text: point.text}});
            }});
        }} else {{
            console.error("Plotly.js target div '{graph_div_id}' not found.");
        }}
    </script>
</body>
</html>
"""
    graph_ph.empty() # Clear previous content
    components.html(html_content, height=620, scrolling=False) # Use components.html

    if new_data_processed:
        st.session_state.wz_graph_ctr = st.session_state.get("wz_graph_ctr", 0) + 1
else:
    graph_ph.empty()

# ─── Log display ──────────────────────────────────────────────────────────────
with log_container_ph.container():
    is_expanded = st.checkbox(
        "Expand Log", value=st.session_state.log_expanded, key="log_expanded_toggle"
    )
    st.session_state.log_expanded = is_expanded

    with st.expander("Live Log", expanded=is_expanded):
        if recent:
            try:
                parsed = [
                    json.loads(item)
                    if isinstance(item, str) and item.startswith("{")
                    else {"raw_log": item}
                    for item in recent
                ]
                st.json(parsed)
            except json.JSONDecodeError:
                st.json([{"raw_log": item} for item in recent])
        elif st.session_state.wazuh_streaming:
            st.caption("No new events yet…")
        else:
            st.caption("Log is empty and streaming is stopped.")

# ─── Auto-rerun while streaming ───────────────────────────────────────────────
if st.session_state.wazuh_streaming:
    time.sleep(REFRESH_INTERVAL)
    st.rerun() 