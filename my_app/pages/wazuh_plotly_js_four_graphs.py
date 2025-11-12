# pages/wazuh.py
import streamlit as st
import streamlit.components.v1 as components # Added for HTML components
import queue
import threading
import time
import json
from collections import deque
from common import open_ssh_client, summarise_wazuh, generate_graph, plot_graph, get_figure_as_json, get_node_color

# ─── Constants ────────────────────────────────────────────────────────────────
REFRESH_INTERVAL = 0.5  # seconds
_JSON_PATH = "/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.json"
THREAD_NAME = "wazuh-tail"
MAX_FULL_HISTORY_SIZE = 2000 # Max items to keep in the full history for the graph

st.set_page_config(page_title="Wazuh Alerts (Categorized)", layout="wide")
st.title("Wazuh Alerts (Categorized Graphs)")

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
    "Lines to keep (for live log)",
    1,
    2000,
    50,
    key="wazuh_max_events",
    on_change=_restart_stream_on_lines_change,
)

st.number_input(
    "Max recent events for graphs",
    1,
    MAX_FULL_HISTORY_SIZE,
    2000,
    key="wazuh_max_nodes_overall",
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
def _stream_wazuh(out_q: queue.Queue, stop_event: threading.Event, num_lines_for_tail: int):
    """SSH-tail the Wazuh alerts file, pushing each line onto *out_q*."""
    client = None
    try:
        client = open_ssh_client(ip, user, passwd)
        cmd = f"sudo -S tail -n {num_lines_for_tail} -F {_JSON_PATH}"
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
# MODIFIED: Placeholders for four graphs in a 2x2 layout
st_ui_columns = st.columns(2)
graph_placeholders = {
    "red": st_ui_columns[0].empty(),    # Top-left
    "yellow": st_ui_columns[1].empty(), # Top-right
    "blue": st_ui_columns[0].empty(),   # Bottom-left
    "green": st_ui_columns[1].empty(),  # Bottom-right
}
# The above will cause overwrites. Need to define them sequentially within columns.
col1, col2 = st.columns(2)
with col1:
    graph_placeholders_col1_top = st.empty()
    graph_placeholders_col1_bottom = st.empty()
with col2:
    graph_placeholders_col2_top = st.empty()
    graph_placeholders_col2_bottom = st.empty()

# Store in a dictionary with keys for categories
graph_placeholders_map = {
    "red": graph_placeholders_col1_top,
    "yellow": graph_placeholders_col2_top, # Corrected assignment
    "blue": graph_placeholders_col1_bottom,
    "green": graph_placeholders_col2_bottom,
}

log_container_ph = st.empty()
status_ph = st.empty()

# ─── Control Buttons ──────────────────────────────────────────────────────────
col_btn1, col_btn2, _ = st.columns([1, 1, 3])

if col_btn1.button("▶ Start / Resume", use_container_width=True):
    if _start_streamer_thread():
        status_ph.caption("Starting stream…")
    else:
        status_ph.caption("Resuming stream display…")
    st.session_state.wazuh_streaming = True
    st.rerun()

if col_btn2.button("⏹️ Stop Stream", use_container_width=True):
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
            truncated = raw if len(raw) < 2000 else f"{raw[:2000]}…"
            recent.appendleft(f"Non-JSON log line: {truncated}") # Non-JSON only to recent log
    except queue.Empty:
        break  # shouldn't happen

# MODIFIED: Derive overall graph_source_items from wazuh_FULL_history based on NEW user selection
# This is the total pool of recent events to distribute among the 4 graphs.
max_nodes_for_graphs_overall = st.session_state.get("wazuh_max_nodes_overall", 2000)
_full_history_deque = st.session_state.get("wazuh_FULL_history", deque(maxlen=MAX_FULL_HISTORY_SIZE))
overall_graph_source_items = list(_full_history_deque)[-max_nodes_for_graphs_overall:]

# ─── Status message ───────────────────────────────────────────────────────────
if st.session_state.wazuh_streaming:
    if not overall_graph_source_items and not new_data_processed:
        status_ph.caption("Streaming… waiting for initial data for graphs…")
    elif not new_data_processed:
        status_ph.caption(
            f"Streaming… last update {time.strftime('%H:%M:%S')} – waiting for new events…"
        )
    else:
        status_ph.caption(f"Streaming… updated {time.strftime('%H:%M:%S')}")
elif not st.session_state.wazuh_streaming and not _is_thread_alive(THREAD_NAME):
    status_ph.info("Streamer is stopped.")

# ─── Graph Generation and Display (Four Graphs) ───────────────────────────────
# MODIFIED: Entire graph section replaced

def _get_placeholder_html(text: str) -> str:
    """Returns HTML for a styled placeholder box to maintain layout."""
    # This CSS is designed to create a box that is visually similar to
    # a blank Streamlit component, matching the dark theme.
    return f'''
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
body, html {{
    margin: 0;
    padding: 0;
    width: 100%;
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    background-color: transparent;
}}
.container {{
    width: 100%;
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #6f7480; /* A muted text color from Streamlit's theme */
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
    border: 1px solid rgba(49, 51, 63, 0.2); /* A faint border */
    border-radius: 0.5rem; /* Matches Streamlit's border radius */
    box-sizing: border-box;
    padding: 1rem;
    text-align: center;
}}
</style>
</head>
<body>
    <div class="container">{text}</div>
</body>
</html>
'''

graph_categories_config = [
    {"key": "red", "title": "Critical Alerts (Levels 15+)", "placeholder": graph_placeholders_map["red"]},
    {"key": "yellow", "title": "High Alerts (Levels 12-14)", "placeholder": graph_placeholders_map["yellow"]},
    {"key": "blue", "title": "Medium Alerts (Levels 7-11)", "placeholder": graph_placeholders_map["blue"]},
    {"key": "green", "title": "Low Alerts (Levels 0-6)", "placeholder": graph_placeholders_map["green"]},
]

if overall_graph_source_items:
    # Segregate events by color category
    events_by_color = {"green": [], "blue": [], "yellow": [], "red": [], "other": []}
    for item_json_str in overall_graph_source_items:
        level = None
        actual_color = "other" # Default category
        try:
            data = json.loads(item_json_str)
            rule_data = data.get("rule")
            if isinstance(rule_data, dict):
                level = rule_data.get("level")
            actual_color = get_node_color(level) # common.get_node_color handles None level
        except json.JSONDecodeError:
            actual_color = get_node_color(None) # Assign to default if not parsable
        
        if actual_color in events_by_color:
            events_by_color[actual_color].append(item_json_str)
        else: # Should map to 'grey' -> 'other' if DEFAULT_NODE_COLOR is grey
            events_by_color["other"].append(item_json_str)

    any_graph_displayed = False
    for category in graph_categories_config:
        cat_key = category["key"]
        cat_title = category["title"]
        cat_placeholder = category["placeholder"]
        
        category_event_items = events_by_color[cat_key]
        num_nodes_cat = len(category_event_items)

        with cat_placeholder: # Use the placeholder's context to manage its content
            st.subheader(f"{cat_title}: {num_nodes_cat} events")
            if num_nodes_cat > 0:
                any_graph_displayed = True
                tooltips_cat = [summarise_wazuh(item) for item in category_event_items]
                G_cat, pos_cat = generate_graph(num_nodes_cat)
                
                figure_json_str_cat = get_figure_as_json(G_cat, pos_cat, tooltips_cat, category_event_items)
                
                graph_div_id_cat = f"plotly_js_graph_{cat_key}_{st.session_state.get('wz_graph_ctr', 0)}"

                html_content_cat = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
</head>
<body>
    <div id="{graph_div_id_cat}" style="width:100%;height:300px;"></div>
    <script>
        var figData = {figure_json_str_cat};
        var graphDiv = document.getElementById('{graph_div_id_cat}');
        if (graphDiv) {{
            Plotly.newPlot(graphDiv, figData.data, figData.layout, figData.config || {{}});
            graphDiv.on('plotly_click', function(data){{
                var point = data.points[0];
                console.log('Plotly.js Click Event ({cat_key}): Node #', point.pointNumber, 'Data:', point);
            }});
        }} else {{
            console.error("Plotly.js target div '{graph_div_id_cat}' not found.");
        }}
    </script>
</body>
</html>
"""
                components.html(html_content_cat, height=320, scrolling=False)
            else:
                # Use a placeholder with fixed height to prevent layout shifts
                placeholder_html = _get_placeholder_html(f"No {cat_key.capitalize()} alerts in the current selection.")
                components.html(placeholder_html, height=320)
    
    if new_data_processed: # Increment counter if any new data was processed from queue
        st.session_state.wz_graph_ctr = st.session_state.get("wz_graph_ctr", 0) + 1

else: # No overall_graph_source_items
    for category in graph_categories_config:
        with category["placeholder"]:
            st.subheader(f"{category['title']}: 0 events")
            # Use a placeholder with fixed height to prevent layout shifts
            placeholder_html = _get_placeholder_html(
                "Waiting for data or to adjust 'Max recent events for graphs'."
            )
            components.html(placeholder_html, height=320)


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
                st.json(parsed, expanded=True)
            except json.JSONDecodeError:
                st.json([{"raw_log": item} for item in recent], expanded=True)
        elif st.session_state.wazuh_streaming:
            st.caption("No new log events yet…")
        else:
            st.caption("Log is empty and streaming is stopped.")

# ─── Auto-rerun while streaming ───────────────────────────────────────────────
if st.session_state.wazuh_streaming:
    time.sleep(REFRESH_INTERVAL)
    st.rerun() 