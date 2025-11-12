# pages/wazuh.py
import streamlit as st
import streamlit.components.v1 as components 
import queue
import threading
import time
import json
import pandas as pd
import uuid
import os
from collections import deque
from common import open_ssh_client, summarise_wazuh, generate_graph, get_figure_as_json 

# ─── Constants ────────────────────────────────────────────────────────────────
REFRESH_INTERVAL = 0.5  # seconds
_JSON_PATH = "/var/lib/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.json"
THREAD_NAME = "wazuh-tail"
MAX_FULL_HISTORY_SIZE = 1000 # Max items to keep in the full history for the graph
CSV_PATH = 'case_data.csv'

st.set_page_config(page_title="Wazuh Alerts Interactive Graph", layout="wide")
st.title("Wazuh Alerts Interactive Graph")

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

# Toggle to pause auto-refresh while selecting
st.sidebar.checkbox(
    "Pause auto-refresh while selecting",
    key="wazuh_pause_refresh",
    value=st.session_state.get("wazuh_pause_refresh", False),
    help="Halts reruns so you can click or lasso-select multiple nodes without interruptions.",
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
if "selected_node_ids" not in st.session_state: # For selected graph nodes (global IDs)
    st.session_state.selected_node_ids = []
if "modal_is_open" not in st.session_state:
    st.session_state.modal_is_open = False
if "node_data_to_save" not in st.session_state:
    st.session_state.node_data_to_save = ""
if "user_comment_to_save" not in st.session_state:
    st.session_state.user_comment_to_save = ""

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

# Initialize component_value before the graph is rendered
component_value = None

# Derive graph_source_items from wazuh_FULL_history based on user's selection
current_max_nodes_for_graph = st.session_state.get("wazuh_max_nodes", 30)
_full_history_deque = st.session_state.get("wazuh_FULL_history", deque(maxlen=MAX_FULL_HISTORY_SIZE))
graph_source_items = list(_full_history_deque)[-current_max_nodes_for_graph:]

# Calculate global IDs for the items currently in the graph
start_gid = max(0, len(_full_history_deque) - len(graph_source_items))
global_ids_for_current_graph = list(range(start_gid, start_gid + len(graph_source_items)))

# ─── Graph Rendering and Component Value Retrieval ────────────────────────────
# This section will render the graph and potentially get a new component_value

js_foreground_fig_placeholder = "null" 

if graph_source_items: 
    tooltips = [summarise_wazuh(item) for item in graph_source_items]
    num_current_nodes = len(graph_source_items)
    G, pos = generate_graph(num_current_nodes)
    raw_figure_json = get_figure_as_json(G, pos, tooltips, graph_source_items, is_foreground=True)
    
    js_fig_object = {}
    if raw_figure_json:
        try:
            js_fig_object = json.loads(raw_figure_json)
            if js_fig_object and 'data' in js_fig_object and isinstance(js_fig_object['data'], list) and len(js_fig_object['data']) > 0:
                js_fig_object['data'][0]['customdata'] = global_ids_for_current_graph
                initial_local_selected_indices_for_js = [
                    i for i, gid_val in enumerate(global_ids_for_current_graph)
                    if gid_val in st.session_state.get("selected_node_ids", [])
                ]
                js_fig_object['data'][0]['selectedpoints'] = initial_local_selected_indices_for_js
                
                if 'layout' not in js_fig_object:
                    js_fig_object['layout'] = {}
                js_fig_object['layout']['clickmode'] = 'event+select' 
                js_fig_object['layout']['dragmode'] = 'lasso' 
            
            js_foreground_fig_placeholder = json.dumps(js_fig_object)
        except json.JSONDecodeError:
            st.error("Failed to parse or augment figure JSON for interactivity.")

    js_graph_source_items = json.dumps(graph_source_items)

    try:
        with open("pages/wazuh_plotly_template.html") as f:
            html_template = f.read()
        
        html_content = html_template.replace(
            "{js_foreground_fig_placeholder}", js_foreground_fig_placeholder
        ).replace(
            "{js_graph_source_items}", js_graph_source_items
        )
    except FileNotFoundError:
        st.error("Error: The 'wazuh_plotly_template.html' file was not found in the 'pages' directory.")
        html_content = "" # Fallback to empty
    except Exception as e:
        st.error(f"An error occurred while reading or formatting the HTML template: {e}")
        html_content = "" # Fallback to empty

    if html_content:
        with graph_ph:
            component_value = components.html(html_content, height=620, scrolling=False)
else:
    graph_ph.empty()

# Robust event buffering: store the event in session_state as soon as it is received
if component_value is not None:
    st.session_state['wazuh_component_event'] = component_value

# Always process the buffered event if it exists
component_event = st.session_state.get('wazuh_component_event', None)
if component_event is not None:
    print(f"DEBUG: Python received component_event: {component_event}")
    if isinstance(component_event, dict) and "type" in component_event:
        event_type = component_event.get("type")

        if event_type == "selection" and "data" in component_event:
            selection_data = component_event["data"]

            # Standard selection logic
            if isinstance(selection_data, list):
                st.session_state.selected_node_ids = [
                    gid for gid in selection_data if isinstance(gid, int)
                ]
            elif not selection_data:
                st.session_state.selected_node_ids = []

            # If exactly one node is selected (a click), treat this as modal opening to pause refresh
            # and also fetch its data directly from the full history for case creation.
            if isinstance(selection_data, list) and len(selection_data) == 1:
                gid = selection_data[0]
                full_hist = st.session_state.get("wazuh_FULL_history", [])
                if 0 <= gid < len(full_hist):
                    st.session_state.node_data_to_save = list(full_hist)[gid]
                    st.session_state.user_comment_to_save = ""
                else:
                    st.session_state.node_data_to_save = ""
                    st.session_state.user_comment_to_save = ""
                st.session_state.modal_is_open = False  # Close modal automatically

            st.session_state['wazuh_component_event'] = None
            st.rerun()

# Prune selected node IDs
st.session_state.selected_node_ids = [
    gid for gid in st.session_state.get("selected_node_ids", []) if gid in global_ids_for_current_graph
]

# ─── UI Elements ──────────────────────────────────────────────────────────────
sel_col1, _ = st.columns([1, 4])
if sel_col1.button("🧹 Clear Selections", use_container_width=True):
    st.session_state.selected_node_ids = []
    st.rerun()

col1, col2, _ = st.columns([1, 1, 3])
if col1.button("▶ Start / Resume", use_container_width=True):
    if _start_streamer_thread():
        status_ph.caption("Starting stream…")
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
            tag, msg = raw.split("!!", 2)[1:]
            if tag == "ERROR":
                st.error(msg.strip())
                st.session_state.wazuh_streaming = False
                _stop_streamer_thread()
            break
        
        if raw: # Don't add empty lines to history
            try:
                json.loads(raw)
                recent.appendleft(raw)
                st.session_state.wazuh_FULL_history.append(raw)
            except json.JSONDecodeError:
                recent.appendleft(f"Non-JSON: {raw[:100]}")
    except queue.Empty:
        break

# ─── Status & Log Display ─────────────────────────────────────────────────────
if st.session_state.wazuh_streaming:
    status_ph.caption(f"Streaming… updated {time.strftime('%H:%M:%S')}" if new_data_processed else "Streaming… waiting for events…")
elif not _is_thread_alive(THREAD_NAME):
    status_ph.info("Streamer is stopped.")

with log_container_ph.container():
    st.session_state.log_expanded = st.checkbox("Expand Log", st.session_state.log_expanded)
    with st.expander("Live Log", expanded=st.session_state.log_expanded):
        if recent:
            st.json([json.loads(item) if item.startswith('{') else {"raw_log": item} for item in recent])
        else:
            st.caption("Log is empty.")

# ─── Case Saving UI ─────────────────────────────────────────────────────────────
st.divider()
st.markdown("## Create New Case")

# ─── Data Picker: Bypass JavaScript Communication ─────────────────────────────
if graph_source_items:
    st.write("**Select Alert Data to Save:**")
    
    # Create columns for better layout
    cols = st.columns(min(3, len(graph_source_items)))
    
    # Reverse the items to show the latest first
    for i, item in enumerate(reversed(graph_source_items)):
        col_idx = i % len(cols)
        with cols[col_idx]:
            try:
                # Parse JSON to get readable info
                alert_data = json.loads(item)
                timestamp = alert_data.get("timestamp", "Unknown")
                rule_desc = alert_data.get("rule", {}).get("description", "No description")
                alert_id = alert_data.get("id", "")
                
                # Create a button with shortened description
                button_label = f"🚨 {timestamp[:19]}\n{rule_desc[:40]}...\n📋 {alert_id}"
                
                # Add the alert ID as help text so it's searchable but not cluttering the display
                help_text = f"Alert ID: {alert_id}\nTimestamp: {timestamp}"
                
                if st.button(button_label, key=f"load_alert_{i}", use_container_width=True, help=help_text):
                    st.session_state.node_data_to_save = item
                    st.session_state.user_comment_to_save = ""
                    st.rerun()
                    
            except json.JSONDecodeError:
                # Fallback for non-JSON data
                if st.button(f"📄 Alert {i+1}", key=f"load_alert_{i}", use_container_width=True):
                    st.session_state.node_data_to_save = item
                    st.session_state.user_comment_to_save = ""
                    st.rerun()

# ─── Case Creation Form ─────────────────────────────────────────────────────────
if st.session_state.node_data_to_save:
    # Use a key for the text_area that gets updated when new data arrives
    current_comment = st.session_state.get("user_comment_to_save", "")
    user_input_for_case = st.text_area(
        "Enter/edit user comment:",
        value=current_comment,
        key=f"user_comment_{st.session_state.node_data_to_save[:20]}", # Change key to force re-render
        height=100
    )

    with st.expander("Alert Data to be Saved (JSON)", expanded=False):
        st.json(st.session_state.node_data_to_save)

    if st.button("💾 Save Case to CSV"):
        case_id = str(uuid.uuid4())
        
        new_data = pd.DataFrame({
            'case_id': [case_id],
            'node_data': [st.session_state.node_data_to_save],
            'user_input': [user_input_for_case],
            'mitre_response': [''],
            'ai_response': ['']
        })

        try:
            header = not os.path.exists(CSV_PATH) or os.path.getsize(CSV_PATH) == 0
            new_data.to_csv(CSV_PATH, mode='a', header=header, index=False)
            st.success(f"Case saved successfully with ID: `{case_id}`")
            st.toast("✅ Case Saved!", icon="💾")
            
            # Clear the data after saving
            st.session_state.node_data_to_save = ""
            st.session_state.user_comment_to_save = ""
            st.rerun()

        except Exception as e:
            st.error(f"Error saving data: {e}")

else:
    st.info("Click one of the alert buttons above to load alert data for saving.")

# ─── Display saved cases ────────────────────────────────────────────────────────
st.divider()
st.write(f"### Recently Saved Cases (`{CSV_PATH}`)")
try:
    if os.path.exists(CSV_PATH) and os.path.getsize(CSV_PATH) > 0:
        df = pd.read_csv(CSV_PATH)
        st.dataframe(df.tail(10))
    else:
        st.info(f"`{CSV_PATH}` is empty or does not exist.")
except Exception as e:
    st.error(f"Could not read CSV file: {e}")

# ─── Auto-rerun ───────────────────────────────────────────────────────────────
if (st.session_state.wazuh_streaming and 
    not st.session_state.get("wazuh_pause_refresh", False) and
    not st.session_state.get("modal_is_open", False)):
    time.sleep(REFRESH_INTERVAL)
    st.rerun() 