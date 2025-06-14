import os
import sys
import paramiko
import threading
import queue
import time
import json
import re
from collections import deque

# Visualization dependencies
import networkx as nx
import matplotlib.pyplot as plt  # used if um_gen_metal is available
import plotly.graph_objects as go
import streamlit as st # Added for caching

# -----------------------------------------------------------------------------
# Try to load the user's fractal‑graph helper `um_gen_metal`. If it isn't on the
# PYTHONPATH, the rest of the code will gracefully fall back to a simple path
# graph for visualisation.
# -----------------------------------------------------------------------------
APP_DIR = os.path.dirname(os.path.abspath(__file__))
if APP_DIR not in sys.path:
    sys.path.append(APP_DIR)

try:
    import um_gen_metal as metal  # type: ignore
except ModuleNotFoundError:
    metal = None

# -----------------------------------------------------------------------------
# Node Color Helper based on Wazuh Rule Level
# -----------------------------------------------------------------------------
DEFAULT_NODE_COLOR = "grey" # Default color for unknown levels

def get_node_color(level: int | None) -> str:
    """Determine node color based on Wazuh rule level."""
    if level is None:
        return DEFAULT_NODE_COLOR
    if 0 <= level <= 6:
        return "green"
    elif 7 <= level <= 11:
        return "blue"
    elif 12 <= level <= 14:
        return "yellow"
    elif level >= 15:
        return "red"
    return DEFAULT_NODE_COLOR # Default for any other case

# -----------------------------------------------------------------------------
# SSH helper
# -----------------------------------------------------------------------------

def open_ssh_client(ip: str, user: str, pw: str) -> paramiko.SSHClient:
    """Return a connected `paramiko.SSHClient`."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=ip, username=user, password=pw)
    return client

# -----------------------------------------------------------------------------
# Snort / tcpdump line prettifier (identical to original)
# -----------------------------------------------------------------------------

def prettify_tcpdump(line: str) -> str:
    rex = re.match(
        r"^(?P<time>\S+)\s+IP6?\s+(?P<src>[^>]+)\s+>\s+(?P<dst>[^:]+):\s+(?P<rest>.*)$",
        line,
    )
    if not rex:
        return line
    d = rex.groupdict()
    return (
        f"Time: {d['time']}\nSource: {d['src']}\nDestination: {d['dst']}\nDetails: {d['rest']}"
    )

# -----------------------------------------------------------------------------
# Wazuh JSON one‑liner summariser
# -----------------------------------------------------------------------------

def summarise_wazuh(raw: str) -> str:
    try:
        data = json.loads(raw)
        return f"{data.get('timestamp', '')} – {data.get('rule', {}).get('description', '')}"
    except Exception:
        return raw[:120]

# -----------------------------------------------------------------------------
# Fractal‑graph helper (unchanged logic)
# -----------------------------------------------------------------------------

@st.cache_data
def generate_graph(n: int):
    """Return a `(graph, pos)` pair with **exactly** the same logic as the original file.

    • If the user has `um_gen_metal` on the PYTHONPATH, we let it draw a shape
      while monkey‑patching `nx.draw` so we can intercept the graph + layout.
    • Otherwise, we fall back to a simple `nx.path_graph(n)` with a spring layout.
    """
    st.write(f"DEBUG: generate_graph(n={n}) called in common.py") # DEBUG
    captured = {}

    def _fake_draw(G, pos=None, *_, **__):  # noqa: ANN001 (keep signature generic)
        captured["G"] = G.copy()
        captured["pos"] = pos.copy() if pos is not None else nx.spring_layout(G)

    orig_nx_draw, orig_plt_show = nx.draw, plt.show
    nx.draw = _fake_draw  # type: ignore
    plt.show = lambda *_a, **_k: None  # noqa: E731

    try:
        if metal is not None:
            metal.draw_shape(n)
        else:
            G = nx.path_graph(n)
            pos = nx.spring_layout(G)
            captured["G"], captured["pos"] = G, pos
    finally:
        nx.draw = orig_nx_draw  # type: ignore
        plt.show = orig_plt_show  # type: ignore

    return captured["G"], captured["pos"]

# -----------------------------------------------------------------------------
# Plotly helper (MODIFIED to include node colors)
# -----------------------------------------------------------------------------

def plot_graph(G: nx.Graph, pos: dict, tooltips: list[str], node_colors: list[str], is_foreground: bool = False, selected_nodes: list[int] | None = None):
    edge_x, edge_y = [], []
    for u, v in G.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        hoverinfo="skip",
        line=dict(width=1),
    )

    node_x, node_y, hover_text = [], [], []
    # Ensure node_colors has the same length as G.nodes() for safety,
    # though they should already align if generate_graph and graph_source_items match.
    # The colors are generated based on graph_source_items which should match the number of nodes.
    colors_for_plot = node_colors[:len(list(G.nodes()))]
    
    # Prepare marker properties for selected nodes
    marker_line_widths = [3 if idx in (selected_nodes or []) else 1 for idx in range(len(list(G.nodes())))]
    marker_line_colors = ["#FFFF00" if idx in (selected_nodes or []) else "black" for idx in range(len(list(G.nodes())))] # Yellow for selected

    for idx, node in enumerate(sorted(G.nodes())): # Iterate consistently
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        hover_text.append(tooltips[idx] if idx < len(tooltips) else f"Node {node}")

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers",
        hovertext=hover_text,
        hoverinfo="text",
        marker=dict(
            size=12, 
            color=colors_for_plot,
            line=dict(width=marker_line_widths, color=marker_line_colors) # Add border for selection
        ),
    )

    fig = go.Figure([edge_trace, node_trace])
    fig.update_layout(
        margin=dict(l=0, r=0, t=0, b=0),
        showlegend=False,
        xaxis=dict(visible=False),
        yaxis=dict(visible=False, scaleanchor="x", scaleratio=1),
        paper_bgcolor='rgba(0,0,0,0)' if is_foreground else 'white', # Default 'white' for background
        plot_bgcolor='rgba(0,0,0,0)' if is_foreground else 'white'  # Default 'white' for background
    )
    return fig

def get_figure_as_json(G: nx.Graph, pos: dict, tooltips: list[str], graph_source_items: list[str], is_foreground: bool = False, selected_nodes: list[int] | None = None) -> str:
    """Generates a Plotly figure and returns it as a JSON string.
    Node colors are determined by the 'rule.level' in graph_source_items.
    The 'is_foreground' flag makes the plot background transparent.
    Selected nodes are highlighted.
    """
    node_colors = []
    # Ensure that the number of tooltips, graph_source_items, and nodes in G align.
    # The number of nodes in G is determined by generate_graph(len(graph_source_items)).
    # So, len(graph_source_items) should be the guiding length.

    num_items = len(graph_source_items)

    for i in range(num_items):
        item_json_str = graph_source_items[i]
        level = None
        try:
            data = json.loads(item_json_str)
            level = data.get("rule", {}).get("level")
        except json.JSONDecodeError:
            # If JSON is invalid, it won't have a rule.level
            pass # level remains None
        node_colors.append(get_node_color(level))
    
    # Ensure tooltips list is also aligned or padded if necessary
    # This is more of a safeguard; ideally, they should already be aligned.
    safe_tooltips = (tooltips + [f"Node {i}" for i in range(len(tooltips), num_items)])[:num_items]

    fig = plot_graph(G, pos, safe_tooltips, node_colors, is_foreground, selected_nodes)
    return fig.to_json()

# -----------------------------------------------------------------------------
# Streaming helpers (identical to the original logic, but with a safe `client`
# close and the exact same remote commands).
# -----------------------------------------------------------------------------

# Path used by the original single‑node Wazuh Docker stack
_WAZUH_DOCKER_ALERTS_JSON = (
    "/docker/volumes/single-node_wazuh_logs/_data/alerts/alerts.json"
)


def ssh_stream_wazuh(user: str, ip: str, pw: str, q: queue.Queue):
    client: paramiko.SSHClient | None = None
    try:
        client = open_ssh_client(ip, user, pw)
        cmd = (
            f"sudo -S tail -n 1000 -F {_WAZUH_DOCKER_ALERTS_JSON}"
        )
        stdin, stdout, _ = client.exec_command(cmd)
        stdin.write(pw + "\n")
        stdin.flush()
        for line in stdout:
            q.put(line.strip())
    except Exception as e:  # pragma: no cover – bubble up error via queue
        q.put(json.dumps({"error": str(e)}))
    finally:
        if client is not None:
            client.close()


def ssh_stream_snort(
    user: str,
    ip: str,
    pw: str,
    host: str,
    q: queue.Queue,
):
    client: paramiko.SSHClient | None = None
    try:
        client = open_ssh_client(ip, user, pw)
        # Base Snort command
        base_cmd = "sudo -S snort -A console -c /etc/snort/snort.conf -i ens192 host "
        
        # Append host filter if provided. The 'host' parameter is expected to be 
        # a valid BPF filter string like "host 192.168.1.1" or "net 192.168.0.0/16 or port 80"
        # If host is empty, no filter is applied.
        cmd = f"{base_cmd} {host}" if host else base_cmd
        
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True) # Added get_pty=True for sudo
        stdin.write(pw + "\n")
        stdin.flush()

        # Add a small delay and check stderr for sudo password errors
        time.sleep(0.5)
        if stderr.channel.recv_stderr_ready():
            err_output = stderr.channel.recv_stderr(1024).decode(errors="ignore")
            if "try again" in err_output.lower() or "incorrect password" in err_output.lower():
                q.put(f"!!ERROR!! Sudo password incorrect or other sudo issue for Snort: {err_output}")
                return
            # Log other stderr output as info, as Snort can be verbose on stderr
            # q.put(f"!!INFO!! Snort stderr: {err_output}") 

        for line in stdout:
            q.put(line.strip())
    except Exception as e:
        # Ensure a serializable error message is put on the queue
        try:
            err_json = json.dumps({"error": str(e)})
            q.put(f"!!ERROR!! {err_json}")
        except TypeError: # Fallback if error object itself is not serializable
            q.put(f"!!ERROR!! Error during Snort streaming: {str(e)}")
    finally:
        if client is not None:
            client.close()

def ssh_stream_tcpdump(
    user: str,
    ip: str,
    pw: str,
    bpf_filter: str, # BPF filter, e.g., "host 1.2.3.4", or empty for all traffic on interface
    q: queue.Queue,
):
    client: paramiko.SSHClient | None = None
    HARDCODED_INTERFACE = "ens192" # Define the hardcoded interface
    try:
        client = open_ssh_client(ip, user, pw)
        base_cmd = f"sudo -S tcpdump -l -n -i {HARDCODED_INTERFACE}"
        cmd = f"{base_cmd} {bpf_filter}" if bpf_filter else base_cmd
        
        stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
        stdin.write(pw + "\n")
        stdin.flush()

        time.sleep(0.5) # Check for sudo errors
        if stderr.channel.recv_stderr_ready():
            err_output = stderr.channel.recv_stderr(1024).decode(errors="ignore")
            if "try again" in err_output.lower() or "incorrect password" in err_output.lower():
                q.put(f"!!ERROR!! Sudo password incorrect or other sudo issue for tcpdump: {err_output}")
                return
            # Unlike snort, tcpdump might send actual error messages to stderr if command is malformed
            # So, if there's stderr output beyond sudo issues, it could be a tcpdump error.
            if err_output.strip(): # If there is any other stderr output
                 q.put(f"!!ERROR!! tcpdump stderr: {err_output.strip()}")
                 return # Stop if tcpdump itself reports an error via stderr

        for line in stdout:
            q.put(line.strip())
    except Exception as e:
        try:
            err_json = json.dumps({"error": str(e)})
            q.put(f"!!ERROR!! {err_json}")
        except TypeError:
            q.put(f"!!ERROR!! Error during tcpdump streaming: {str(e)}")
    finally:
        if client is not None:
            client.close()