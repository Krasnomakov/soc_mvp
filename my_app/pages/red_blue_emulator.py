import streamlit as st
from sshtunnel import SSHTunnelForwarder
import paramiko
import os

# --- Configuration & State ---
if 'ssh_tunnel_active' not in st.session_state:
    st.session_state.ssh_tunnel_active = False
if 'ssh_server' not in st.session_state:
    st.session_state.ssh_server = None

# --- Helper Functions ---
def start_ssh_tunnel_password(ssh_host, ssh_port, ssh_user, ssh_password, remote_bind_address, local_bind_address):
    """Starts the SSH tunnel using password authentication."""
    try:
        server = SSHTunnelForwarder(
            (ssh_host, int(ssh_port)),
            ssh_username=ssh_user,
            ssh_password=ssh_password,
            remote_bind_address=remote_bind_address,
            local_bind_address=local_bind_address,
            # logger=create_logger(loglevel=1) # Optional: for debugging
        )
        server.start()
        st.session_state.ssh_tunnel_active = True
        st.session_state.ssh_server = server
        st.success(f"SSH tunnel established to {ssh_host}!")
        st.rerun() # Rerun to update iframe src
        return server
    except Exception as e:
        st.error(f"Failed to start SSH tunnel: {e}")
        if st.session_state.ssh_server:
            st.session_state.ssh_server.stop()
        st.session_state.ssh_tunnel_active = False
        st.session_state.ssh_server = None
        return None

def stop_ssh_tunnel():
    """Stops the SSH tunnel."""
    if st.session_state.ssh_server:
        try:
            st.session_state.ssh_server.stop()
            st.session_state.ssh_tunnel_active = False
            st.session_state.ssh_server = None
            st.success("SSH tunnel stopped.")
            st.rerun()
        except Exception as e:
            st.error(f"Error stopping tunnel: {e}")
    else:
        st.info("No active tunnel to stop.")


# --- Streamlit UI ---
st.set_page_config(layout="wide", page_title="Remote Server Emulator")

st.title("💻 Red/Blue Team - Remote Server Access via SSH Tunnel")
st.markdown("""
This page allows you to establish an SSH tunnel to a remote server and access a service
(e.g., a web application) running on that server through your local browser, embedded within this app.
""")

with st.sidebar:
    st.header("SSH Tunnel Configuration")
    ssh_host_default = "your_vm_ip" # Replace with a sensible default or leave empty
    ssh_user_default = "user"       # Replace with a sensible default or leave empty
    # ssh_key_default = "~/.ssh/id_rsa" # Common default path - REMOVED

    ssh_host = st.text_input("SSH Server IP/Hostname", ssh_host_default)
    ssh_port = st.number_input("SSH Server Port", value=22, min_value=1, max_value=65535)
    ssh_user = st.text_input("SSH Username", ssh_user_default)
    ssh_password = st.text_input("SSH Password", type="password", help="Your SSH password for the remote server.")
    # ssh_key_path = st.text_input("Path to SSH Private Key", ssh_key_default, help="e.g., ~/.ssh/id_rsa or C:/Users/YourUser/.ssh/id_rsa") - REMOVED

    st.markdown("---")
    st.header("Port Forwarding")
    remote_server_port = st.number_input("Remote Server Port (on VM)", value=8888, min_value=1, max_value=65535)
    local_tunnel_port = st.number_input("Local Tunnel Port (on this machine)", value=8888, min_value=1, max_value=65535)

    col1, col2 = st.columns(2)
    with col1:
        if st.button("🚀 Start Tunnel", use_container_width=True, type="primary", disabled=st.session_state.ssh_tunnel_active):
            if not all([ssh_host, ssh_user, ssh_password, remote_server_port, local_tunnel_port]):
                st.warning("Please fill in all SSH (including password) and port forwarding details.")
            else:
                remote_bind_addr = ('localhost', int(remote_server_port))
                local_bind_addr = ('0.0.0.0', int(local_tunnel_port)) # Listen on all interfaces for local access
                start_ssh_tunnel_password(ssh_host, ssh_port, ssh_user, ssh_password, remote_bind_addr, local_bind_addr)
    with col2:
        if st.button("🛑 Stop Tunnel", use_container_width=True, disabled=not st.session_state.ssh_tunnel_active):
            stop_ssh_tunnel()

    if st.session_state.ssh_tunnel_active and st.session_state.ssh_server:
        st.sidebar.success(f"Tunnel Active: localhost:{st.session_state.ssh_server.local_bind_port} -> {ssh_host}:{remote_server_port}")
    else:
        st.sidebar.info("Tunnel Inactive")


# --- Main Page Content ---
if st.session_state.ssh_tunnel_active and st.session_state.ssh_server:
    display_url = f"http://localhost:{st.session_state.ssh_server.local_bind_port}"
    st.success(f"Displaying content from: {display_url}")
    
    # Using st.components.v1.iframe for more control
    # It's generally recommended to use localhost or 127.0.0.1 for security
    # if the service on the remote end is only meant for local access on that VM.
    # If it's a web server meant to be accessed generally, 'localhost' is still correct
    # from the perspective of the machine running this streamlit app, as the tunnel
    # forwards remote_port@remote_vm to local_port@this_machine.
    
    st.markdown(f"### Embedded View (from `{display_url}`)")
    
    # The height can be adjusted as needed.
    # Ensure the service on the remote end is actually serving HTTP content.
    # If it's not a web server, this iframe won't display anything meaningful.
    st.components.v1.iframe(display_url, height=800, scrolling=True)

    st.markdown("""
    **Notes:**
    - If the embedded view is blank or shows an error, ensure the remote service at `localhost:{remote_server_port}` on the VM is running and accessible.
    - The SSH tunnel forwards traffic from `localhost:{local_tunnel_port}` on *this* machine to `localhost:{remote_server_port}` on the *remote VM*.
    - Ensure your SSH password is correct.
    """)

elif st.session_state.ssh_tunnel_active and not st.session_state.ssh_server:
    st.error("Tunnel was marked active, but server instance is missing. Please try stopping and restarting.")
else:
    st.info("SSH tunnel is not active. Configure and start the tunnel using the sidebar to view remote content.")

st.markdown("---")
st.markdown("Developed with assistance from an AI pair programmer.")

# To run this app:
# 1. Ensure 'streamlit' and 'sshtunnel' and 'paramiko' are in your requirements.txt and installed.
# 2. Save this code as a Python file (e.g., pages/red_blue_emulator.py).
# 3. Run Streamlit: `streamlit run your_main_app.py` (assuming this is a page in a multi-page app)
# 4. Navigate to this page in your Streamlit app.
# 5. Fill in your SSH details (including password) in the sidebar.
# 6. Click "Start Tunnel".
# 7. If the tunnel is successful and the remote service is running, it will appear in the iframe.
