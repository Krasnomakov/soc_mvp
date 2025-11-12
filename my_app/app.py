# login.py  – drop-in, bullet-proof credential store
import streamlit as st
import paramiko  # or whichever SSH lib you already import


# ------------------------------------------------------------------------------
def creds_in_state() -> bool:
    """Return True only if the three mandatory keys exist and are non-empty."""
    return all(st.session_state.get(k) for k in ("username", "ip", "password"))

def save_clicked() -> None:
    st.session_state.username = st.session_state.tmp_user.strip()
    st.session_state.ip       = st.session_state.tmp_ip.strip()
    st.session_state.password = st.session_state.tmp_pw
    st.success("✅ Saved!  Switch pages and start streaming.")

# ------------------------------------------------------------------------------
def login_page():
    st.title("Welcome to the Cybersecurity Operations Center (SOC)")
    st.caption("Please enter your credentials to connect to the SOC host. If you don't have them, please read **Getting Started** section for instructions.")
    # Pre-fill input boxes with whatever is already stored
    if creds_in_state():
        default_user = st.session_state.username
        default_ip   = st.session_state.ip
        default_pw   = st.session_state.password
    else:
        default_user = default_ip = default_pw = ""

    st.text_input("SSH username", key="tmp_user", value=default_user)
    st.text_input("Sensor IP / host", key="tmp_ip", value=default_ip)
    st.text_input("Password", type="password", key="tmp_pw", value=default_pw)

    st.button("💾 Save", on_click=save_clicked)

    # Optional quick self-test ------------------------------------------------------
    def ssh_test():
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=st.session_state.ip,
                username=st.session_state.username,
                password=st.session_state.password,
                port=22,
                timeout=4,
            )
            client.close()
            st.success("SSH connection test: OK")
        except Exception as e:
            st.error(f"SSH connection test failed: {e!s}")

    if creds_in_state() and st.button("Test connection"):
        ssh_test()

    # ------------------------------------------------------------------------------
    st.caption(
        "These credentials are kept **only in this browser tab's memory** while "
        "the app is running; reload the page and they're gone."
    )


pg = st.navigation(
    {
        "Login": [st.Page(login_page, title="Login", icon="🔒")],
        "Getting Started": [st.Page("pages/getting_started_page.py", title="How to set up your SOC?", icon="📋")],
        "AI & Investigation": [st.Page("pages/chat_page.py", title="Threat Intelligence", icon="🔍")],
        "Red vs Blue Emulation": [
            st.Page("pages/red_blue_emulator.py", title="Caldera Emulator", icon="🚔"),
        ],
        "Alert Graphs | Wazuh SIEM": [
            st.Page("pages/wazuh_plotly_js_interactive.py", title="Interactive Plot", icon="👉"),
            st.Page("pages/wazuh_plotly_js_four_graphs.py", title="Rule Level Graphs", icon="📊"),
            st.Page("pages/wazuh_plotly_js.py", title="Simple Plot", icon="*️⃣"),
        ],
        "Network Traffic & IDS": [
            st.Page("pages/machine_traffic.py", title="VM Traffic", icon="🌐"),
            st.Page("pages/snort.py", title="Snort Sniffer", icon="🐽"),
        ]
        
    }
)

pg.run() 