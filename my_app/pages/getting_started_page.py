import streamlit as st
from PIL import Image
import os

st.set_page_config(layout="wide")

st.title("How to set up your SOC? | Getting Started Manual")
st.markdown("This is a student project and is not a production-ready solution. It is a proof of concept with **one Windows target** and **one Linux host**.")
st.markdown("---")

# Table of Contents
st.subheader("Table of Contents")
st.markdown("""
- [Step 1: Define your network configuration](#step-1-define-your-network-configuration)
- [Step 2: Install Wazuh SIEM](#step-2-install-wazuh-siem)
- [Step 3: Deploy Wazuh Agent](#step-3-deploy-wazuh-agent)
- [Step 4: Install Snort IDS](#step-4-install-snort-ids)
- [Step 5: Test Wazuh and Snort](#step-5-test-wazuh-and-snort)
- [Step 6: Run Alert Stream and Graph Visualizations](#step-6-run-alert-stream-and-graph-visualizations)
- [Step 7: Threat Intelligence](#step-7-threat-intelligence)
- [Step 8: Install, Learn and Test MITRE Caldera](#step-8-install-learn-and-test-mitre-caldera)
- [Step 9: Run a Red Operation against your Windows target](#step-9-run-a-red-operation-against-your-windows-target)
- [Step 10: Run a Blue Operation](#step-10-run-a-blue-operation)
- [Step 11: Emulate APT](#step-11-emulate-apt)
- [Step 12: Exercise and keep the SOC alive](#step-12-exercise-and-keep-the-soc-alive)
""")
st.markdown("---")

# Placeholder text
lorem_ipsum_short = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
lorem_ipsum_long = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."

# Image placeholder
image_path = 'Figure_1.png'
image_1 = "images/step_1_abstract_network.png"
image_2 = "images/step_2_wazuh_in_docker.png"
image_3 = "images/step_3_wazuh_agent_sysmon.png"
image_4 = "images/step_4_snort_ids.png"
image_5 = "images/step_5_test_wazuh.png"
image_5_1 = "images/step_5_1_test_wazuh_custom_rules.png"
image_5_2 = "images/step_5_2_test_snort.png"
image_6 = "images/step_6_universal_matrix_wazuh_alerts_graph.png"
image_6_1 = "images/step_6_1_rule_level_graphs.png"
image_7 = "images/step_7_mitre_lookup.png"
image_7_1 = "images/step_7_1_ai_query.png"
image_7_2 = "images/step_7_2_graph_to_case.png"
image_8 = "images/step_8_install_caldera.png"

image = None
if os.path.exists(image_path):
    try:
        image = Image.open(image_path)
    except Exception as e:
        st.error(f"Error loading image '{image_path}': {e}")
else:
    st.warning(f"Placeholder image '{image_path}' not found. It should be in the root directory of the app.")


# Step 1
st.header("Step 1: Define your network configuration")
col1, col2 = st.columns([2, 1])
with col1:
    st.subheader("Which devices and networks do you want to monitor? Where will be your SOC hosted?") 
    st.write("""

            The first step is to understand which devices and networks you want to monitor and defend. And where will you host your SOC. In our example we use one Windows target (Virtual machine) and one Linux host (Virtual machine). The dashboard runs locally on Mac with Apple Silicon.
                        
            On Windows, you can get the IP address with this command in Command Prompt or PowerShell:
            ```powershell
            ipconfig
            ```
            On Linux, you can use this command in the terminal:
            ```bash
            ip addr
            ```
                        
            """)
    st.markdown("**Save IP addresses in a text file. We will use this file later.**")
with col2:
    if os.path.exists(image_1):
        st.image(image_1, caption="Figure 1: Abstract network diagram")

st.markdown("---")

# Step 2
st.header("Step 2: Install Wazuh SIEM")
st.markdown("On the host where you want to install Wazuh SIEM, connect to the internet and open browser.")
st.write("Open this link: https://documentation.wazuh.com/current/deployment-options/docker/docker-installation.html")
st.markdown("Follow the instruction and install Docker and Wazuh SIEM.")

if os.path.exists(image_2):
    st.image(image_2, caption="Figure 2: Three Wazuh components (manager, indexer, dashboard) inside a Docker container", width=600)

st.markdown("---")

# Step 3
st.header("Step 3: Deploy Wazuh Agent")
col1, col2 = st.columns(2)
with col1:
    if os.path.exists(image_3):
        st.image(image_3, caption="Figure 3: Wazuh Agent on Windows", width=600)
with col2:
    st.subheader("Follow the instruction to deploy Wazuh Agent on Windows")
    st.write("Open this link: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html")
    st.write("In order to get complete log of all events from your target it is required to install Sysmon and configure Wazuh agent to use it and send logs.")
    st.markdown('''
                Open this link and follow the instruction to install Sysmon: https://wazuh.com/blog/using-wazuh-to-monitor-sysmon-events/ 
                            
                Or install it directly from Microsoft: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
                
                **Note:** You can use Sysmon on Linux host as well.
                ''')
    st.write("""Github with config files for Sysmon and Wazuh Agent that were used and tested in this project: https://github.com/Krasnomakov/soc_config/tree/main/Windows%20target%20VM%20Configs""")    

st.markdown("---")

# Step 4
st.header("Step 4: Install Snort IDS")
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Installation Guide for Snort 3 on Ubuntu 22.04 (Linux host)")
    st.write("""
            Snort is a powerful open-source Intrusion Detection System (IDS). This guide helps you install Snort 3 on Ubuntu 22.04 using the official source.

            For more details, visit the [Snort website](https://www.snort.org).
            """)

    with st.expander("View Installation Steps"):
        st.markdown("#### 4.1: Install Required Dependencies")
        st.code("""
                sudo apt update
                sudo apt install -y \\
                    build-essential libpcap-dev libpcre3-dev libdumbnet-dev bison flex zlib1g-dev \\
                    liblzma-dev openssl libssl-dev libnghttp2-dev libhwloc-dev cmake \\
                    libluajit-5.1-dev pkg-config libtool git autoconf
                """, language='bash')

        st.markdown("#### 4.2: Install libdaq from Source")
        st.code("""
                git clone https://github.com/snort3/libdaq.git
                cd libdaq
                ./bootstrap
                ./configure
                make
                sudo make install
                cd ..
                """, language='bash')

        st.markdown("#### 4.3: Install Snort 3")
        st.code("""
                git clone https://github.com/snort3/snort3.git
                cd snort3
                mkdir build && cd build
                cmake ..
                make -j$(nproc)
                sudo make install
                cd ../..
                """, language='bash')

        st.markdown("#### 4.4: Update Shared Library Cache")
        st.code("sudo ldconfig", language='bash')

        st.markdown("#### 4.5: Verify Snort Installation")
        st.code("snort -V", language='bash')
        st.success("Snort 3 should now be installed and ready for configuration.")

        st.markdown("#### Optional: Create Symlink")
        st.write("To simplify running Snort from the terminal:")
        st.code("sudo ln -s /usr/local/bin/snort /usr/sbin/snort", language='bash')

        

with col2:
    if os.path.exists(image_4):
        st.image(image_4, caption="Figure 4: Snort IDS")

st.markdown("---")


# Step 5
st.header("Step 5: Test Wazuh and Snort")

st.markdown("#### Test Wazuh")
st.markdown("At this stage you must have Wazuh SIEM running and Wazuh Agent deployed on your target.")
st.info("Use this ossec.conf file and place it in agent configuration folder: https://github.com/Krasnomakov/soc_config/tree/main/Windows%20target%20VM%20Configs/ossec-agent%20(Wazuh%20Agent)")

st.markdown("Ensure that you have Sysmon installed on your target Windows machine.")
st.info("Use this configuration file when installing Sysmon: https://github.com/Krasnomakov/soc_config/tree/main/Windows%20target%20VM%20Configs/Sysmon")
st.markdown("Restart Wazuh agent. Check that it is active in Wazuh dashboard.")
st.markdown("These two files make Sysmon log specific events and Wazuh agent send the log to the manager. You can test if it is working by accessing the Wazuh dashboard on localhost at your host machine.")
st.markdown("In order to trigger a test alert, disable Security Service on Windows, open powershell as admin and execute:")
st.code("""powersell.exe -Command "Get-Service" """, language='powershell')
st.markdown("Then, on your host go to **Threat Intelligence/Thret Hunting** in the left vertical menu of Wazuh Dashboard. Open events in appeared page and check if you have any alerts. The latest or one of the latest alerts will have MITRE ID 1059 and contain information about new process creationand even show exact command rom powershell on your target amchine.")
st.markdown("Alternatively go to **Home/Overview** in the left vertical menu of Wazuh Dashboard. On the page click Green or Low Severity events. You will see alerts log and find your event of interest.")

if image:
    st.image(image_5, caption="Figure 5: Capture Get-Service", width=700)
st.markdown("---")
st.markdown("#### Add Wazuh Custom Rule and test it")
st.markdown("Open Wazuh dashboard and go to **Server Management/Rules** in the left vertical menu.")
st.markdown("Search for local_rules. Click on local_rules.xml and it will open the editor.")
st.info("Copy and Overwrite the content of local_rules.xml with the content of https://github.com/Krasnomakov/soc_config/tree/main/wazuh_rules")
st.markdown("On your target machine install procdump from sysinternals: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump")
st.markdown("Place procdump.exe in C:\Tools folder (create the folder).")
st.markdown("In new powershel window with admin priveleges (and remember to disable windows defender) execute: ")
st.code(""".\procdump.exe -m lsass.exe lsass.dmp""", language='powershell')
st.markdown("Then go to Wazuh dashboard and go to **Home/Overview** in the left vertical menu. Click on Blue or Medium Severity events. You will see alerts log and find your event of interest.")
if image:
    st.image(image_5_1, caption="Figure 5.1: Capture procdump", width=700)
st.markdown("---")

st.markdown("#### Test Snort")
st.markdown("To find the relevant network interface (port), use the command `ip addr` and identify the interface connected to the network you wish to monitor.")
st.info("In our virtual environment setup, `ens192` was used as a sniffer port for the virtual network. However, you can use a standard port such as `ens160` or another based on your configuration.")
st.markdown("Launch Snort with the following command:")
st.code("sudo -S snort -A console -c /etc/snort/snort.conf -i <YOUR_INTERFACE> host <YOUR_TARGET_IP>", language='bash')
st.markdown("Open new terminal. And install nmap with the following command:")
st.code(" sudo apt install nmap")
st.markdown("Launch nmap scan with the following command:")
st.code("nmap -sS -sV -O <YOUR_TARGET_IP>", language='bash')

if image:
    st.image(image_5_2, caption="Figure 5.2: Capture nmap scan", width=700)
st.markdown("---")

# Step 6
st.header("Step 6: Run Alert Stream and Graph Visualizations")
col1, col2 = st.columns([1, 1])
with col1:
    if image:
        st.image(image_6, caption="Figure 6: Universal Matrix Wazuh Alerts Graph", width=600)
with col2:
    st.markdown("Open browser and go to Login page in the left vertical menu.")
    st.markdown("You will be prompted to enter login, password and ip of your host - enter it.")
    st.markdown("In the left vertical menu go to **Interactive  Plot**.")
    st.markdown("Clck **Start/Resume** button.")
    st.markdown("If everything is correct, you will see a graph with colored nodes. On hover a node will display an alert detils and on click it can be opened.")
    
    st.markdown("---")
    st.info("Tip: Amount of nodes in the graph can be changed above the graph. A log with streaming events can be opened and when a node is selected a corresponding event will highlight below as a button for investigation. Test the graph by repeating OS Credentials attack on Windows target - a new Blue node must appear on the graph in a second.")
st.markdown("---")

st.markdown("#### Test Rule Level Graphs")
st.markdown("Open Left vertical menu and go to **Rule Level Graphs**. If your Windows target is in IDLE state and not many things happen on, most likely you will see two graphs with little blue nodes and with many gren nodes. It is possible that you might see graphs with red or yellow nodes and this will be something to investigate.")
if image:
    st.image(image_6_1, caption="Figure 6.1: Rule Level Graphs, Triage", width=700)
    st.warning("Use graphs to visually recognize patterns and anomalies. It is an intuitive way to navigate in the stream of alerts.")

st.markdown("---")

# Step 7
st.header("Step 7: Threat Intelligence")
st.markdown("SOC Threat Intelligence allows to investigate threats (alerts), get mitigations and receive feedback from AI.")

tab1, tab2, tab3 = st.tabs(["MITRE ATT&CK", "AI", "Cases & Graphs"])
with tab1:
    st.write("Open Threat Intelligence page in the left vertical menu.")
    st.write("Enter MITRE ATT&CK ID. You can get it from alerts log from interactive graph, wazuh alerts log or even Wazuh dashboard on your host and rules.")
    st.write("Click save and you will see the case with unique ID appeared below. Click on expander and open the case.")
    st.write("Click on **Run MITRE Lookup for Case ...** button. If case closes after the click, oepn it and you will see the case with MITRE ATT&CK details and mitigations for this particular threat.")
    if image:
        st.image(image_7, caption="Figure 7a: MITRE ATT&CK Lookup", width=700)
with tab2:
    st.write("Open your case and click on **Query AI** button. You will see the AI response in the right side of the page.")
    st.info("For that you need ollama server and a model. Default model is gemma3:4b. To install visit https://ollama.ai")
    if image:
        st.image(image_7_1, caption="Figure 7b: Threat Intel AI Query", width=700)
with tab3:
    st.write("It is possible to get threat data directly from interactive graph. Save it into cases and send to investigation page for further analysis.")
    st.write("Open **Interactive Plot** page in the left vertical menu. Start streaming. Click on a node and open a pop up with alert details.")
    st.write("While pop up is open scroll down and you will see a number of buttons. One is highlighted and it corresponds to the node you clicked on. Click on the button and you will see a case opened below.")
    st.write("In order to save the case enter your question or note. E.g. what is this alert about? And then click on **Save Case to CSV** button. You will see the case saved in csv below.")
    st.write("Now you can open **Threat Intelligence** page in the left vertical menu. And use the case to lookup mitigations in MITRE ATT&CK or query AI agent for feedback or to answer your question.")
    if image:
        st.image(image_7_2, caption="Figure 7c: Graph to Case", width=700)
        
st.markdown("---")

# Step 8
st.header("Step 8: Install, Learn and Test MITRE Caldera")
st.markdown("MITRE Caldera is a tool that allows to create and test MITRE ATT&CK techniques and mitigations.")
st.info("Install it on your host machine: https://github.com/mitre/caldera")
st.markdown("Run Caldera and login on localhost:8888 with default credentials: admin/admin.")
st.warning("Caldera can be installed as a docker container. We use it as a server running in terminal.")
st.markdown("If everything is correct you will see the dashboard with a number of options in your browser.")
if image:
    st.image(image_8, caption="Figure 8: Caldera Dashboard", width=600)
st.markdown("Inside Caldera dashboard in the left vertical menu go to **Plugins/training** and select **User Certificate**. Complete the user training and learn the basics.")
st.markdown("---")

# Step 9
st.header("Step 9: Run a Red Operation against your Windows target")

st.markdown("Deploy Sandcat agent on your Windows target. And run a Discovery operation.")
st.markdown("You will see emerging yellow nodes on the interactive graph. And can investigate them in the Threat Intelligence page.")
st.success("Compare event log with executed abilities from Caldera dashboard and alerts log in Wazuh dashboard or interactive graph. If your Wazuh SIEM is functioning, you mustcapture all basic abilities and actions your agent performed.")

st.markdown("---")

# Step 10
st.header("Step 10: Run a Blue Operation")
st.write("Deploy Blue sandcat agent on the Windows target. And run Response Training operation. See how blue agent checks files and processes.")
st.success("You can also see Blue agent's action in Wazuh alerts and on the graph.")

st.markdown("---")

# Step 11
st.header("Step 11: Emulate APT")
st.write("Advanced Persistent Threat (APT) is a type of cyber attack that is designed to gain unauthorized access to a system or network. APTs are typically carried out by sophisticated attackers who use a combination of techniques to gain access to a target system.")
st.markdown("Make sure your agents are deployed. You can use **Caldera Emulator** in the left vertical menu of SOC dashboard. Then run a script that will launch APT similar to known groups. Simply enter a group name and run the script. It will use Caldera's API and launch the sophisticated attack.")
st.code("Use this  script: <attack_launch_script>")
st.error("Be careful! Do not launch it on your host or valuable machine that you cannot erase after the test.")
st.warning("Use your Blue agent and Wazuh to monitor the attack and respond to it.")

st.markdown("---")

# Step 12
st.header("Step 12: Exercise and keep the SOC alive!")
st.balloons()
st.write("Congratulations on completing the getting started guide!")
st.markdown("Explore rules, offense chaining, triage. Learn network sniffing. Use pages of this dashboard to enhance your user experience.")
st.markdown("Add more tools and customize - it is super easy with Streamlit and Cursor!")
st.markdown("Keep the SOC alive! Build on top of this MVP configuration and gather more intelligence.")
st.markdown("Keep host and dashboard separated. Deploy more SIEM or IDS  tools on other hosts - never host everyhtin on one server. Keep your SOC distributed.")