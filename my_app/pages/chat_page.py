import streamlit as st
import uuid
import subprocess
import json # For parsing the output if it's structured
import re # Added for more robust technique ID extraction
import requests # For Ollama API calls
import pandas as pd
import os


# Placeholder for future integration with common.py
# import common 
# from mitre_querying import lookup_and_mitigation # This script is called via subprocess

# Define the path to the MITRE ATT&CK JSON data
# Ensure this file exists in your workspace or provide the correct path.
MITRE_JSON_PATH = "mitre_querying/enterprise-attack.json"
OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL_NAME = "gemma3:4b"  # <<< CHANGE THIS TO YOUR DESIRED OLLAMA MODEL
CSV_PATH = 'case_data.csv'

def load_cases_from_csv():
    """Load existing cases from the CSV file and return them as a dictionary."""
    cases = {}
    try:
        if os.path.exists(CSV_PATH) and os.path.getsize(CSV_PATH) > 0:
            df = pd.read_csv(CSV_PATH)
            for _, row in df.iterrows():
                case_id = row['case_id']
                # Combine node_data and user_input as the case text
                case_text = f"Alert Data:\n{row['node_data']}\n\nUser Comment:\n{row['user_input']}"
                
                cases[f"csv_case_{case_id}"] = {
                    "text": case_text,
                    "mitre_results": row['mitre_response'] if pd.notna(row['mitre_response']) and row['mitre_response'].strip() else None,
                    "ai_results": row['ai_response'] if pd.notna(row['ai_response']) and row['ai_response'].strip() else None,
                    "source": "csv",
                    "original_case_id": case_id
                }
    except Exception as e:
        st.error(f"Error loading cases from CSV: {e}")
    
    return cases

def save_csv_case_updates(case_id, mitre_results=None, ai_results=None):
    """Update the CSV file with new MITRE or AI results for a specific case."""
    try:
        if os.path.exists(CSV_PATH):
            df = pd.read_csv(CSV_PATH)
            mask = df['case_id'] == case_id
            if mitre_results is not None:
                df.loc[mask, 'mitre_response'] = mitre_results
            if ai_results is not None:
                df.loc[mask, 'ai_response'] = ai_results
            df.to_csv(CSV_PATH, index=False)
            st.success("Results saved to CSV file!")
    except Exception as e:
        st.error(f"Error updating CSV file: {e}")

def clear_csv_cases():
    """Clear all cases from the CSV file, keeping only the headers."""
    try:
        # Create empty DataFrame with just the headers
        columns = ["case_id", "node_data", "user_input", "mitre_response", "ai_response"]
        empty_df = pd.DataFrame(columns=columns)
        empty_df.to_csv(CSV_PATH, index=False)
        st.success("CSV file cleared! Only headers remain.")
        return True
    except Exception as e:
        st.error(f"Error clearing CSV file: {e}")
        return False

def save_case(case_text):
    case_id = str(uuid.uuid4())
    st.session_state[f"case_{case_id}"] = {"text": case_text, "mitre_results": None, "ai_results": None}
    st.success(f"Case saved with ID: {case_id}")
    return case_id

def run_mitre_lookup(case_text):
    # This is a simplified example. You'll need to extract relevant technique IDs
    # from the case_text. For now, we'll use a placeholder or a very simple extraction.
    # Example: extract things that look like Txxxx or Txxxx.xxx
    technique_ids = re.findall(r"T\d{4}(?:\.\d{3})?", case_text)

    if not technique_ids:
        return "No MITRE technique IDs found in the text (e.g., T1059, T1059.001)."

    try:
        process = subprocess.run(
            [
                "python", 
                "mitre_querying/lookup_and_mitigation.py", 
                MITRE_JSON_PATH
            ] + technique_ids,
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8' # Ensure correct encoding for output
        )
        return process.stdout
    except subprocess.CalledProcessError as e:
        return f"Error during MITRE lookup: {e.stderr}"
    except FileNotFoundError:
        return f"Error: The script 'mitre_querying/lookup_and_mitigation.py' or '{MITRE_JSON_PATH}' not found."

def run_ai_agent_query(case_text):
    payload = {
        "model": OLLAMA_MODEL_NAME,
        "prompt": case_text,
        "stream": False  # Get the full response at once
    }
    try:
        response = requests.post(OLLAMA_API_URL, json=payload, timeout=120) # 120 seconds timeout
        response.raise_for_status()  # Raise an exception for HTTP errors (4xx or 5xx)
        # Assuming Ollama returns a JSON where the main response is in a 'response' key
        # For non-streaming, the response is a single JSON object per line, but the last one has the full response.
        # This might need adjustment based on exact Ollama behavior for non-streaming if it sends multiple JSON objects.
        # A common pattern is that the final JSON object contains the full response field.
        
        # Try to parse the last line if multiple JSON objects are returned
        json_response_lines = response.text.strip().split('\n')
        final_json_response = json.loads(json_response_lines[-1])
        return final_json_response.get("response", "No response field found in Ollama output.")
    except requests.exceptions.ConnectionError:
        return f"Error: Could not connect to Ollama server at {OLLAMA_API_URL}. Please ensure Ollama is running."
    except requests.exceptions.Timeout:
        return "Error: Request to Ollama timed out."
    except requests.exceptions.HTTPError as e:
        return f"Error: Ollama API request failed: {e.response.status_code} - {e.response.text}"
    except json.JSONDecodeError:
        return f"Error: Could not parse JSON response from Ollama: {response.text}"
    except Exception as e:
        return f"An unexpected error occurred while querying Ollama: {str(e)}"

st.title("Investigation Chat Page")

st.header("Create New Case")

# Check if new case data is coming from Wazuh page
initial_case_text = ""
if "new_case_from_wazuh" in st.session_state:
    initial_case_text = st.session_state.pop("new_case_from_wazuh") # Get and remove it
    # Automatically save this case
    if initial_case_text:
        save_case(initial_case_text)
        # No need to rerun here, the rest of the page will load with the new case

case_input = st.text_area("Paste text for investigation here (include MITRE Technique IDs like T1059 or T1059.001):", value=initial_case_text, height=200, key="chat_page_case_input")

if st.button("Save Case"):
    if case_input:
        save_case(case_input)
    else:
        st.warning("Please enter some text for the case.")

st.header("Saved Cases")

# Add control buttons for CSV management
col1, col2, col3 = st.columns([1, 1, 3])

with col1:
    if st.button("🔄 Refresh CSV Cases", use_container_width=True):
        st.rerun()  # This will reload the CSV data when the page reruns

with col2:
    # Handle CSV clearing with confirmation
    if "confirm_clear_csv" not in st.session_state:
        st.session_state.confirm_clear_csv = False
    
    if not st.session_state.confirm_clear_csv:
        if st.button("🗑️ Clear CSV Cases", use_container_width=True, type="secondary"):
            st.session_state.confirm_clear_csv = True
            st.rerun()
    else:
        if st.button("⚠️ Confirm Clear", use_container_width=True, type="primary"):
            if clear_csv_cases():
                st.session_state.confirm_clear_csv = False
                st.rerun()  # Refresh the page to show empty cases
        if st.button("❌ Cancel", use_container_width=True):
            st.session_state.confirm_clear_csv = False
            st.rerun()

st.write("") # Add some spacing

# Load cases from CSV file
csv_cases = load_cases_from_csv()

# Combine CSV cases with session state cases
all_cases = {}

# Add CSV cases
all_cases.update(csv_cases)

# Add session state cases
for key in st.session_state.keys():
    if key.startswith("case_"):
        all_cases[key] = st.session_state[key]
        all_cases[key]["source"] = "session"

if not all_cases:
    st.info("No saved cases found. Create a new case above or save cases from the Wazuh page.")
else:
    csv_count = len([k for k in all_cases.keys() if k.startswith("csv_case_")])
    session_count = len([k for k in all_cases.keys() if not k.startswith("csv_case_")])
    st.write(f"Found {len(all_cases)} saved cases: {csv_count} from CSV, {session_count} from current session")

# Iterate over a copy of items in case new cases are added during iteration
for key, case_data in all_cases.items():
    # Extract case ID and determine source
    if key.startswith("csv_case_"):
        case_id = case_data["original_case_id"]
        case_source = "CSV"
        display_id = f"{case_id} (from CSV)"
    else:
        case_id = key.replace("case_", "")
        case_source = "Session"
        display_id = f"{case_id} (current session)"
        
    with st.expander(f"Case: {display_id} - Preview: {case_data['text'][:1000] + '...' if len(case_data['text']) > 1000 else case_data['text']}"):
        st.subheader(f"Full Text for Case: {display_id}")
        st.caption(f"Source: {case_source}")
        st.write(case_data["text"])

        # MITRE Lookup Section
        if st.button(f"Run MITRE Lookup for Case {case_id}", key=f"mitre_btn_{key}"):
            with st.spinner("Querying MITRE ATT&CK..."):
                results = run_mitre_lookup(case_data["text"])
                
                # Update the appropriate storage
                if case_data.get("source") == "csv":
                    save_csv_case_updates(case_data["original_case_id"], mitre_results=results)
                    case_data["mitre_results"] = results  # Update local copy for immediate display
                else:
                    st.session_state[key]["mitre_results"] = results
        
        if case_data.get("mitre_results"):
            st.subheader("MITRE Lookup Results:")
            st.text_area("Results", value=case_data["mitre_results"], height=600, disabled=True, key=f"mitre_res_{key}")

        # AI Agent Query Section
        if st.button(f"Query AI Agent for Case {case_id}", key=f"ai_btn_{key}"):
            with st.spinner(f"Querying AI Agent ({OLLAMA_MODEL_NAME})..."):
                ai_response = run_ai_agent_query(case_data["text"])
                
                # Update the appropriate storage
                if case_data.get("source") == "csv":
                    save_csv_case_updates(case_data["original_case_id"], ai_results=ai_response)
                    case_data["ai_results"] = ai_response  # Update local copy for immediate display
                else:
                    st.session_state[key]["ai_results"] = ai_response
        
        if case_data.get("ai_results"):
            st.subheader("AI Agent Results:")
            st.text_area("Results", value=case_data["ai_results"], height=600, disabled=True, key=f"ai_res_{key}")

# Placeholder for checking integrity with common.py
# if 'common' in globals() and hasattr(common, 'check_integrity'):
#     common.check_integrity() 