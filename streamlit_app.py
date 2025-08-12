import streamlit as st
import json
import requests
import pandas as pd
from io import StringIO

# --- Function Definitions ---

def get_auth_token(login_url, username, password):
    """
    Authenticates with the API to get a session token.
    """
    try:
        payload = {
            "evt": "LS",
            "gtp": "Password",
            "lid": username,
            "pwd": password
        }
        headers = {"Content-Type": "application/json"}
        response = requests.post(login_url, json=payload, headers=headers, timeout=15)
        response.raise_for_status()
        response_json = response.json()

        # Check for 'tkn', 'token', or 'sid' to get the auth key.
        token = response_json.get("tkn") or response_json.get("token") or response_json.get("sid")

        if not token:
            st.error(f"Login successful, but no token key found in the response: {response_json}")
            return None
        return token

    except requests.exceptions.HTTPError as http_err:
        st.error(f"HTTP error during login: {http_err}")
        st.error(f"Response body: {response.text}")
        return None
    except requests.exceptions.RequestException as req_err:
        st.error(f"Network error during login: {req_err}")
        return None
    except json.JSONDecodeError:
        st.error(f"Failed to decode JSON from login response. Response text: {response.text}")
        return None


def ingest_record(ingest_url, token, record):
    """
    Sends a single, complete JSON record to the ingestion API.
    """
    try:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        response = requests.post(ingest_url, json=record, headers=headers, timeout=15)
        return response
    except requests.exceptions.RequestException as e:
        mock_response = requests.Response()
        mock_response.status_code = 503
        mock_response.reason = "Network Error"
        mock_response._content = json.dumps({"error": str(e)}).encode('utf-8')
        return mock_response


# --- Streamlit App UI and Logic ---

def main():
    st.set_page_config(page_title="JSON Ingestion Tool", layout="wide")
    st.title("🚀 JSON Data Ingestion Tool")
    st.markdown("This app ingests a list of complete JSON payloads from a file, one by one.")

    if 'results' not in st.session_state:
        st.session_state.results = []

    # --- Configuration Sidebar ---
    with st.sidebar:
        st.header("⚙️ API Configuration")
        
        # 1. Environment Selector
        # Maps user-friendly names to the keys in secrets.toml
        env_options = {"Pre-Production": "pre_production", "Production": "production"}
        selected_env_display = st.radio(
            "Select Environment",
            options=list(env_options.keys()),
            horizontal=True
        )
        
        st.info(f"You have selected the **{selected_env_display}** environment.", icon="🌐")
        
        # 2. Get the corresponding key for st.secrets
        selected_env_key = env_options[selected_env_display]

        # 3. Securely load credentials from st.secrets
        try:
            login_url = st.text_input("Login API URL", st.secrets[selected_env_key]["login_url"])
            ingest_url = st.text_input("Ingestion API URL", st.secrets[selected_env_key]["ingest_url"])
            username = st.text_input("Login ID (lid)", st.secrets[selected_env_key]["username"])
            password = st.text_input("Password (pwd)", type="password", value=st.secrets[selected_env_key]["password"])
        except (KeyError, AttributeError):
            st.error("Secrets not configured. Please ensure you have a .streamlit/secrets.toml file locally or have added secrets in the Streamlit Cloud settings.")
            st.stop()


    # --- File Upload ---
    st.header("1. Upload JSON File")
    st.markdown("Upload a file containing a list of complete JSON payload objects.")
    uploaded_file = st.file_uploader("Choose a JSON file", type="json")

    # --- Ingestion Trigger ---
    if st.button("Start Ingestion Process", type="primary", use_container_width=True):
        st.session_state.results = []

        if not all([login_url, ingest_url, username, password, uploaded_file]):
            st.warning("Please fill in all API configuration fields and upload a file.", icon="⚠️")
        else:
            try:
                with st.spinner(f"Authenticating with {selected_env_display} environment..."):
                    token = get_auth_token(login_url, username, password)

                if not token:
                    st.error("Login failed. Please check credentials and API details.")
                    st.stop()

                st.success(f"Authentication successful with {selected_env_display}!", icon="✅")

                stringio = StringIO(uploaded_file.getvalue().decode("utf-8"))
                json_data = json.load(stringio)

                if not isinstance(json_data, list):
                    st.error("The uploaded JSON file must contain a list of objects.", icon="❌")
                    st.stop()

                total_records = len(json_data)
                st.info(f"Found {total_records} records to ingest.")

                progress_bar = st.progress(0, text="Starting ingestion...")

                for i, record in enumerate(json_data):
                    response = ingest_record(ingest_url, token, record)
                    status_code = response.status_code
                    is_success = 200 <= status_code < 300

                    try:
                        response_body = response.json()
                    except json.JSONDecodeError:
                        response_body = response.text

                    st.session_state.results.append({
                        "Record #": i + 1,
                        "Status": "✅ Success" if is_success else "❌ Failed",
                        "Status Code": status_code,
                        "API Response": json.dumps(response_body, indent=2),
                        "Sent Payload": json.dumps(record, indent=2)
                    })

                    progress_text = f"Ingesting record {i + 1} of {total_records}..."
                    progress_bar.progress((i + 1) / total_records, text=progress_text)

                progress_bar.empty()

            except json.JSONDecodeError:
                st.error("Invalid JSON file. Please ensure the file is well-formed.", icon="❌")
            except Exception as e:
                st.error(f"An unexpected error occurred: {e}", icon="🔥")

    # --- Display Results ---
    if st.session_state.results:
        st.header("2. Ingestion Results")
        results_df = pd.DataFrame(st.session_state.results)

        success_count = (results_df['Status'] == "✅ Success").sum()
        error_count = len(results_df) - success_count

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Records", len(results_df))
        col2.metric("✅ Successful", int(success_count))
        col3.metric("❌ Failed", int(error_count))

        if error_count > 0:
            st.error("Some records failed to ingest. See details in the 'Failed Records' tab below.")
        else:
            st.balloons()
            st.success("All records were ingested successfully!")

        tab1, tab2 = st.tabs(["All Records", "Failed Records"])

        with tab1:
            st.markdown("Detailed log of all ingestion attempts.")
            st.dataframe(results_df)

        with tab2:
            if error_count > 0:
                error_df = results_df[results_df['Status'] == "❌ Failed"]
                st.markdown(f"Displaying {error_count} failed record(s).")
                st.dataframe(error_df)
            else:
                st.info("No failed records to display.")

if __name__ == "__main__":
    main()

