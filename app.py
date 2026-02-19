import os
import sqlite3
import subprocess

import pandas as pd
import plotly.express as px
import streamlit as st

st.set_page_config(page_title="Network IDS/IPS Dashboard", layout="wide")

DB_PATH = "logs/attacks.db"


def get_attack_data() -> pd.DataFrame:
    """
    Reads all attack records from the SQLite database.

    Returns an empty DataFrame if the database does not exist yet or if
    the query fails for any reason.
    """
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            return pd.read_sql_query(
                "SELECT * FROM attacks ORDER BY timestamp DESC", conn
            )
    except Exception:
        return pd.DataFrame()


def block_ip(ip_address: str) -> bool:
    """
    Adds a Windows Firewall inbound block rule for the given IP address.

    Requires the process to be running with administrator privileges.
    Returns True if the firewall rule was created successfully.

    Args:
        ip_address: The source IP to block.
    """
    rule_name = f"IDS_BLOCK_{ip_address}"
    command = (
        f'netsh advfirewall firewall add rule name="{rule_name}" '
        f"dir=in action=block remoteip={ip_address}"
    )
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.returncode == 0 or "OK" in result.stdout or "Tamam" in result.stdout
    except Exception:
        return False


# ------------------------------------------------------------------
# Dashboard layout
# ------------------------------------------------------------------

st.title("Network IDS/IPS Dashboard")

df = get_attack_data()

col1, col2, col3, col4 = st.columns(4)
col1.metric("System Status", "ACTIVE", delta="Protection ON")
col2.metric("Total Records", len(df))
col3.metric("Last Attacker IP", df["src_ip"].iloc[0] if not df.empty else "None")

with col4:
    st.write("")
    if st.button("Refresh Data", use_container_width=True):
        st.rerun()

st.divider()

if not df.empty:
    st.subheader("IPS Mode: Active Firewall Blocking")
    unique_ips = df["src_ip"].unique()

    ips_col1, ips_col2 = st.columns([3, 1])
    with ips_col1:
        selected_ip = st.selectbox("Select attacker IP to block:", unique_ips)
    with ips_col2:
        st.write("")
        if st.button("Block IP", type="primary", use_container_width=True):
            if block_ip(selected_ip):
                st.success(f"{selected_ip} has been blocked via Windows Firewall.")
            else:
                st.error(
                    "Failed to add firewall rule. "
                    "Make sure you are running with administrator privileges."
                )

    st.divider()

    with st.expander("Traffic Analysis Chart", expanded=False):
        fig = px.bar(
            df,
            x="timestamp",
            y="packet_count",
            color="src_ip",
            title="Attack Intensity Over Time",
        )
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Detected Attacks")
    st.dataframe(df, use_container_width=True)

else:
    st.info("No attacks detected yet. System is listening...")