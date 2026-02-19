import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
import os
import subprocess

st.set_page_config(page_title="Emirzone IDS/IPS Dashboard", layout="wide")

def get_data():
    if not os.path.exists("logs/attacks.db"):
        return pd.DataFrame()
    try:
        with sqlite3.connect("logs/attacks.db") as conn:
            df = pd.read_sql_query("SELECT * FROM attacks ORDER BY timestamp DESC", conn)
            return df
    except:
        return pd.DataFrame()

def block_ip_firewall(ip_address):
    """Windows Güvenlik Duvarı üzerinden IP'yi engeller"""
    try:
        # CMD üzerinden Firewall kuralı ekleme komutu
        rule_name = f"IDS_BLOCK_{ip_address}"
        command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
        
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        # Komut başarılı olduysa (Tamam veya OK döner)
        if result.returncode == 0 or "Tamam" in result.stdout or "OK" in result.stdout:
            return True
        return False
    except Exception as e:
        return False

st.title("🛡️ Custom Network IDS/IPS Dashboard")

df = get_data()

# Üst Metrikler
col1, col2, col3, col4 = st.columns(4)
col1.metric("Sistem Durumu", "AKTİF", delta="Koruma Açık")
col2.metric("Toplam Kayıt", len(df))
col3.metric("Son Saldırı IP", df["src_ip"].iloc[0] if not df.empty else "Yok")

with col4:
    st.write("")
    if st.button("🔄 Verileri Yenile", use_container_width=True):
        st.rerun()

st.divider()

if not df.empty:
    # IPS MODU - AKTİF ENGELLEME
    st.subheader("🛑 IPS Modu: Aktif Savunma (Güvenlik Duvarı)")
    unique_ips = df["src_ip"].unique()
    
    ips_col1, ips_col2 = st.columns([3, 1])
    with ips_col1:
        selected_ip = st.selectbox("Engellenecek Saldırgan IP'yi Seçin:", unique_ips)
    with ips_col2:
        st.write("") # Butonu hizalamak için boşluk
        if st.button("⛔ IP'yi Engelle", type="primary", use_container_width=True):
            if block_ip_firewall(selected_ip):
                st.success(f"Başarılı! {selected_ip} adresi Windows Güvenlik Duvarı tarafından engellendi.")
            else:
                st.error("Hata! VS Code'u 'Yönetici Olarak Çalıştır' seçeneğiyle açtığınızdan emin olun.")
                
    st.divider()

    # Görsel Analiz (Tıklayınca açılır)
    with st.expander("📈 Görsel Trafik Analizini Göster", expanded=False):
        fig = px.bar(df, x="timestamp", y="packet_count", color="src_ip", title="Saldırı Şiddeti Analizi")
        st.plotly_chart(fig, use_container_width=True)
    
    # Tablo
    st.subheader("🚨 Tespit Edilen Tüm Saldırılar")
    st.dataframe(df, use_container_width=True)
else:
    st.info("Henüz bir saldırı tespit edilmedi. Sistem dinlemede...")