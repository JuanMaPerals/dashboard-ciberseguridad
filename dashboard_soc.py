import streamlit as st
import pandas as pd
import requests

# --- Configuración de la Página de Streamlit ---
st.set_page_config(
    page_title="Dashboard de Análisis de IOCs",
    page_icon="🔬",
    layout="wide",
)

# --- Funciones de Lógica de la Aplicación ---

@st.cache_data(ttl=600) # Cachea los datos por 10 minutos (600 segundos)
def fetch_wazuh_data():
    """
    Se conecta a la API de Wazuh CTI para obtener los últimos indicadores.
    Maneja errores si la API no responde.
    """
    url = "https://jh.live/wazuh-cti/api/indicators/"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Error al conectar con la API de Wazuh CTI: {e}")
        return None

def analizar_con_web_check(indicator, api_key):
    """
    Realiza una llamada a la API de web-check.xyz para analizar un indicador.
    """
    api_url = "https://v1.web-check.xyz/api/v1/check"
    headers = {"x-api-key": api_key}
    payload = {"url": indicator}
    
    try:
        with st.spinner(f"Analizando {indicator}... Esto puede tardar un momento."):
            response = requests.post(api_url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Error al analizar con Web-Check: {e}")
        if 'response' in locals() and response.status_code == 401:
            st.error("La clave API parece ser inválida o ha expirado. Por favor, verifícala.")
        return None

def mostrar_resultados_analisis(results):
    """
    Formatea y muestra los resultados del análisis de la API de Web-Check.
    """
    st.success("¡Análisis completado!")

    if not results or 'data' not in results:
        st.warning("La respuesta de la API no contiene datos válidos.")
        return

    data = results['data']

    # Resumen de Amenazas
    if 'threat' in data and data['threat']:
        st.subheader("🚨 Resumen de Amenazas")
        threat_data = data['threat']
        cols = st.columns(3)
        cols[0].metric("Es Malicioso", "Sí" if threat_data.get('is_malicious') else "No")
        cols[1].metric("Es Phishing", "Sí" if threat_data.get('is_phishing') else "No")
        cols[2].metric("Es Sospechoso", "Sí" if threat_data.get('is_suspicious') else "No")

    # Mostrar otros datos en expanders para mantener la interfaz limpia
    with st.expander("🔬 Tecnologías Detectadas"):
        if 'technologies' in data and data['technologies']:
            for tech in data['technologies']:
                st.markdown(f"- **{tech.get('name')}**: {tech.get('version', 'N/A')}")
        else:
            st.info("No se detectaron tecnologías específicas.")
            
    with st.expander("🔒 Cabeceras de Seguridad"):
        if 'headers' in data and 'security' in data['headers']:
             st.json(data['headers']['security'])
        else:
            st.info("No se encontraron cabeceras de seguridad.")

    with st.expander("📄 Información del Dominio y SSL"):
         if 'domain' in data:
            st.write("**Registrador:**", data['domain'].get('registrar'))
            st.write("**Fecha de Creación:**", data['domain'].get('created_date'))
            st.write("**Fecha de Expiración:**", data['domain'].get('expires_date'))
         if 'ssl' in data and data['ssl']:
            st.write("**Emisor del Certificado SSL:**", data['ssl'].get('issuer'))
            st.write("**Válido hasta:**", data['ssl'].get('valid_to'))

    with st.expander("Raw JSON Response"):
        st.json(results)

# --- Interfaz de Usuario del Dashboard ---

st.title("🔬 Dashboard de Análisis de IOCs con API Integrada")
st.markdown("Herramienta educativa para analizar IOCs en tiempo real del feed de **Wazuh CTI** e integrarlos con **Web-Check.xyz**.")

# --- Barra Lateral ---
st.sidebar.header("Configuración y Filtros")

# Campo para la clave API
api_key = st.sidebar.text_input("Introduce tu Clave API de Web-Check.xyz", type="password")
st.sidebar.markdown("[Obtener una clave API gratuita](https://v1.web-check.xyz/dashboard)")

# Cargar datos
data = fetch_wazuh_data()

if data:
    df = pd.DataFrame(data)
    if 'first_seen' in df.columns:
        df['first_seen'] = pd.to_datetime(df['first_seen'])

    # Filtros de Indicadores
    if 'type' in df.columns:
        unique_types = df['type'].unique()
        selected_type = st.sidebar.multiselect(
            "Filtrar por Tipo de IOC:",
            options=unique_types,
            default=list(unique_types)
        )
        df_filtered = df[df['type'].isin(selected_type)]
    else:
        st.sidebar.warning("La columna 'type' no se encuentra en los datos.")
        df_filtered = df

    # --- Cuerpo Principal ---
    total_indicadores = len(df_filtered)
    ips_maliciosas = len(df_filtered[df_filtered['type'] == 'ipv4']) if 'type' in df_filtered.columns else 0
    hashes = len(df_filtered[df_filtered['type'].str.contains('hash', na=False)]) if 'type' in df_filtered.columns else 0

    col1, col2, col3 = st.columns(3)
    col1.metric("Total de Indicadores", f"{total_indicadores}")
    col2.metric("IPs Maliciosas 🕵️", f"{ips_maliciosas}")
    col3.metric("Hashes Detectados 🧬", f"{hashes}")

    st.markdown("---")
    st.subheader("Feed de Indicadores de Compromiso en Tiempo Real")
    st.dataframe(df_filtered, use_container_width=True)
    st.markdown("---")

    # --- Módulo de Análisis Práctico ---
    st.header("🔧 Módulo de Análisis Práctico con API de Web-Check.xyz")
    st.write("Selecciona un indicador (URL o Dominio) para realizar un análisis completo.")

    if 'type' in df.columns and 'value' in df.columns:
        indicadores_analizables = df_filtered[df_filtered['type'].isin(['url', 'domain'])]['value'].unique()
        if len(indicadores_analizables) > 0:
            selected_indicator = st.selectbox("Elige un Indicador para Analizar:", options=indicadores_analizables)
            if st.button(f"🚀 Analizar '{selected_indicator}' con la API"):
                if api_key:
                    results = analizar_con_web_check(selected_indicator, api_key)
                    if results:
                        mostrar_resultados_analisis(results)
                else:
                    st.warning("Por favor, introduce tu clave API de Web-Check.xyz en la barra lateral para continuar.")
        else:
            st.info("No hay indicadores analizables (URLs, Dominios) en el set de datos filtrado actual.")
    else:
        st.warning("Las columnas 'type' o 'value' no se encuentran en los datos para el análisis.")
else:
    st.warning("No se pudieron cargar los datos de Wazuh CTI. Inténtalo de nuevo más tarde.")
