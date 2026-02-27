# ==========================================
# PARCHE DE INFRAESTRUCTURA PARA DEPLOYMENT
# ==========================================
__import__('pysqlite3')
import sys
sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

import streamlit as st
import sqlite3
import hashlib
import json
from datetime import datetime
import google.generativeai as genai
import chromadb

# ==========================================
# 1. CONFIGURACIÓN Y CONEXIONES
# ==========================================
# Configura tu API Key de Gemini aquí (idealmente usar st.secrets)
# Usar el manejador de secretos de Streamlit
api_key = st.secrets["GEMINI_API_KEY"]
genai.configure(api_key=api_key)
model = genai.GenerativeModel('gemini-2.5-flash') # Modelo rápido y eficiente para estructuración

# Inicializar ChromaDB (Local)
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="user_memories")

# Inicializar SQLite
conn = sqlite3.connect('temporal_eco.db', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, onboarding_done BOOLEAN)''')
conn.commit()

# ==========================================
# 2. LÓGICA DE IA Y PROMPT ENGINEERING
# ==========================================
PROMPT_ESTRUCTURADOR = """
Eres el 'Estructurador Cognitivo' de una cápsula del tiempo. 
Tu trabajo es analizar la siguiente entrada del diario de un usuario y extraer los metadatos clave en formato JSON estrictamente válido.
No añadas texto adicional fuera del JSON.

Esquema JSON esperado:
{
  "summary": "Resumen de 1 oración",
  "emotions": ["emocion1", "emocion2"],
  "people_mentioned": ["persona1"],
  "tags": ["etiqueta1", "etiqueta2"],
  "importance_score": <int del 1 al 10, donde 10 es un hito de vida y 1 es trivial>
}

Entrada del usuario: 
"""

def estructurar_memoria(texto):
    response = model.generate_content(PROMPT_ESTRUCTURADOR + texto)
    try:
        # Limpiar posible formato Markdown de la respuesta del LLM
        clean_json = response.text.replace('```json', '').replace('```', '').strip()
        return json.loads(clean_json)
    except Exception as e:
        st.error(f"Error parseando JSON del LLM: {e}")
        return {}

# ==========================================
# 3. FUNCIONES DE BASE DE DATOS Y ESTADO
# ==========================================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_user(username, password):
    c.execute("SELECT id, onboarding_done FROM users WHERE username=? AND password=?", (username, hash_password(password)))
    return c.fetchone()

def register_user(username, password):
    try:
        c.execute("INSERT INTO users (username, password, onboarding_done) VALUES (?, ?, ?)", 
                  (username, hash_password(password), False))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def guardar_memoria(user_id, texto):
    # 1. Pasar por el LLM para estructurar
    metadatos = estructurar_memoria(texto)
    
    # 2. Guardar en Vector DB (ChromaDB genera el embedding automáticamente por defecto)
    doc_id = f"{user_id}_{datetime.now().timestamp()}"
    
    # Preparamos los metadatos para ChromaDB (no soporta listas directamente, las convertimos a strings separados por comas)
    chroma_meta = {
        "user_id": user_id,
        "date": datetime.now().isoformat(),
        "emotions": ",".join(metadatos.get("emotions", [])),
        "people": ",".join(metadatos.get("people_mentioned", [])),
        "importance": metadatos.get("importance_score", 1)
    }
    
    collection.add(
        documents=[texto],
        metadatas=[chroma_meta],
        ids=[doc_id]
    )
    return metadatos

# ==========================================
# 4. INTERFAZ DE STREAMLIT (UI/UX)
# ==========================================
def main():
    st.title("⏳ Cápsula del Tiempo IA - Demo MVP")

    # Inicializar estado de sesión
    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False
        st.session_state['user_id'] = None
        st.session_state['onboarding_done'] = False

    # PANTALLA DE LOGIN / REGISTRO
    if not st.session_state['logged_in']:
        tab1, tab2 = st.tabs(["Iniciar Sesión", "Registrarse"])
        
        with tab1:
            u_login = st.text_input("Usuario (Login)")
            p_login = st.text_input("Contraseña (Login)", type="password")
            if st.button("Entrar"):
                user_data = login_user(u_login, p_login)
                if user_data:
                    st.session_state['logged_in'] = True
                    st.session_state['user_id'] = user_data[0]
                    st.session_state['onboarding_done'] = user_data[1]
                    st.rerun()
                else:
                    st.error("Credenciales incorrectas")
                    
        with tab2:
            u_reg = st.text_input("Usuario (Registro)")
            p_reg = st.text_input("Contraseña (Registro)", type="password")
            if st.button("Crear cuenta"):
                if register_user(u_reg, p_reg):
                    st.success("Cuenta creada. Inicia sesión.")
                else:
                    st.error("El usuario ya existe.")

    # PANTALLA DE ONBOARDING (Cuestionario Base)
    elif not st.session_state['onboarding_done']:
        st.subheader("Cuestionario de Inicialización (Modo Entrevistador)")
        st.write("Para que tu futura IA pueda simularte, necesitamos un contexto base.")
        
        with st.form("onboarding_form"):
            q1 = st.text_area("1. ¿Cuáles son tus valores principales en la vida?")
            q2 = st.text_area("2. Describe un evento de tu pasado que te cambió profundamente.")
            q3 = st.text_area("3. ¿Cuáles son tus mayores miedos y esperanzas?")
            
            submitted = st.form_submit_button("Guardar mi perfil base")
            if submitted:
                if q1 and q2 and q3:
                    with st.spinner("Procesando y guardando memorias base..."):
                        guardar_memoria(st.session_state['user_id'], f"Valores principales: {q1}")
                        guardar_memoria(st.session_state['user_id'], f"Evento que me cambió: {q2}")
                        guardar_memoria(st.session_state['user_id'], f"Miedos y esperanzas: {q3}")
                        
                        c.execute("UPDATE users SET onboarding_done = 1 WHERE id = ?", (st.session_state['user_id'],))
                        conn.commit()
                        st.session_state['onboarding_done'] = True
                        st.success("¡Perfil base creado!")
                        st.rerun()
                else:
                    st.warning("Por favor responde a todas las preguntas para inicializar tu perfil.")

    # PANTALLA PRINCIPAL (Diario / Ingestión de Contexto)
    else:
        st.subheader("Tu Diario de Vida")
        if st.button("Cerrar Sesión"):
            st.session_state.clear()
            st.rerun()

        nueva_entrada = st.text_area("¿Qué tienes en mente hoy? Escribe cómo te sientes, qué pasó, o reflexiones aleatorias.")
        
        if st.button("Guardar en la Cápsula"):
            if nueva_entrada:
                with st.spinner("El Estructurador IA está analizando tu memoria..."):
                    meta = guardar_memoria(st.session_state['user_id'], nueva_entrada)
                    st.success("Memoria guardada y estructurada exitosamente.")
                    with st.expander("Ver metadatos extraídos por la IA (Modo Debug)"):
                        st.json(meta)
            else:
                st.warning("No puedes guardar un recuerdo vacío.")

if __name__ == '__main__':
    main()