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
import time
from datetime import datetime
import google.generativeai as genai
import chromadb

# ==========================================
# 1. CONFIGURACIÓN Y CONEXIONES
# ==========================================
try:
    api_key = st.secrets["GEMINI_API_KEY"]
    genai.configure(api_key=api_key)
except KeyError:
    st.error("🚨 Error crítico: La clave 'GEMINI_API_KEY' no está configurada en los secretos de Streamlit.")
    st.stop()

model = genai.GenerativeModel('gemini-2.5-flash')

chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="user_memories")

conn = sqlite3.connect('temporal_eco.db', check_same_thread=False)
c = conn.cursor()

# 1. Creamos la tabla base si es un despliegue 100% nuevo
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY, 
              username TEXT UNIQUE, 
              password TEXT, 
              onboarding_done BOOLEAN)''')

# 2. SISTEMA DE MIGRACIÓN AUTOMÁTICA
# Intentamos añadir las nuevas columnas a la tabla existente. 
# Si ya existen, SQLite lanzará un error que ignoramos silenciosamente.
try:
    c.execute("ALTER TABLE users ADD COLUMN kromos_score INTEGER DEFAULT 0")
except Exception:
    pass # La columna kromos_score ya existía

try:
    c.execute("ALTER TABLE users ADD COLUMN avatar_created BOOLEAN DEFAULT 0")
except Exception:
    pass # La columna avatar_created ya existía

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
        clean_json = response.text.replace('```json', '').replace('```', '').strip()
        return json.loads(clean_json)
    except Exception as e:
        st.error(f"Error parseando JSON del LLM: {e}")
        return {}

# ==========================================
# 3. FUNCIONES DE BASE DE DATOS Y LÓGICA
# ==========================================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    try:
        c.execute("INSERT INTO users (username, password, onboarding_done, kromos_score, avatar_created) VALUES (?, ?, ?, ?, ?)", 
                  (username, hash_password(password), False, 0, False))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

# MODIFICACIÓN: Ahora recuperamos el username en la posición 1
def login_user(username, password):
    c.execute("SELECT id, username, onboarding_done, kromos_score, avatar_created FROM users WHERE username=? AND password=?", 
              (username, hash_password(password)))
    return c.fetchone()

def guardar_memoria(user_id, texto):
    metadatos = estructurar_memoria(texto)
    doc_id = f"{user_id}_{datetime.now().timestamp()}"
    score_obtenido = metadatos.get("importance_score", 1)
    
    chroma_meta = {
        "user_id": user_id,
        "date": datetime.now().isoformat(),
        "emotions": ",".join(metadatos.get("emotions", [])),
        "people": ",".join(metadatos.get("people_mentioned", [])),
        "importance": score_obtenido
    }
    collection.add(documents=[texto], metadatas=[chroma_meta], ids=[doc_id])
    
    c.execute("UPDATE users SET kromos_score = kromos_score + ? WHERE id = ?", (score_obtenido, user_id))
    conn.commit()
    st.session_state['kromos_score'] += score_obtenido
    
    return metadatos

# ==========================================
# 4. COMPONENTES DE INTERFAZ (UI)
# ==========================================
def renderizar_dashboard():
    st.subheader("Tu Espacio Personal")
    
    if st.button("Cerrar Sesión"):
        st.session_state.clear()
        st.rerun()

    KROMOS_TARGET = 50 
    progreso_actual = min(st.session_state.get('kromos_score', 0), KROMOS_TARGET)
    porcentaje = int((progreso_actual / KROMOS_TARGET) * 100)
    
    # Extraemos el nombre del usuario para el avatar
    nombre_usuario = st.session_state.get('username', 'Usuario')

    tab_diario, tab_kromos = st.tabs(["📝 Mi Diario", "🧠 Kromos (Avatar)"])

    # --- PESTAÑA DIARIO ---
    with tab_diario:
        nueva_entrada = st.text_area("¿Qué tienes en mente hoy? Escribe cómo te sientes, qué pasó, o reflexiones aleatorias.")
        
        if st.button("Guardar en la Cápsula"):
            if nueva_entrada:
                with st.spinner("Procesando memoria e integrando en la red neuronal..."):
                    meta = guardar_memoria(st.session_state['user_id'], nueva_entrada)
                    puntos = meta.get('importance_score', 1)
                    
                    # LOGICA DE CREACIÓN DEL AVATAR (Primera vez)
                    if not st.session_state.get('avatar_created', False):
                        c.execute("UPDATE users SET avatar_created = 1 WHERE id = ?", (st.session_state['user_id'],))
                        conn.commit()
                        st.session_state['avatar_created'] = True
                        st.balloons()
                        st.success("✨ ¡Tu Avatar ha sido creado! Revisa la pestaña 'Kromos'.")
                        time.sleep(1.5) # Pequeña pausa para que el usuario lea el mensaje
                        st.rerun() # FORZAMOS EL RE-RENDERIZADO PARA ACTUALIZAR LA OTRA PESTAÑA
                    else:
                        st.success(f"Memoria guardada. ¡Avatar sincronizado +{puntos} puntos!")
                        time.sleep(1)
                        st.rerun() # Forzamos recarga para ver avanzar la barra
            else:
                st.warning("No puedes guardar un recuerdo vacío.")

    # --- PESTAÑA KROMOS ---
    with tab_kromos:
        # SI EL AVATAR AÚN NO HA SIDO CREADO
        if not st.session_state.get('avatar_created', False):
            st.info("🧬 **No hay ningún avatar asignado.**\n\nVe a 'Mi Diario' y escribe tu primera entrada libre para inicializar el núcleo de tu avatar.")
            
        # SI EL AVATAR YA ESTÁ CREADO
        else:
            st.markdown(f"## 👤 Avatar: {nombre_usuario}")
            
            # ESTADO BLOQUEADO (< 100%)
            if porcentaje < 100:
                st.error("🔒 **ESTADO: BLOQUEADO**")
                st.progress(porcentaje / 100.0)
                st.write(f"**Sincronización:** {porcentaje}% ({progreso_actual}/{KROMOS_TARGET} puntos)")
                st.info("El avatar necesita más contexto emocional y vivencial para poder simular tu personalidad con precisión. Continúa escribiendo en 'Mi Diario'.")
                
            # ESTADO DESBLOQUEADO (100%)
            else:
                st.success("🔓 **ESTADO: DESBLOQUEADO**")
                st.progress(1.0)
                st.write("**Sincronización:** 100% - ¡Avatar Operativo!")
                st.markdown("---")
                st.write("*(Interfaz de chat RAG en construcción...)*")

# ==========================================
# 5. CONTROLADOR PRINCIPAL (MAIN)
# ==========================================
def main():
    st.title("⏳ Cápsula del Tiempo IA")

    if 'logged_in' not in st.session_state:
        st.session_state['logged_in'] = False
        st.session_state['user_id'] = None
        st.session_state['username'] = None
        st.session_state['onboarding_done'] = False
        st.session_state['kromos_score'] = 0
        st.session_state['avatar_created'] = False

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
                    st.session_state['username'] = user_data[1] # Guardamos el nombre
                    st.session_state['onboarding_done'] = user_data[2]
                    st.session_state['kromos_score'] = user_data[3]
                    st.session_state['avatar_created'] = bool(user_data[4])
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

    # PANTALLA DE ONBOARDING
    elif not st.session_state['onboarding_done']:
        st.subheader("Cuestionario de Inicialización")
        with st.form("onboarding_form"):
            q1 = st.text_area("1. ¿Cuáles son tus valores principales en la vida?")
            q2 = st.text_area("2. Describe un evento de tu pasado que te cambió profundamente.")
            q3 = st.text_area("3. ¿Cuáles son tus mayores miedos y esperanzas?")
            
            submitted = st.form_submit_button("Guardar mi perfil base")
            if submitted:
                if q1 and q2 and q3:
                    with st.spinner("Procesando memorias base..."):
                        guardar_memoria(st.session_state['user_id'], f"Valores principales: {q1}")
                        guardar_memoria(st.session_state['user_id'], f"Evento que me cambió: {q2}")
                        guardar_memoria(st.session_state['user_id'], f"Miedos y esperanzas: {q3}")
                        
                        c.execute("UPDATE users SET onboarding_done = 1 WHERE id = ?", (st.session_state['user_id'],))
                        conn.commit()
                        st.session_state['onboarding_done'] = True
                        st.success("¡Perfil base creado! Pasando a tu cápsula...")
                        time.sleep(1)
                        st.rerun()
                else:
                    st.warning("Por favor responde a todas las preguntas para inicializar tu perfil.")

    # DASHBOARD PRINCIPAL
    else:
        renderizar_dashboard()

if __name__ == '__main__':
    main()