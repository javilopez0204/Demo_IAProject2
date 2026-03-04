# app.py
import streamlit as st
import sqlite3
import hashlib
import pandas as pd
import chromadb

# Importamos las dos funciones clave de nuestro cerebro (LangGraph)
from core_ai import estructurar_memoria, simular_respuesta_avatar

# ==========================================
# 1. CONFIGURACIÓN DE PÁGINA Y BASE DE DATOS
# ==========================================
st.set_page_config(page_title="Kromos | Cápsula del Tiempo", page_icon="🧬", layout="centered")

chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="user_memories")

def init_db():
    conn = sqlite3.connect('temporal_eco.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE,
                  password TEXT,
                  avatar_created BOOLEAN DEFAULT 0,
                  kromos_score INTEGER DEFAULT 0)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS calendario_capsula
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  fecha TEXT, titulo TEXT, descripcion TEXT)''')
    conn.commit()
    conn.close()

init_db()

# ==========================================
# 2. FUNCIONES DE AUTENTICACIÓN
# ==========================================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login_user(username, password):
    conn = sqlite3.connect('temporal_eco.db')
    c = conn.cursor()
    c.execute('SELECT id, kromos_score, avatar_created FROM users WHERE username=? AND password=?', (username, hash_password(password)))
    data = c.fetchone()
    conn.close()
    return data

def create_user(username, password):
    conn = sqlite3.connect('temporal_eco.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hash_password(password)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def update_user_score(user_id, points):
    conn = sqlite3.connect('temporal_eco.db')
    c = conn.cursor()
    c.execute('SELECT kromos_score FROM users WHERE id=?', (user_id,))
    current_score = c.fetchone()[0]
    new_score = current_score + points
    
    avatar_created = 1 if new_score >= 50 else 0
    
    c.execute('UPDATE users SET kromos_score=?, avatar_created=? WHERE id=?', (new_score, avatar_created, user_id))
    conn.commit()
    conn.close()
    return new_score, avatar_created

# ==========================================
# 3. LÓGICA DE MEMORIA (RAG)
# ==========================================
def guardar_memoria(user_id, texto):
    with st.spinner("Analizando cognitivamente tu recuerdo..."):
        metadatos = estructurar_memoria(texto)
        puntos = metadatos.get("importance_score", 5) 
        
        doc_id = f"user_{user_id}_mem_{hashlib.md5(texto.encode()).hexdigest()[:8]}"
        collection.add(
            documents=[texto],
            metadatas=[{"user_id": user_id, "emotions": str(metadatos.get("emotions", [])), "score": puntos}],
            ids=[doc_id]
        )
        
        nuevo_score, avatar_listo = update_user_score(user_id, puntos)
        return nuevo_score, avatar_listo

# ==========================================
# 4. INTERFAZ DE USUARIO (UI)
# ==========================================
if 'user_id' not in st.session_state:
    st.title("🧬 Bienvenido a Kromos")
    st.write("Tu ecosistema de memoria persistente y gemelo digital.")
    
    menu = st.radio("Menú", ["Iniciar Sesión", "Registrarse"])
    
    username = st.text_input("Usuario")
    password = st.text_input("Contraseña", type="password")
    
    if menu == "Registrarse":
        if st.button("Crear cuenta"):
            if create_user(username, password):
                st.success("Cuenta creada. Por favor, inicia sesión.")
            else:
                st.error("El usuario ya existe.")
                
    elif menu == "Iniciar Sesión":
        if st.button("Entrar"):
            user_data = login_user(username, password)
            if user_data:
                st.session_state['user_id'] = user_data[0]
                st.session_state['username'] = username
                st.session_state['score'] = user_data[1]
                st.session_state['avatar_created'] = user_data[2]
                st.session_state['chat_history'] = [] # Inicializamos el historial del chat web
                st.rerun()
            else:
                st.error("Credenciales incorrectas.")

else:
    # ------------------------------------------
    # PANTALLA PRINCIPAL (USUARIO LOGUEADO)
    # ------------------------------------------
    st.sidebar.title(f"👤 {st.session_state['username']}")
    st.sidebar.progress(min(st.session_state['score'] / 50.0, 1.0), text=f"Sincronización: {st.session_state['score']}/50 pts")
    
    if st.sidebar.button("Cerrar Sesión"):
        st.session_state.clear()
        st.rerun()

    if st.session_state['score'] >= 50:
        st.success("🔓 SISTEMA NEURONAL OPERATIVO. Kromos está listo.")
    else:
        st.warning(f"⚠️ Sincronización incompleta. Necesitas {50 - st.session_state['score']} puntos más para despertar al Avatar.")

    tab1, tab2, tab3 = st.tabs(["💬 Chat Neural", "📝 Mi Diario", "🗓️ Calendario Futuro"])

    # --- PESTAÑA 1: CHAT NEURAL (RESTAURADO) ---
    with tab1:
        # Usamos columnas para alinear el título y el botón de reset
        col_titulo, col_boton = st.columns([3, 1])
        with col_titulo:
            st.header("💬 Chat Local con Kromos")
        with col_boton:
            # BOTÓN DE NUEVA CONVERSACIÓN
            if st.button("🗑️ Limpiar Chat"):
                st.session_state['chat_history'] = []
                st.rerun()

        if st.session_state['score'] >= 50:
            st.info("Puedes hablar con Kromos desde aquí o desde WhatsApp.")
            
            # 1. Mostrar historial de mensajes de la sesión web
            for msg in st.session_state['chat_history']:
                with st.chat_message(msg["role"]):
                    st.write(msg["content"])
            
            # 2. Input del usuario
            prompt = st.chat_input("Escribe tu mensaje a Kromos...")
            if prompt:
                with st.chat_message("user"):
                    st.write(prompt)
                
                with st.spinner("Kromos está procesando..."):
                    respuesta_final, recuerdos_usados = simular_respuesta_avatar(
                        st.session_state['user_id'],
                        st.session_state['username'],
                        prompt,
                        st.session_state['chat_history'] 
                    )
                
                st.session_state['chat_history'].append({"role": "user", "content": prompt})
                st.session_state['chat_history'].append({"role": "assistant", "content": respuesta_final})
                
                st.rerun()
        else:
            st.write("El núcleo cognitivo de Kromos aún está inactivo. Ve a 'Mi Diario' para darle contexto.")

    # --- PESTAÑA 2: MI DIARIO ---
    with tab2:
        st.header("📝 Ingesta de Memoria")
        st.write("Escribe un recuerdo o hito importante. Kromos lo analizará y lo integrará en su red neuronal.")
        
        nuevo_recuerdo = st.text_area("¿Qué quieres preservar en tu cápsula hoy?", height=150)
        
        if st.button("Guardar en la Cápsula"):
            if nuevo_recuerdo:
                nuevo_score, avatar_listo = guardar_memoria(st.session_state['user_id'], nuevo_recuerdo)
                st.session_state['score'] = nuevo_score
                st.session_state['avatar_created'] = avatar_listo
                st.success("¡Memoria asimilada correctamente!")
                if avatar_listo:
                    st.balloons()
                st.rerun()
            else:
                st.error("El recuerdo no puede estar vacío.")

    # --- PESTAÑA 3: CALENDARIO FUTURO ---
    with tab3:
        st.header("🗓️ Tu Visión Futura (Calendario)")
        st.write("Aquí se muestran los eventos que Kromos ha agendado autónomamente.")
        
        try:
            conn = sqlite3.connect('temporal_eco.db')
            df = pd.read_sql_query("SELECT fecha as Fecha, titulo as Título, descripcion as Descripción FROM calendario_capsula ORDER BY fecha ASC", conn)
            conn.close()
            
            if not df.empty:
                st.dataframe(df, use_container_width=True, hide_index=True)
                # Botón útil para refrescar la tabla si agendas algo por WhatsApp mientras tienes la web abierta
                if st.button("🔄 Refrescar Calendario"):
                    st.rerun()
            else:
                st.info("No tienes eventos futuros programados. Pídele a Kromos en el chat que te recuerde algo.")
        except Exception as e:
            st.info("No tienes eventos futuros programados. Pídele a Kromos en el chat que te recuerde algo.")