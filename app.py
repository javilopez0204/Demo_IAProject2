# ==========================================
# PARCHE MULTIPLATAFORMA (LOCAL VS CLOUD)
# ==========================================
try:
    __import__('pysqlite3')
    import sys
    sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')
except ImportError:
    pass # Si estamos en Windows local, usamos el sqlite3 nativo

import streamlit as st
import sqlite3
import hashlib
import time
from datetime import datetime

# ==========================================
# IMPORTACIÓN DEL MÓDULO DE IA (CEREBRO)
# ==========================================
from core_ai import estructurar_memoria, simular_respuesta_avatar, collection

# ==========================================
# 1. CONFIGURACIÓN Y CONEXIONES (SQLITE)
# ==========================================
conn = sqlite3.connect('temporal_eco.db', check_same_thread=False)
c = conn.cursor()

# 1. Creamos la tabla base si es un despliegue 100% nuevo
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY, 
              username TEXT UNIQUE, 
              password TEXT, 
              onboarding_done BOOLEAN)''')

# 2. SISTEMA DE MIGRACIÓN AUTOMÁTICA
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
# 2. FUNCIONES DE BASE DE DATOS Y LÓGICA
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

def login_user(username, password):
    c.execute("SELECT id, username, onboarding_done, kromos_score, avatar_created FROM users WHERE username=? AND password=?", 
              (username, hash_password(password)))
    return c.fetchone()

def guardar_memoria(user_id, texto):
    # Usamos la función importada de core_ai.py
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
    
    # Guardamos en la colección vectorial (importada de core_ai.py)
    collection.add(documents=[texto], metadatas=[chroma_meta], ids=[doc_id])
    
    # Guardamos en la BD relacional local
    c.execute("UPDATE users SET kromos_score = kromos_score + ? WHERE id = ?", (score_obtenido, user_id))
    conn.commit()
    st.session_state['kromos_score'] += score_obtenido
    
    return metadatos

# ==========================================
# 3. COMPONENTES DE INTERFAZ (UI)
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
                        time.sleep(1.5)
                        st.rerun() 
                    else:
                        st.success(f"Memoria guardada. ¡Avatar sincronizado +{puntos} puntos!")
                        time.sleep(1)
                        st.rerun() 
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
                
            # ESTADO DESBLOQUEADO (100% -> CHAT RAG ACTIVO)
            else:
                st.success("🔓 **SISTEMA NEURONAL OPERATIVO**")
                st.markdown("---")
                
                # Inicializar el historial de chat del avatar si no existe
                if 'chat_historial' not in st.session_state:
                    st.session_state['chat_historial'] = [
                        {"role": "assistant", "content": f"Hola. Soy Kromos, tu reflejo digital al 100% de sincronización. ¿En qué recuerdo quieres que profundicemos hoy?"}
                    ]
                
                # Renderizar el historial de chat visualmente
                for mensaje in st.session_state['chat_historial']:
                    with st.chat_message(mensaje["role"]):
                        st.markdown(mensaje["content"])
                
                # Entrada de texto del usuario para el chat
                if prompt := st.chat_input("Pregúntale algo a tu yo del pasado..."):
                    
                    ventana_deslizante = st.session_state['chat_historial'][-4:] if len(st.session_state['chat_historial']) >= 4 else st.session_state['chat_historial']
                    
                    with st.chat_message("user"):
                        st.markdown(prompt)
                    st.session_state['chat_historial'].append({"role": "user", "content": prompt})
                    
                    with st.chat_message("assistant"):
                        with st.spinner("Kromos está conectando recuerdos..."):
                            # Usamos la función importada de core_ai.py
                            respuesta_ia, recuerdos_usados = simular_respuesta_avatar(
                                st.session_state['user_id'], 
                                nombre_usuario, 
                                prompt,
                                ventana_deslizante
                            )
                            st.markdown(respuesta_ia)
                            
                            with st.expander("Ver contexto inyectado (Modo Debug)"):
                                st.markdown("**Memoria a Corto Plazo (Ventana):**")
                                st.json(ventana_deslizante)
                                st.markdown("**Memoria a Largo Plazo (ChromaDB):**")
                                if recuerdos_usados:
                                    for r in recuerdos_usados:
                                        st.caption(f"💭 {r}")
                                else:
                                    st.caption("No se encontraron recuerdos específicos.")
                                    
                    st.session_state['chat_historial'].append({"role": "assistant", "content": respuesta_ia})

# ==========================================
# 4. CONTROLADOR PRINCIPAL (MAIN)
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
                    st.session_state['username'] = user_data[1] 
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