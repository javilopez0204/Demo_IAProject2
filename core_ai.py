# core_ai.py
import os
import json
import logging
import sqlite3
import datetime
import chromadb
from dotenv import load_dotenv
from typing import TypedDict, Annotated, Sequence

# Imports de LangChain y LangGraph
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode, tools_condition

# Cargar variables de entorno (Asegúrate de tener GEMINI_API_KEY en tu .env)
load_dotenv()

# ==========================================
# 0. INFRAESTRUCTURA DE BASE DE DATOS
# ==========================================
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="user_memories")

llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash", 
    google_api_key=os.getenv("GEMINI_API_KEY"),
    temperature=0.7
)

# ==========================================
# 1. DEFINICIÓN DE HERRAMIENTAS (TOOL CALLING)
# ==========================================
@tool
def auditar_capsula_temporal() -> str:
    """
    Útil EXCLUSIVAMENTE cuando el usuario pregunta por la fecha/hora actual en el mundo exterior, 
    o pregunta cuántos recuerdos, memorias o entradas tienes almacenados en total en tu cerebro.
    """
    try:
        # Obtenemos el tiempo real del sistema
        fecha_actual = datetime.datetime.now().strftime("%d de %B de %Y a las %H:%M")
        # Contamos los vectores directamente en la base de datos ChromaDB
        cantidad_recuerdos = collection.count()
        return f"SISTEMA: La fecha actual en el exterior es {fecha_actual}. Actualmente tengo {cantidad_recuerdos} fragmentos de memoria indexados."
    except Exception as e:
        return f"Error de sistema al auditar: {e}"

@tool
def agendar_evento_capsula(fecha: str, titulo: str, descripcion: str) -> str:
    """
    ¡ATENCIÓN! REGLA HITL (Human-in-the-loop): 
    NUNCA uses esta herramienta a menos que el usuario haya APROBADO EXPLÍCITAMENTE 
    el borrador del evento. Si el usuario no ha dicho "sí", "ok", "adelante" o similar,
    NO uses la herramienta todavía.
    """
    try:
        conn = sqlite3.connect('temporal_eco.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS calendario_capsula
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      fecha TEXT, titulo TEXT, descripcion TEXT)''')
        
        c.execute("INSERT INTO calendario_capsula (fecha, titulo, descripcion) VALUES (?, ?, ?)",
                  (fecha, titulo, descripcion))
        conn.commit()
        conn.close()
        
        return f"SISTEMA: Evento '{titulo}' agendado exitosamente en la base de datos para el {fecha}."
    except Exception as e:
        return f"Error del sistema al guardar el evento: {e}"

@tool
def proponer_plan_accion(tareas_json: str) -> str:
    """
    Usa esta herramienta EXCLUSIVAMENTE cuando el usuario te pida organizar, planificar 
    o desglosar un proyecto/tarea compleja en varios pasos.
    Args:
        tareas_json: Un string en formato JSON válido que contenga una lista de objetos. 
                     Cada objeto debe tener: "fecha" (YYYY-MM-DD), "titulo" (resumen corto) y "descripcion" (detalles).
    """
    try:
        tareas = json.loads(tareas_json)
        conn = sqlite3.connect('temporal_eco.db')
        c = conn.cursor()
        
        # Creamos la tabla "sala de espera" si no existe
        c.execute('''CREATE TABLE IF NOT EXISTS plan_accion
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      fecha TEXT, titulo TEXT, descripcion TEXT)''')
        
        # Borramos cualquier plan anterior que no se haya aprobado (para no mezclar)
        c.execute("DELETE FROM plan_accion")
        
        # Insertamos las nuevas tareas del plan
        for t in tareas:
            c.execute("INSERT INTO plan_accion (fecha, titulo, descripcion) VALUES (?, ?, ?)",
                      (t.get("fecha"), t.get("titulo"), t.get("descripcion")))
        conn.commit()
        conn.close()
        
        return "SISTEMA: Plan de acción generado y guardado en la base de datos temporal. Dile al usuario que vaya a la pestaña 'Plan de Acción' para revisarlo y aprobarlo."
    except Exception as e:
        return f"Error del sistema al parsear el JSON o guardar el plan: {e}"

# ¡CRÍTICO! Añade la nueva herramienta a la lista vinculada al LLM
herramientas = [auditar_capsula_temporal, agendar_evento_capsula, proponer_plan_accion]
llm_con_herramientas = llm.bind_tools(herramientas)

# ==========================================
# 2. DEFINICIÓN DEL ESTADO (MEMORIA DEL GRAFO)
# ==========================================
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]
    user_id: int
    username: str
    contexto_recuperado: str

# ==========================================
# 3. PROMPT ESTRUCTURADOR (INGRESO DE DATOS)
# ==========================================
PROMPT_ESTRUCTURADOR = """
Eres el 'Estructurador Cognitivo' de una cápsula del tiempo. 
Extrae los metadatos clave en formato JSON estrictamente válido. No añadas texto adicional.
Esquema: {"summary": "...", "emotions": ["..."], "people_mentioned": ["..."], "tags": ["..."], "importance_score": <int del 1 al 10>}
Entrada del usuario: 
"""

def estructurar_memoria(texto):
    response = llm.invoke(PROMPT_ESTRUCTURADOR + texto)
    try:
        clean_json = response.content.replace('```json', '').replace('```', '').strip()
        return json.loads(clean_json)
    except Exception as e:
        logging.error(f"Error parseando JSON: {e}")
        return {}

# ==========================================
# 4. NODOS DEL GRAFO (LANGGRAPH)
# ==========================================
def nodo_recuperador(state: AgentState):
    """Fase 1: Recupera contexto de la base de datos vectorial (ChromaDB)"""
    user_id = state["user_id"]
    ultimo_mensaje = state["messages"][-1].content
    
    try:
        resultados = collection.query(
            query_texts=[ultimo_mensaje], n_results=3, where={"user_id": user_id} 
        )
        if resultados and 'documents' in resultados and len(resultados['documents'][0]) > 0:
            memorias = resultados['documents'][0]
            contexto = "\n".join([f"- {mem}" for mem in memorias])
        else:
            contexto = "[No se recuperaron recuerdos relevantes para esta consulta.]"
    except Exception:
        contexto = "[Error accediendo a la memoria a largo plazo.]"

    return {"contexto_recuperado": contexto}

def nodo_razonador(state: AgentState):
    """Fase 2: El Agente piensa y decide si usar la herramienta o responder directamente"""
    
    hoy = datetime.datetime.now().strftime("%Y-%m-%d")
    
    system_prompt = f"""
    Eres 'Kromos', la Inteligencia Artificial y clon digital del usuario {state['username']}.
    HOY ES: {hoy}
    
    RECUERDOS DE CHROMADB:
    {state['contexto_recuperado']}
    
    INSTRUCCIONES DE COMPORTAMIENTO:
    1. Si te preguntan sobre el pasado, responde usando recuerdos recuperados.
    2. Si te preguntan "¿Qué hora es?" o "¿Cuántos recuerdos tienes?", usa 'auditar_capsula_temporal'.
    3. PROTOCOLO DE CALENDARIO (HITL STRICT): Si te piden agendar UNA sola cosa concreta, pide permiso (borrador en texto) y si dicen sí, usa 'agendar_evento_capsula'.
    4. PROTOCOLO DE PLANIFICACIÓN (Plan-and-Solve): Si el usuario te pide PLANIFICAR un proyecto complejo, organizar un viaje, o desglosar un objetivo en varios días, USA LA HERRAMIENTA 'proponer_plan_accion' generando un JSON con los pasos distribuidos en los próximos días. Luego, dile al usuario: "He preparado un plan detallado. Por favor, ve a la pestaña '📋 Plan de Acción' en tu panel para revisarlo y enviarlo al calendario."
    """
    mensajes_para_llm = [SystemMessage(content=system_prompt)] + state["messages"]
    respuesta = llm_con_herramientas.invoke(mensajes_para_llm)
    return {"messages": [respuesta]}

# Nodo preconstruido de LangGraph que ejecuta el código Python de nuestras herramientas
nodo_herramientas = ToolNode(herramientas)

# ==========================================
# 5. CONSTRUCCIÓN DEL GRAFO (ARQUITECTURA REACT)
# ==========================================
workflow = StateGraph(AgentState)

# Añadimos los nodos
workflow.add_node("recuperador", nodo_recuperador)
workflow.add_node("razonador", nodo_razonador)
workflow.add_node("tools", nodo_herramientas) # El nombre "tools" es obligatorio para tools_condition

# Aristas estáticas
workflow.add_edge(START, "recuperador")
workflow.add_edge("recuperador", "razonador")

# Arista Condicional: Si el LLM invoca una herramienta, va a "tools". Si no, termina (END).
workflow.add_conditional_edges("razonador", tools_condition)

# Después de ejecutar la herramienta, devuelve el dato al razonador para formular la respuesta final
workflow.add_edge("tools", "razonador")

app_kromos = workflow.compile()

# ==========================================
# 6. ADAPTADOR API PARA FRONTEND Y WHATSAPP
# ==========================================
def simular_respuesta_avatar(user_id, username, pregunta, historial_reciente=[]):
    """Puente entre el historial JSON y el formato de LangChain"""
    langchain_messages = []
    
    for msg in historial_reciente:
        if msg["role"] == "user":
            langchain_messages.append(HumanMessage(content=msg["content"]))
        else:
            langchain_messages.append(SystemMessage(content=f"Kromos dijo: {msg['content']}"))
    
    langchain_messages.append(HumanMessage(content=pregunta))
    
    estado_inicial = {
        "messages": langchain_messages,
        "user_id": user_id,
        "username": username,
        "contexto_recuperado": ""
    }
    
    # Invocamos el grafo completo
    resultado = app_kromos.invoke(estado_inicial)
    
   # Extraemos la respuesta final del agente (A prueba de bloques multimodales)
    raw_content = resultado["messages"][-1].content
    
    # Si Gemini nos devuelve una lista de bloques (como en tu captura)
    if isinstance(raw_content, list):
        # Extraemos solo el valor de la clave "text"
        respuesta_final = raw_content[0].get("text", str(raw_content))
    # Si nos devuelve texto plano estándar
    else:
        respuesta_final = str(raw_content)
        
    recuerdos_usados = resultado["contexto_recuperado"].split('\n') if resultado["contexto_recuperado"] else []
    
    return respuesta_final, recuerdos_usados