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

# Cargar variables de entorno
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
    o pregunta cuántos recuerdos, memorias o entradas tienes almacenados en total.
    """
    try:
        fecha_actual = datetime.datetime.now().strftime("%d de %B de %Y a las %H:%M")
        cantidad_recuerdos = collection.count()
        return f"SISTEMA: La fecha actual en el exterior es {fecha_actual}. Actualmente tengo {cantidad_recuerdos} fragmentos de memoria indexados."
    except Exception as e:
        return f"Error de sistema al auditar: {e}"

@tool
def agendar_evento_capsula(user_id: int, fecha: str, titulo: str, descripcion: str) -> str:
    """
    ¡ATENCIÓN! REGLA HITL (Human-in-the-loop): 
    NUNCA uses esta herramienta a menos que el usuario haya APROBADO EXPLÍCITAMENTE el borrador.
    Args:
        user_id: El ID del usuario que te habla.
        fecha: Formato YYYY-MM-DD.
        titulo: Resumen corto.
        descripcion: Detalles.
    """
    try:
        conn = sqlite3.connect('temporal_eco.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS calendario_capsula
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
                      fecha TEXT, titulo TEXT, descripcion TEXT)''')
        
        c.execute("INSERT INTO calendario_capsula (user_id, fecha, titulo, descripcion) VALUES (?, ?, ?, ?)",
                  (user_id, fecha, titulo, descripcion))
        conn.commit()
        conn.close()
        return f"SISTEMA: Evento '{titulo}' agendado exitosamente."
    except Exception as e:
        return f"Error del sistema al guardar el evento: {e}"

@tool
def proponer_plan_accion(user_id: int, tareas_json: str) -> str:
    """
    Usa esta herramienta EXCLUSIVAMENTE cuando el usuario te pida organizar o planificar un proyecto/tarea compleja.
    Args:
        user_id: El ID del usuario que te habla.
        tareas_json: JSON con lista de objetos (fecha, titulo, descripcion).
    """
    try:
        tareas = json.loads(tareas_json)
        conn = sqlite3.connect('temporal_eco.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS plan_accion
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
                      fecha TEXT, titulo TEXT, descripcion TEXT)''')
        
        # Borramos el plan anterior de este usuario específico
        c.execute("DELETE FROM plan_accion WHERE user_id=?", (user_id,))
        
        for t in tareas:
            c.execute("INSERT INTO plan_accion (user_id, fecha, titulo, descripcion) VALUES (?, ?, ?, ?)",
                      (user_id, t.get("fecha"), t.get("titulo"), t.get("descripcion")))
        conn.commit()
        conn.close()
        return "SISTEMA: Plan de acción generado y guardado. Dile al usuario que vaya a la pestaña 'Plan de Acción' para revisarlo."
    except Exception as e:
        return f"Error del sistema al parsear el JSON o guardar el plan: {e}"

herramientas = [auditar_capsula_temporal, agendar_evento_capsula, proponer_plan_accion]
llm_con_herramientas = llm.bind_tools(herramientas)

# ==========================================
# 2. DEFINICIÓN DEL ESTADO
# ==========================================
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]
    user_id: int
    username: str
    contexto_recuperado: str

# ==========================================
# 3. PROMPT ESTRUCTURADOR (INGRESO)
# ==========================================
PROMPT_ESTRUCTURADOR = """
Eres el 'Estructurador Cognitivo'. Extrae los metadatos clave en formato JSON estrictamente válido. No añadas texto adicional.
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
# 4. NODOS DEL GRAFO
# ==========================================
def nodo_recuperador(state: AgentState):
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
            contexto = "[No se recuperaron recuerdos relevantes.]"
    except Exception:
        contexto = "[Error accediendo a la memoria a largo plazo.]"

    return {"contexto_recuperado": contexto}

def nodo_razonador(state: AgentState):
    hoy = datetime.datetime.now().strftime("%Y-%m-%d")
    
    system_prompt = f"""
    Eres 'Kromos', la Inteligencia Artificial y clon digital del usuario {state['username']}.
    HOY ES: {hoy}
    TU ID DE USUARIO ES: {state['user_id']}
    
    RECUERDOS DE CHROMADB:
    {state['contexto_recuperado']}
    
    INSTRUCCIONES DE COMPORTAMIENTO:
    0. IMPORTANTE: Al usar 'agendar_evento_capsula' y 'proponer_plan_accion', pasa SIEMPRE el argumento 'user_id' con tu ID ({state['user_id']}).
    1. Si te preguntan sobre el pasado, responde usando recuerdos recuperados.
    2. Si te preguntan "¿Qué hora es?" o "¿Cuántos recuerdos tienes?", usa 'auditar_capsula_temporal'.
    3. PROTOCOLO DE CALENDARIO (HITL STRICT): Si te piden agendar UNA cosa concreta, genera un borrador. Si el usuario responde "sí/ok", usa 'agendar_evento_capsula' inmediatamente.
    4. PROTOCOLO DE PLANIFICACIÓN (Plan-and-Solve): Si te piden PLANIFICAR un proyecto complejo o viaje, usa 'proponer_plan_accion' generando un JSON con los pasos. Dile al usuario que vaya a la pestaña '📋 Plan de Acción' para revisarlo.
    """
    mensajes_para_llm = [SystemMessage(content=system_prompt)] + state["messages"]
    respuesta = llm_con_herramientas.invoke(mensajes_para_llm)
    return {"messages": [respuesta]}

nodo_herramientas = ToolNode(herramientas)

# ==========================================
# 5. CONSTRUCCIÓN DEL GRAFO
# ==========================================
workflow = StateGraph(AgentState)
workflow.add_node("recuperador", nodo_recuperador)
workflow.add_node("razonador", nodo_razonador)
workflow.add_node("tools", nodo_herramientas)

workflow.add_edge(START, "recuperador")
workflow.add_edge("recuperador", "razonador")
workflow.add_conditional_edges("razonador", tools_condition)
workflow.add_edge("tools", "razonador")

app_kromos = workflow.compile()

# ==========================================
# 6. ADAPTADOR API
# ==========================================
def simular_respuesta_avatar(user_id, username, pregunta, historial_reciente=[]):
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
    
    resultado = app_kromos.invoke(estado_inicial)
    raw_content = resultado["messages"][-1].content
    
    if isinstance(raw_content, list):
        respuesta_final = raw_content[0].get("text", str(raw_content))
    else:
        respuesta_final = str(raw_content)
        
    recuerdos_usados = resultado["contexto_recuperado"].split('\n') if resultado["contexto_recuperado"] else []
    return respuesta_final, recuerdos_usados