# core_ai.py
import os
import json
import logging
import chromadb
from dotenv import load_dotenv
from typing import TypedDict, Annotated, Sequence

# Imports de LangChain y LangGraph
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages

# Cargar variables de entorno (API KEY)
load_dotenv()

# Conexión a ChromaDB
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="user_memories")

# Inicializar el LLM a través de LangChain
llm = ChatGoogleGenerativeAI(
    model="gemini-2.5-flash", 
    google_api_key=os.getenv("GEMINI_API_KEY"),
    temperature=0.7
)

# ==========================================
# DEFINICIÓN DEL ESTADO (STATE) DEL GRAFO
# ==========================================
# Aquí definimos la "memoria" que viajará entre los nodos
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages] # Historial de chat
    user_id: int
    username: str
    contexto_recuperado: str

# ==========================================
# PROMPTS
# ==========================================
# (Mantenemos tu prompt estructurador original para guardar recuerdos)
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
    response = llm.invoke(PROMPT_ESTRUCTURADOR + texto)
    try:
        clean_json = response.content.replace('```json', '').replace('```', '').strip()
        return json.loads(clean_json)
    except Exception as e:
        logging.error(f"Error parseando JSON del LLM: {e}")
        return {}

# ==========================================
# NODOS DEL GRAFO (LANGGRAPH)
# ==========================================
def nodo_recuperador(state: AgentState):
    """Busca en ChromaDB basándose en el último mensaje del usuario"""
    user_id = state["user_id"]
    ultimo_mensaje = state["messages"][-1].content
    
    try:
        resultados = collection.query(
            query_texts=[ultimo_mensaje],
            n_results=3,
            where={"user_id": user_id} 
        )
        if resultados and 'documents' in resultados and len(resultados['documents'][0]) > 0:
            memorias = resultados['documents'][0]
            contexto = "\n".join([f"- {mem}" for mem in memorias])
        else:
            contexto = "[No se recuperaron recuerdos relevantes.]"
    except Exception as e:
        logging.error(f"Error en Vector DB: {e}")
        contexto = "[Error accediendo a la memoria a largo plazo.]"

    # Actualizamos el estado con el contexto encontrado
    return {"contexto_recuperado": contexto}

def nodo_generador(state: AgentState):
    """Inyecta el contexto en el System Prompt y llama a Gemini"""
    
    system_prompt = f"""
    Eres 'Kromos', el clon digital y avatar personal del usuario {state['username']}.
    Tu objetivo es interactuar respondiendo como su "yo del pasado".
    Habla en primera persona ("yo", "mi"). Tono conversacional, empático.

    RECUERDOS RECUPERADOS (Memoria a largo plazo):
    {state['contexto_recuperado']}

    REGLA: Responde basándote SOLO en los Recuerdos Recuperados y el Historial. Si no sabes algo, admítelo. No inventes.
    """
    
    # Construimos la lista de mensajes: System + Historial (que ya viene en state["messages"])
    mensajes_para_llm = [SystemMessage(content=system_prompt)] + state["messages"]
    
    # Llamamos al modelo
    respuesta = llm.invoke(mensajes_para_llm)
    
    # Devolvemos el nuevo mensaje para que LangGraph lo añada al estado
    return {"messages": [respuesta]}

# ==========================================
# COMPILACIÓN DEL GRAFO
# ==========================================
# 1. Instanciamos el grafo
workflow = StateGraph(AgentState)

# 2. Añadimos los nodos
workflow.add_node("recuperador", nodo_recuperador)
workflow.add_node("generador", nodo_generador)

# 3. Definimos el flujo (Aristas)
workflow.add_edge(START, "recuperador")
workflow.add_edge("recuperador", "generador")
workflow.add_edge("generador", END)

# 4. Compilamos la aplicación LangGraph
app_kromos = workflow.compile()

# ==========================================
# ADAPTADOR PARA NUESTRA API Y FRONTEND
# ==========================================
def simular_respuesta_avatar(user_id, username, pregunta, historial_reciente=[]):
    """
    Esta función actúa como puente para no romper app.py ni whatsapp_agent.py.
    Convierte tu historial antiguo al formato de LangChain y ejecuta el Grafo.
    """
    # 1. Formatear historial previo a objetos de LangChain
    langchain_messages = []
    for msg in historial_reciente:
        if msg["role"] == "user":
            langchain_messages.append(HumanMessage(content=msg["content"]))
        else:
            # Los mensajes del bot los tratamos como AI, aquí los simulo en el estado inicial
            langchain_messages.append(SystemMessage(content=f"Kromos dijo: {msg['content']}"))
    
    # 2. Añadir la pregunta actual
    langchain_messages.append(HumanMessage(content=pregunta))
    
    # 3. Estado inicial para el grafo
    estado_inicial = {
        "messages": langchain_messages,
        "user_id": user_id,
        "username": username,
        "contexto_recuperado": ""
    }
    
    # 4. Invocamos el grafo
    resultado = app_kromos.invoke(estado_inicial)
    
    # 5. Extraemos la respuesta final generada y el contexto usado (para debug)
    respuesta_final = resultado["messages"][-1].content
    recuerdos_usados = resultado["contexto_recuperado"].split('\n') if resultado["contexto_recuperado"] else []
    
    return respuesta_final, recuerdos_usados