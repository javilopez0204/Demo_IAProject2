# core_ai.py
import os
import json
import logging
import google.generativeai as genai
import chromadb
from dotenv import load_dotenv

# Cargar variables de entorno (API KEY)
load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

model = genai.GenerativeModel('gemini-2.5-flash')

# Conexión a ChromaDB
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_or_create_collection(name="user_memories")

# ==========================================
# PROMPTS
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

PROMPT_SIMULADOR = """
Eres 'Kromos', el clon digital y avatar personal del usuario {nombre_usuario}.
Tu objetivo es interactuar con el usuario respondiendo a sus preguntas como si fueras su "yo del pasado" o su reflejo digital.
Habla siempre en primera persona ("yo", "mi", "nosotros"). Tienes un tono conversacional, empático y reflexivo.

REGLA DE ORO DE ARQUITECTURA COGNITIVA: 
1. Responde basándote EXCLUSIVAMENTE en los "Recuerdos Recuperados" (memoria a largo plazo) y en el "Historial de la Conversación" (memoria a corto plazo).
2. Si la respuesta requiere información que no está en tu memoria, admite tu limitación (ej. "Aún no tengo recuerdos claros sobre eso, cuéntame más").
3. ¡NO INVENTES VIVENCIAS, NOMBRES NI EMOCIONES!

HISTORIAL DE LA CONVERSACIÓN RECIENTE (Memoria a corto plazo):
{historial_conversacion}

RECUERDOS RECUPERADOS (Memoria a largo plazo):
{contexto}

PREGUNTA ACTUAL DEL USUARIO:
{pregunta}
"""

# ==========================================
# FUNCIONES CORE
# ==========================================
def estructurar_memoria(texto):
    response = model.generate_content(PROMPT_ESTRUCTURADOR + texto)
    try:
        clean_json = response.text.replace('```json', '').replace('```', '').strip()
        return json.loads(clean_json)
    except Exception as e:
        logging.error(f"Error parseando JSON del LLM: {e}")
        return {}

def recuperar_memorias(user_id, pregunta, top_k=5):
    try:
        resultados = collection.query(
            query_texts=[pregunta],
            n_results=top_k,
            where={"user_id": user_id} 
        )
        if resultados and 'documents' in resultados and len(resultados['documents'][0]) > 0:
            return resultados['documents'][0]
        return []
    except Exception as e:
        logging.error(f"Error en la base de datos vectorial: {e}")
        return []

def simular_respuesta_avatar(user_id, username, pregunta, historial_reciente=[]):
    memorias = recuperar_memorias(user_id, pregunta)
    
    if not memorias:
        contexto = "[No se recuperaron recuerdos relevantes.]"
    else:
        contexto = "\n".join([f"- {mem}" for mem in memorias])
        
    historial_str = ""
    if historial_reciente:
        for msg in historial_reciente:
            rol = "Usuario" if msg["role"] == "user" else "Kromos"
            historial_str += f"{rol}: {msg['content']}\n"
    else:
        historial_str = "[Inicio de la conversación]"
        
    prompt_final = PROMPT_SIMULADOR.format(
        nombre_usuario=username, 
        historial_conversacion=historial_str,
        contexto=contexto, 
        pregunta=pregunta
    )
    
    response = model.generate_content(prompt_final)
    return response.text, memorias