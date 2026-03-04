# whatsapp_agent.py
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import PlainTextResponse
from twilio.twiml.messaging_response import MessagingResponse
from core_ai import simular_respuesta_avatar
import sqlite3

app = FastAPI(title="Kromos WhatsApp Agent")

# Conexión de solo lectura a SQLite para validar al usuario
def get_user_data(phone_number):
    # Para un MVP, podemos asumir un ID de usuario fijo (ej. ID=1) 
    # o mapear números de teléfono en tu BD. 
    # Asumamos que Kromos responde por el usuario 1:
    conn = sqlite3.connect('temporal_eco.db')
    c = conn.cursor()
    c.execute("SELECT id, username, avatar_created FROM users WHERE id=1")
    user = c.fetchone()
    conn.close()
    return user

@app.post("/webhook/whatsapp")
async def whatsapp_webhook(
    From: str = Form(...), 
    Body: str = Form(...)
):
    """
    Endpoint que Twilio llama cuando llega un mensaje de WhatsApp.
    From: Número del remitente (ej. 'whatsapp:+34600123456')
    Body: El texto del mensaje recibido
    """
    
    # 1. Identificar al usuario dueño del avatar
    user_data = get_user_data(phone_number=From)
    
    if not user_data:
        return handle_error_response("Usuario no encontrado en el sistema.")
        
    user_id, username, avatar_created = user_data
    
    if not avatar_created:
        return handle_error_response(f"Hola, el avatar de {username} aún no está sincronizado al 100%.")

    # 2. Invocamos al Agente (Kromos)
    # Extraemos el mensaje del usuario
    mensaje_entrante = Body.strip()
    
    try:
        # Aquí pasamos una ventana de historial vacía por ahora para mantener el MVP simple.
        # En el futuro, podríamos usar Redis o SQLite para guardar el contexto de esta charla.
        respuesta_ia, _ = simular_respuesta_avatar(
            user_id=user_id,
            username=username,
            pregunta=mensaje_entrante,
            historial_reciente=[] 
        )
    except Exception as e:
        print(f"Error en IA: {e}")
        return handle_error_response("Mi red neuronal está temporalmente desconectada.")

    # 3. Formatear la respuesta para Twilio (XML TwiML)
    twiml = MessagingResponse()
    msg = twiml.message()
    msg.body(respuesta_ia)
    
    # Twilio espera una respuesta XML con formato TwiML
    return PlainTextResponse(str(twiml), media_type="application/xml")

def handle_error_response(error_message):
    twiml = MessagingResponse()
    msg = twiml.message()
    msg.body(error_message)
    return PlainTextResponse(str(twiml), media_type="application/xml")

# Para ejecutar: uvicorn whatsapp_agent:app --reload --port 8000