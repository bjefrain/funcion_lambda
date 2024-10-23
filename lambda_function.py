import json
import openai
import chromadb
from chromadb.utils import embedding_functions
import boto3
import time
from botocore.exceptions import ClientError
import re

# Configurar el cliente DynamoDB
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('ChatFeedback')

def lambda_handler(event, context):
    try:
        openai.api_key = "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"

        body = json.loads(event.get('body', '{}'))

        # Verificar si es una solicitud de feedback, reporte, o una consulta de chat
        if 'feedback' in body:
            feedback = body['feedback']
            return save_feedback(feedback)
        
        if 'report' in body:  # Nuevo manejo del reporte
            report = body['report']
            return save_report(report)

        query = body.get("query", "")
        previous_messages = body.get("messages", [])

        contextChat = {
            "role": "system",
            "content": "Actúa como un asistente estudiantil, respondiendo de forma clara, breve y estructurada, solo con información disponible o recuperada. Si no hay datos relevantes o la consulta no es académica, cierra la conversación educadamente. Evita respuestas largas o delimitadores markdown."
        }

        messages = [contextChat] + previous_messages
        results = query_collection(query)

        for document in results['documents'][0]:
            messages.append({"role": "system", "content": document})

        messages.append({"role": "user", "content": query})

        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo", messages=messages)

        response_content = response.choices[0].message.content

        # Aplicar el formateo a la respuesta
        formatted_response = format_response(response_content)

        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json; charset=utf-8'},
            'body': json.dumps(formatted_response, ensure_ascii=False)
        }
    except Exception as e:
        error_message = "Ocurrió un error durante el procesamiento: {}".format(str(e))
        print("Error:", str(e))  # Esto imprime el error en los logs de CloudWatch
        return {
            'statusCode': 500,
            'body': json.dumps({"error": error_message})
        }

# Función para consultar los documentos en ChromaDB
def query_collection(query):
    openai_ef = embedding_functions.OpenAIEmbeddingFunction(
        api_key="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",
        model_name="text-embedding-ada-002",
        dimensions=1536
    )

    chroma_client = chromadb.HttpClient(host="54.176.182.239", port="8000")
    collection = chroma_client.get_collection(name="test_1", embedding_function=openai_ef)

    return collection.query(
        query_texts=[query],
        n_results=10,
    )

# Convertir listas con guiones y números en viñetas, y reemplazar el Markdown por HTML
def format_response(text):
    # Reemplazar **negritas** por <strong>negritas</strong>
    text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
    # Eliminar cualquier cantidad de numerales al principio de una línea
    text = re.sub(r'#+\s*(.*?)\n', r'<strong>\1</strong><br>', text)
    # Reemplazar listas con guiones
    text = text.replace('- ', '<br>• ')
    # Saltos de línea dobles en párrafos
    text = text.replace('\n\n', '</p><p>')
    # Saltos de línea simples en <br>
    text = text.replace('\n', '<br>')
    return f"<p>{text}</p>"

# Función para guardar el feedback en DynamoDB
def save_feedback(feedback):
    try:
        message_id = feedback.get('message_id')
        timestamp = feedback.get('timestamp')  # Obtener el timestamp del registro existente
        feedback_type = feedback.get('feedback_type')
        user_id = feedback.get('user_id', 'anonimo')
        user_message = feedback.get('user_message', '')
        chatbot_response = feedback.get('chatbot_response', '')

        # Validar que el tipo de feedback sea "like" o "dislike"
        if not message_id or not feedback_type:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'El message_id o feedback_type no son válidos.'})
            }

        if feedback_type not in ['like', 'dislike']:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Tipo de feedback no válido. Debe ser "like" o "dislike".'})
            }

        # Actualizar el registro existente y agregar user_message y chatbot_response si no están ya presentes
        table.update_item(
            Key={
                'message_id': message_id,
                'timestamp': timestamp  # Usar la clave compuesta con timestamp
            },
            UpdateExpression="""
                SET feedback_type = :f,
                user_message = if_not_exists(user_message, :um),
                chatbot_response = if_not_exists(chatbot_response, :cr)
            """,
            ExpressionAttributeValues={
                ':f': feedback_type,
                ':um': user_message,
                ':cr': chatbot_response
            },
            ReturnValues="UPDATED_NEW"
        )

        print(f"Feedback actualizado para message_id={message_id} y timestamp={timestamp}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Feedback guardado exitosamente'})
        }

    except ClientError as e:
        print("Error en DynamoDB:", e.response['Error']['Message'])
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Error al guardar el feedback en DynamoDB.'})
        }
    except Exception as e:
        print("Error general:", str(e))
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Error inesperado al guardar el feedback.'})
        }

# Función para guardar el reporte en DynamoDB
def save_report(report):
    try:
        message_id = report.get('message_id')
        timestamp = report.get('timestamp')  # Obtener el timestamp del registro existente
        report_text = report.get('report', '')
        user_message = report.get('user_message', '')  # Asegurarse de que capture el mensaje del usuario
        chatbot_response = report.get('chatbot_response', '')  # Asegurarse de que capture la respuesta del chatbot

        # Validar que el report y message_id existan
        if not message_id or not report_text:
            print(f"Faltan datos para guardar el reporte: message_id={message_id}, report_text={report_text}")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Faltan el message_id o el texto del reporte.'})
            }

        # Actualizar el registro existente con el campo "report"
        table.update_item(
            Key={
                'message_id': message_id, 
                'timestamp': timestamp  # Usar la clave compuesta de message_id y timestamp
            },
            UpdateExpression="""
                SET report = :r,
                user_message = if_not_exists(user_message, :um),
                chatbot_response = if_not_exists(chatbot_response, :cr)
            """,
            ExpressionAttributeValues={
                ':r': report_text,
                ':um': user_message,
                ':cr': chatbot_response
            },
            ReturnValues="UPDATED_NEW"
        )

        print(f"Reporte agregado para message_id={message_id} y timestamp={timestamp}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Reporte guardado exitosamente'})
        }

    except ClientError as e:
        print(f"Error en DynamoDB: {e.response['Error']['Message']}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Error al guardar el reporte en DynamoDB.'})
        }
    except Exception as e:
        print(f"Error general: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': 'Error inesperado al guardar el reporte.'})
        }