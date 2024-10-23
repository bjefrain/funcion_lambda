# Usar una imagen base de Python 3.9-slim
FROM python:3.9-slim

# Establecer el directorio de trabajo
WORKDIR /app

# Copiar el archivo requirements.txt y instalar las dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el código de la función Lambda al directorio de trabajo
COPY . .

# Comando para ejecutar la función Lambda
ENTRYPOINT ["python3", "-m", "awslambdaric"]
CMD ["lambda_function.lambda_handler"]