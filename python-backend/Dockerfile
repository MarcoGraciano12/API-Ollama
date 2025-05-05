FROM python:3.13-slim

LABEL authors="Marco Graciano"

EXPOSE 5000

# Evita problemas con stdout buffering
ENV PYTHONUNBUFFERED=1

# Crea y usa un directorio de trabajo
WORKDIR /app

# Copia los archivos
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade -r requirements.txt

COPY . .

# Cambia esto si tu script principal no es app.py
CMD ["flask", "run", "--host", "0.0.0.0"]
