FROM python:3.10-slim

LABEL authors="Marco Graciano"

# Expone el puerto que usará Flask
EXPOSE 5000

# Evita problemas con stdout buffering
ENV PYTHONUNBUFFERED=1

# Crea y usa un directorio de trabajo
WORKDIR /app

# Instala dependencias del sistema necesarias para muchas libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    libjpeg-dev \
    zlib1g-dev \
    libmagic1 \
    file \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copia el archivo de requirements
COPY requirements.txt .

# Instala dependencias de Python
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Copia el resto de los archivos del proyecto
COPY . .

# Comando por defecto para iniciar Flask
CMD ["flask", "run", "--host", "0.0.0.0"]
