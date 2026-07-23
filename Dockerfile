# Coalition 509 API — Dockerfile
# Force Python 3.12 pour éviter les problèmes de compilation

FROM python:3.12-slim

WORKDIR /app

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copier les fichiers
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY coalition509_api.py .

# Exposer le port
EXPOSE 8000

# Démarrer l'application
CMD ["uvicorn", "coalition509_api:app", "--host", "0.0.0.0", "--port", "8000"]
