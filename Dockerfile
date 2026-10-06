FROM node:22-alpine AS frontend-build

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html tsconfig*.json vite.config.ts ./
COPY src ./src
RUN npm run build

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    CYBERGUARD_COOKIE_SECURE=true \
    CYBERGUARD_DB_PATH=/home/cyberguard.sqlite3

WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN python -m pip install --no-cache-dir --requirement backend/requirements.txt
COPY backend/app backend/app
COPY backend/models/phiusiil_url_model.json backend/models/phiusiil_url_model.json
COPY --from=frontend-build /build/dist dist

EXPOSE 8000
CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port \"${PORT:-8000}\" --workers 1"]
