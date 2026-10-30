# NoteVault image. Part of the project is to harden this Dockerfile
# (base pinning, non-root user, no baked secrets, minimal layers).
FROM python:3.12

# APP_SECRET is NOT baked into the image — it is injected at runtime
# (docker compose / orchestrator secret). See docker-compose.yml.

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

EXPOSE 8080
CMD ["python", "app.py"]
