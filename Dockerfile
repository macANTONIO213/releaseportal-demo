FROM node:22-bookworm-slim@sha256:efd0ab5780c2d9ab1f0f869571a00d5edb17793bff4cce4a2792e3eb0ffc7562 AS ui
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN corepack prepare pnpm@11.25.0 --activate && pnpm install --frozen-lockfile
COPY src ./src
COPY index.html vite.config.mjs ./
COPY scripts/prepare-sites-build.mjs ./scripts/prepare-sites-build.mjs
COPY worker ./worker
COPY .openai ./.openai
RUN pnpm run build

FROM python:3.12-slim@sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORTAL_MODE=pilot PORTAL_RUNTIME_DIR=/var/lib/releaseportal PORTAL_BIND_HOST=0.0.0.0
WORKDIR /app
COPY backend/requirements.lock.txt ./backend/requirements.lock.txt
RUN pip install --no-cache-dir -r backend/requirements.lock.txt && useradd --uid 10001 --create-home portal && mkdir /var/lib/releaseportal && chown portal:portal /var/lib/releaseportal
COPY backend ./backend
COPY scripts/serve.py ./scripts/serve.py
COPY deploy ./deploy
COPY --from=ui /app/dist ./dist
USER portal
EXPOSE 8055
CMD ["python", "scripts/serve.py"]
