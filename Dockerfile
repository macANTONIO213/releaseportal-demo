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

FROM python:3.12-alpine3.23@sha256:9ce5a4e59b833c002e1c4196c60ec0b38977e3235d626298ba7ffe2e64f5a30c
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORTAL_MODE=pilot PORTAL_RUNTIME_DIR=/var/lib/releaseportal PORTAL_BIND_HOST=0.0.0.0
WORKDIR /app
COPY backend/requirements.lock.txt ./backend/requirements.lock.txt
RUN sed -i 's|http://|https://|g' /etc/apk/repositories \
    && apk upgrade --no-cache \
    && apk add --no-cache 'zlib>=1.3.2-r1' 'musl>=1.2.5-r23' libgcc \
    && pip install --no-cache-dir --only-binary=:all: -r backend/requirements.lock.txt \
    && addgroup -g 10001 portal && adduser -D -u 10001 -G portal portal \
    && mkdir /var/lib/releaseportal && chown portal:portal /var/lib/releaseportal
COPY backend ./backend
COPY scripts/serve.py ./scripts/serve.py
COPY deploy ./deploy
COPY --from=ui /app/dist ./dist
USER portal
EXPOSE 8055
CMD ["python", "scripts/serve.py"]
