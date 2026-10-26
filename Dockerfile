# keymember server with the web app, for both deployments:
# - Cloud Run with Firestore (KEYMEMBER_STORE=firestore)
# - a company's own machine with PGlite in /data (the default), see deploy/compose.yaml

FROM node:24.22.0-bookworm-slim AS build
WORKDIR /src
RUN corepack enable && corepack prepare pnpm@10.34.7 --activate

# Dependencies first, keyed on the lockfile only, so a source change does not download them again
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
# The image already has the Node version the workspace pins; stop pnpm downloading another
RUN sed -i '/^useNodeVersion:/d' pnpm-workspace.yaml && pnpm fetch

COPY . .
RUN sed -i '/^useNodeVersion:/d' pnpm-workspace.yaml \
 && pnpm install --offline --frozen-lockfile --filter "@keymember/server..." --filter "@keymember/web..."
RUN pnpm exec tsc -b packages/core packages/client apps/server \
 && pnpm --filter @keymember/web build \
 && pnpm --filter @keymember/server deploy --prod --legacy /out \
 && cp -r apps/web/dist /out/web

FROM node:24.22.0-bookworm-slim
WORKDIR /app
COPY --from=build /out .
RUN mkdir /data && chown node:node /data
USER node
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080 \
    KEYMEMBER_WEB_DIR=/app/web \
    KEYMEMBER_PGLITE_DIR=/data
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:' + process.env.PORT + '/api/health').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "dist/main.js"]
