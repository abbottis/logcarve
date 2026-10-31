# T10 multistage image: pinned Node asset builder, non-root Python runtime.
# Node 22.23.4 matches the project's tested local toolchain; Python 3.12.16
# matches .python-version. Coordinator verifies tag availability on first
# build and records the build architecture (linux/aarch64 initial demo;
# linux/amd64 remains a separate gate). No moving tags by policy.
# Build from a fresh tracked export: `git archive HEAD | docker build -f- ...`
# is NOT supported (single-file stdin); instead extract the archive to a
# temporary directory and build there (see scripts/smoke_demo.sh), so host
# node_modules, static caches, .uv-python, secrets, DBs and artifacts/ can
# never leak into the context. .dockerignore enforces the same exclusions.

# ---- asset builder (Node is build-only, never ships to runtime) ----
FROM node:22.23.4-bookworm-slim AS assets

WORKDIR /build

# Pinned npm dependencies first for a stable layer.
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# Authored sources + vendor build scripts. Authored templates arrive BEFORE
# the build because Tailwind scans them for utility classes; a stage that
# omits them would silently drop template-driven styles from app.css.
COPY assets/ ./assets/
COPY app/web/templates/ ./app/web/templates/
COPY scripts/build_vendor.mjs scripts/check_no_external.mjs ./scripts/

RUN npm run build && npm run check:external

# ---- Python runtime ----
FROM python:3.12.16-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 logcarve \
    && mkdir -p /data && chown 10001:10001 /data

WORKDIR /srv/logcarve

# Generated from uv.lock with
# `uv export --frozen --no-dev --no-hashes --no-editable --no-emit-project`;
# do not hand-edit, regenerate instead. It carries pinned third-party
# wheels only: project source arrives via the COPY steps below, so the
# install order is dependency-first by construction.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Retain project and bundled-component license texts in distributed images.
COPY LICENSE THIRD_PARTY_NOTICES.md ./

# Authored application first ...
COPY app/ ./app/
COPY config/ ./config/

# ... then builder-regenerated browser assets AND generated template icons
# over the authored tree, so tracked and fresh-clone builds converge.
COPY --from=assets /build/app/web/static/ ./app/web/static/
COPY --from=assets /build/app/web/templates/icons/ ./app/web/templates/icons/

# Tracked license/provenance notices ship inside the static tree they
# describe (see .gitignore exceptions); fail the build if any is missing.
RUN test -f ./app/web/static/vendor/PROVENANCE.md \
    && test -f ./app/web/static/icons/LUCIDE-ISC.txt \
    && test -f ./app/web/static/fonts/INTER-OFL.txt \
    && test -f ./app/web/static/fonts/JETBRAINS-MONO-OFL.txt \
    && test -f ./app/web/static/vendor/js/htmx.min.js \
    && test -f ./app/web/static/vendor/js/chart.umd.min.js \
    && test -f ./app/web/static/app.css

USER 10001
VOLUME /data
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz')"

# Listen on all interfaces inside the container; external reachability is
# decided by the Compose port mapping (loopback-only by default).
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
