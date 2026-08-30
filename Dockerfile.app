# AICyberAuditBox application image.
#
# Kept as a separate file (Dockerfile.app) from the existing Dockerfile at the
# repo root, which only builds the ShaktiDB Postgres image -- that one is
# untouched. This one packages the FastAPI app + static frontend + the LLM
# model weights, so `docker-compose up` is genuinely one command with nothing
# to install separately: pip dependencies are installed at build time here,
# and the model file is baked directly into the image (already present
# locally in this repo, no download step needed).
#
# Deliberately does NOT touch src/ -- this only packages the existing,
# unmodified application code.

FROM python:3.11-slim AS builder

# System build dependencies for packages with native extensions
# (psycopg2-binary ships wheels so no libpq-dev needed; easyocr/opencv and
# sentence-transformers pull in a fair amount at pip-install time).
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY requirements.txt .

# CPU-only torch installed FIRST, deliberately, before requirements.txt.
# sentence-transformers depends on torch but doesn't pin a CPU/GPU variant,
# so a plain `pip install -r requirements.txt` resolves the default (CUDA)
# build and pulls several GB of unused NVIDIA libraries -- this app never
# runs torch on a GPU (llama-server handles all LLM compute separately over
# HTTP). Installing the CPU wheel first satisfies that dependency before pip
# ever considers the CUDA variant.
RUN pip install --no-cache-dir --user torch torchvision --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir --user -r requirements.txt psycopg2-binary



FROM python:3.11-slim AS runtime

# Runtime system libraries needed by easyocr's OpenCV dependency and by
# libraries that render/parse office documents and images.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user -- standard container hardening, no reason to run as root here.
RUN useradd --create-home --uid 1000 appuser

COPY --from=builder /root/.local /home/appuser/.local
ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Application source -- unmodified, copied as-is.
COPY src/ /app/src/
# config/retrieval_config.json (TOP_K tuning per file type) was missing from
# this image entirely -- load_top_k_config() (src/core/retrieval.py) found no
# file at that path inside the container, silently created a fresh one using
# the plain code defaults (12 for every file type), and the repo actual
# tuned values (e.g. 40 for pdf/docx, 45 for xlsx/csv) never reached the
# running app. Confirmed via container logs showing the CONFIG line loading
# 12 for every type instead of the real config files values.
COPY config/ /app/config/
# ISO DOCX export's branded template (report_exporter.py::_export_iso_template_docx)
# looks for this at VAPT/Sample report.docx or Sample report.docx relative to the
# app's own directory -- neither was ever copied into this image, so
# template_path always stayed None inside the container and every ISO export
# silently fell back to the plainer programmatic DOCX generator instead of the
# real template. Only the root-level copy is added here (not the VAPT/ one --
# .dockerignore excludes the whole VAPT/ directory from the build context
# entirely, and Docker cannot reliably re-include a single file from an
# already-excluded directory); the file is byte-identical either way and the
# code's own fallback loop already tries this path second.
COPY ["Sample report.docx", "/app/Sample report.docx"]
COPY docker/wait_for_postgres.py /app/docker/wait_for_postgres.py
COPY docker/generate_secrets.sh /app/docker/generate_secrets.sh
RUN chmod +x /app/docker/generate_secrets.sh

# Persisted, volume-backed data (generated secrets, SQLite fallback file if
# ever used, etc.) -- survives container restarts/recreates.
RUN mkdir -p /app/data

# Note: model weights are NOT copied here -- they live in the separate LLM
# container (Dockerfile.llm), which the app talks to over HTTP via
# LLM_HOSTS/EMBEDDING_HOST, exactly like it already talks to llama-server.exe
# natively today.

# Bake doctr OCR and SentenceTransformer Reranker model caches directly into the image
# so they are baked into the container for 100% offline air-gapped operation without build-time internet dependency.
COPY --chown=appuser:appuser docker/cache/doctr /home/appuser/.cache/doctr
COPY --chown=appuser:appuser docker/cache/huggingface /home/appuser/.cache/huggingface

RUN chown -R appuser:appuser /app /home/appuser/.cache
USER appuser

# Hard offline guarantee at container runtime: the models above are already
# cached in this image layer, so transformers/sentence-transformers/huggingface-hub/doctr
# operate strictly offline with zero external network attempts.
ENV HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 DOCTR_CACHE_DIR=/home/appuser/.cache/doctr

# Verify model loading in pure offline mode during build
RUN python -c "from doctr.models import ocr_predictor; ocr_predictor(pretrained=True); from sentence_transformers import CrossEncoder; CrossEncoder('cross-encoder/ms-marco-MiniLM-L-6-v2'); CrossEncoder('BAAI/bge-reranker-base')"

EXPOSE 8000

# 1. Generate/reuse a persisted JWT_SECRET (docker/generate_secrets.sh).
# 2. Pre-flight blocks startup until Postgres is confirmed reachable (see
#    docker/wait_for_postgres.py for why this exists instead of relying on
#    database.py's own fallback behavior).
# 3. Start the API.
# The .generated_env source is GUARDED, not unconditional.
#
# generate_secrets.sh writes that file only when it had to generate a secret. If
# the operator set JWT_SECRET in the compose environment -- which
# docker-compose.customer.yml explicitly offers ("Uncomment to pin one yourself
# instead") -- the script correctly treats the explicit value as authoritative and
# exits without writing anything. The unguarded `. /app/data/.generated_env` that
# followed then failed with "sh: 1: .: cannot open /app/data/.generated_env", the
# && chain broke, and the container exited before uvicorn ever started.
#
# So following the documented instruction to pin your own secret produced a
# container that would not boot. Verified by execution: identical image, boots
# without JWT_SECRET, dies instantly with it.
#
# `|| true` keeps the chain alive when the file is absent; JWT_SECRET is already
# in the environment in that case, so the export below still does its job. The
# operator's own secret is deliberately NOT written to the volume.
CMD ["sh", "-c", "\
    ./docker/generate_secrets.sh && \
    { [ -f /app/data/.generated_env ] && . /app/data/.generated_env || true; } && \
    export JWT_SECRET && \
    python docker/wait_for_postgres.py && \
    python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 \
"]
