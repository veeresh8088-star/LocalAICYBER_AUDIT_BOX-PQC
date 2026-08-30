#!/bin/sh
# Applies an AICyberAuditBox code patch to an existing install.
#
# Rebuilds the app image on top of the one already installed, so the Python
# packages and the ~1.6GB of OCR model caches are reused untouched -- nothing is
# downloaded and the install stays air-gapped. Takes seconds.
set -e

FROM_VERSION="__FROM__"
TO_VERSION="__TO__"
COMPOSE="docker-compose.yml"

echo "==========================================================="
echo "  AICyberAuditBox patch  ${FROM_VERSION} -> ${TO_VERSION}"
echo "==========================================================="

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker is not running."
  exit 1
fi
if ! docker image inspect "aicyberauditbox-app:${FROM_VERSION}" >/dev/null 2>&1; then
  echo "ERROR: aicyberauditbox-app:${FROM_VERSION} is not installed on this machine."
  echo "       This patch builds on top of it. Installed app images:"
  docker images aicyberauditbox-app --format "         {{.Repository}}:{{.Tag}}"
  exit 1
fi
if [ ! -f "$COMPOSE" ]; then
  echo "ERROR: $COMPOSE not found. Run this from your install folder"
  echo "       (the one you extracted the original bundle into)."
  exit 1
fi

echo ""
echo "--> Building aicyberauditbox-app:${TO_VERSION} from ${FROM_VERSION}"
docker build -f Dockerfile.app.rebase \
  --build-arg "APP_BASE_IMAGE=aicyberauditbox-app:${FROM_VERSION}" \
  -t "aicyberauditbox-app:${TO_VERSION}" .

echo ""
echo "--> Pointing $COMPOSE at the new image"
cp "$COMPOSE" "${COMPOSE}.bak"
sed -i "s|aicyberauditbox-app:${FROM_VERSION}|aicyberauditbox-app:${TO_VERSION}|g" "$COMPOSE"
if ! grep -q "aicyberauditbox-app:${TO_VERSION}" "$COMPOSE"; then
  echo "ERROR: could not update the image tag. Restoring ${COMPOSE}."
  mv "${COMPOSE}.bak" "$COMPOSE"
  exit 1
fi
echo "    previous file kept as ${COMPOSE}.bak"

echo ""
echo "--> Restarting the application (database and LLM keep running)"
docker compose up -d app

echo ""
echo "--> Waiting for it to answer"
i=0
while [ $i -lt 60 ]; do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/ 2>/dev/null || echo 000)
  if [ "$code" = "200" ]; then
    echo ""
    echo "==========================================================="
    echo "  Patched to ${TO_VERSION}.  http://localhost:8000/"
    echo "==========================================================="
    exit 0
  fi
  i=$((i + 1))
  sleep 3
done

echo "The app did not answer. Roll back with:"
echo "  mv ${COMPOSE}.bak $COMPOSE && docker compose up -d app"
exit 1
