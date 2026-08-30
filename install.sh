#!/bin/sh
# Offline installer -- AICyberAuditBox.
#
# Loads every image from the single images tar beside this script, then starts
# the stack. Nothing is downloaded: the machine never needs to reach a registry,
# which is the point of an air-gapped install.
set -e

VERSION="3.22"
IMAGES="aicyberauditbox-images-${VERSION}.tar"
COMPOSE="docker-compose.yml"

echo "==========================================================="
echo "  AICyberAuditBox ${VERSION} -- offline install"
echo "==========================================================="

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker is not running. Start Docker Desktop (or dockerd) first."
  exit 1
fi
if [ ! -f "$IMAGES" ]; then
  echo "ERROR: $IMAGES is not in this folder. Run the installer from the"
  echo "       folder the bundle extracted into."
  exit 1
fi

echo ""
echo "--> Loading all images from $IMAGES"
echo "    (~8GB; several minutes, and it prints nothing while it works)"
docker load -i "$IMAGES"

echo ""
echo "--> Verifying every image the stack needs is present"
MISSING=0
for i in aicyberauditbox-app:${VERSION} \
         aicyberauditbox-llm:${VERSION} \
         aicyberauditbox-llm-embed:${VERSION} \
         aicyberauditbox-shakthidb:3.10 \
         redis:7-alpine; do
  if docker image inspect "$i" >/dev/null 2>&1; then
    echo "    ok   $i"
  else
    echo "    MISSING  $i"
    MISSING=1
  fi
done
[ "$MISSING" = "0" ] || { echo "Aborting: the images above did not load."; exit 1; }

echo ""
echo "--> Starting the stack"
docker compose -f "$COMPOSE" up -d

echo ""
echo "--> Waiting for the application to answer (up to 5 minutes)"
i=0
while [ $i -lt 100 ]; do
  # -f makes curl exit non-zero on any HTTP error, so a zero exit IS the
  # readiness signal. Parsing %{http_code} was fragile: when curl failed for an
  # unrelated reason it had already printed a partial code, and the "|| echo 000"
  # fallback appended to it -- yielding a value that could never match, so a
  # perfectly working app reported as a failed install.
  if curl -fs --max-time 5 http://localhost:8000/ >/dev/null 2>&1; then
    echo ""
    echo "==========================================================="
    echo "  Ready.  Open http://localhost:8000/"
    echo "==========================================================="
    echo ""
    echo "Confirm the LLM sized itself correctly for this machine:"
    echo "  docker compose -f $COMPOSE logs llm | grep 'LLM ENTRYPOINT'"
    echo ""
    echo "The last line must read '= 32768 tokens per request'. A lower number"
    echo "means the machine has less RAM than the LLM expected, and evidence"
    echo "would be truncated before the model sees it -- see INSTALL_v${VERSION}.md."
    exit 0
  fi
  i=$((i + 1))
  sleep 3
done

echo "The app did not answer in time. Check:"
echo "  docker compose -f $COMPOSE ps"
echo "  docker compose -f $COMPOSE logs app | tail -40"
exit 1
