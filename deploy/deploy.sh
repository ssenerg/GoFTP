#!/bin/sh
# Deploys goftp on this server: pulls IMAGE@DIGEST and restarts goftp with
# it. This script's directory holds docker-compose.yml and .env. If goftp
# does not keep running, the image that ran before comes back and the
# script fails.
#
#   deploy.sh IMAGE [DIGEST]   e.g. deploy.sh ghcr.io/OWNER/goftp sha256:...
#
# CI runs it over SSH with a key that may run nothing else, with IMAGE set
# in authorized_keys and DIGEST sent by CI (see the README):
#
#   restrict,command="/opt/goftp/deploy.sh ghcr.io/OWNER/goftp" ssh-ed25519 ...
#
# What it prints may end up in public CI logs, so goftp's own logs, which
# name clients and users, go to the journal: journalctl -t goftp-deploy
set -eu
cd "$(dirname "$0")"

fail() {
	echo "deploy: $*" >&2
	exit 1
}

image=${1:-}
digest=${2:-${SSH_ORIGINAL_COMMAND:-}}
[ -n "$image" ] || fail "usage: deploy.sh IMAGE [DIGEST]"
# The caller chooses the digest of an image in IMAGE, and nothing else.
hex=${digest#sha256:}
case $hex in
*[!0-9a-f]*) hex= ;;
esac
if [ "$digest" != "sha256:$hex" ] || [ ${#hex} -ne 64 ]; then
	fail "the digest must be sha256: and 64 lowercase hexadecimal digits"
fi
[ -f .env ] || fail "there is no .env in $PWD: copy .env.example there and set POSTGRES_PASSWORD"

compose() { docker compose --file docker-compose.yml "$@"; }

docker pull --quiet "$image@$digest" >/dev/null
# The running image stays at hand as goftp:previous.
if docker image inspect goftp:latest >/dev/null 2>&1; then
	docker image tag goftp:latest goftp:previous
fi
docker image tag "$image@$digest" goftp:latest
docker image rm "$image@$digest" >/dev/null 2>&1 || true

# started reports whether goftp started and kept running for a while: its
# image has no shell for a health check.
started() {
	compose up --detach --no-build --wait --wait-timeout 120 postgres || return 1
	compose up --detach --no-build --force-recreate goftp || return 1
	sleep 15
	id=$(compose ps --quiet goftp) || return 1
	[ -n "$id" ] && [ "$(docker inspect --format '{{.State.Running}} {{.RestartCount}}' "$id")" = "true 0" ]
}

if started; then
	# Images replaced by earlier deploys are not needed any more.
	docker image prune --force --filter label=org.opencontainers.image.title=goftp >/dev/null
	echo "deploy: goftp $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' goftp:latest) is running"
	exit 0
fi

compose logs --no-color --tail 100 goftp 2>&1 | logger --tag goftp-deploy || true
if docker image inspect goftp:previous >/dev/null 2>&1; then
	docker image tag goftp:previous goftp:latest
	compose up --detach --no-build --force-recreate goftp >/dev/null 2>&1 || true
fi
fail "goftp did not keep running, so the image that ran before is back. Its logs are on the server: journalctl -t goftp-deploy"
