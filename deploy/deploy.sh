#!/bin/sh
# Deploys goftp on this server: loads the image piped in (the output of
# `docker save`, gzipped or not) and restarts goftp with it. This script's
# directory holds docker-compose.yml and .env. If goftp does not stay up,
# the image that ran before comes back and the script fails.
#
#   docker save goftp | gzip | ssh deploy@server sh /opt/goftp/deploy.sh
#
# The CI workflow runs it for every push to main (see the README).
set -eu
cd "$(dirname "$0")"

compose() { docker compose --file docker-compose.yml "$@"; }

if [ ! -f .env ]; then
	echo "deploy: there is no .env in $PWD: copy .env.example there and set POSTGRES_PASSWORD" >&2
	exit 1
fi

# The running image stays at hand as goftp:previous.
if docker image inspect goftp:latest >/dev/null 2>&1; then
	docker image tag goftp:latest goftp:previous
fi
docker load

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

echo "deploy: goftp did not keep running. Its last logs:" >&2
compose logs --no-color --tail 100 goftp >&2 || true
if docker image inspect goftp:previous >/dev/null 2>&1; then
	docker image tag goftp:previous goftp:latest
	if compose up --detach --no-build --force-recreate goftp; then
		echo "deploy: went back to the image that ran before" >&2
	fi
fi
exit 1
