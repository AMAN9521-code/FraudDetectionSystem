#!/bin/sh

set -e

PORT="${PORT:-8080}"

sed -i "s/port=\"8080\"/port=\"${PORT}\"/" \
    "$CATALINA_HOME/conf/server.xml"

exec catalina.sh run