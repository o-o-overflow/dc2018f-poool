#!/bin/bash

set -e
set -x

# quick a dirty extract of the name from the info.yml
SERVICE_NAME=$(cat info.yml | grep "^service_name:" | cut -f 2 -d '"')

SERVICE_TAG="$SERVICE_NAME-service"
INTERACTION_TAG="$SERVICE_NAME-interaction"

cd service && docker build . -t "$SERVICE_TAG"  && cd -

cd interaction && docker build . -t "$INTERACTION_TAG" && cd -

SERVICE_ID=$(docker run -d --rm "$SERVICE_TAG")

# TODO: EXPLOIT_SCRIPTS=$(get_info.py exploit_scripts)
EXPLOIT_SCRIPTS="/exploit1.py /exploit3.py"


# TODO: SLA_SCRIPTS=$(get_info.py sla_scripts)
SLA_SCRIPTS="/sla1.py"


# TODO: SERVICE_PORT=$(get_info.py service_port)
SERVICE_PORT=10001

# TODO: Set new flag before testing

IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SERVICE_ID")


for script in $SLA_SCRIPTS
do
    docker run --rm "$INTERACTION_TAG" "$script" "$IP" "$SERVICE_PORT"
done

for script in $EXPLOIT_SCRIPTS
do
    RESULT=$(docker run --rm "$INTERACTION_TAG" "$script" "$IP" "$SERVICE_PORT")
    echo $RESULT | grep "FLAG:"
done

docker kill "$SERVICE_ID"
