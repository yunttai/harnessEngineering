#!/usr/bin/env bash
set -euo pipefail
curl --get --data-urlencode "name=' OR 1=1--" http://127.0.0.1:5000/api/users
echo
echo "Attack submitted. Event history:"
sleep 1
curl --fail --silent http://127.0.0.1:8080/api/events
echo
