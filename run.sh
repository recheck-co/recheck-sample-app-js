#!/usr/bin/env bash

PORT=3001

echo "Running Recheck OAuth Test Client on http://localhost:$PORT/"

python3 -m http.server $PORT
