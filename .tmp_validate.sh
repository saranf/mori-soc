#!/usr/bin/env bash
set -e
python3 -c "import ast; ast.parse(open('src/mori_soc/api/server.py').read()); print('AST_OK')"
echo "--- copying to container ---"
docker compose cp src/mori_soc/api/server.py mori-api:/app/src/mori_soc/api/server.py
echo "--- restart ---"
docker compose restart mori-api >/dev/null 2>&1
sleep 5
echo "--- running unit tests ---"
docker compose exec -T mori-api python -m unittest tests.test_api_server 2>&1 | tail -10
