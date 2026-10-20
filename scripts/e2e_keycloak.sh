#!/usr/bin/env bash
# End-to-end over HTTP: Keycloak login -> RFC 8693 exchange at the gateway -> tool calls.
set -euo pipefail
KC=http://localhost:8080/realms/acme/protocol/openid-connect/token
GW=http://localhost:8000
tok() { curl -s "$KC" -d "$@" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])'; }
USER=$(tok grant_type=password -d client_id=warden-gateway -d client_secret=gateway-dev-secret -d username=${1:-carol} -d password=${1:-carol}-dev-pass)
AGENT=$(tok grant_type=client_credentials -d client_id=hr-assistant -d client_secret=hr-dev-secret)
echo "agent credential used directly:"
curl -s -X POST $GW/v1/tools/hr:read_record -H "Authorization: Bearer $AGENT" -H 'content-type: application/json' -d '{"args":{"user":"dave"}}'; echo
DELEG=$(curl -s $GW/sts/exchange -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange -d subject_token=$USER -d actor_token=$AGENT -d scope=hr:read_record | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
echo "delegated token, hr:read_record dave:"
curl -s -X POST $GW/v1/tools/hr:read_record -H "Authorization: Bearer $DELEG" -H 'content-type: application/json' -d '{"args":{"user":"dave"}}'; echo
echo "delegated token, finance report (outside agent scope):"
curl -s -X POST $GW/v1/tools/finance:read_report -H "Authorization: Bearer $DELEG" -H 'content-type: application/json' -d '{"args":{"id":"q3-revenue"}}'; echo
