#!/bin/bash

docker compose up hydra -d
sleep 10

code_client=$(docker compose exec hydra \
    hydra create client \
    --endpoint http://127.0.0.1:4445 \
    --grant-type authorization_code,refresh_token \
    --response-type code,id_token \
    --format json \
    --scope openid --scope offline \
    --redirect-uri http://127.0.0.1:5555/callback)

code_client_id=$(echo $code_client | jq -r '.client_id')
code_client_secret=$(echo $code_client | jq -r '.client_secret')
# yq -i e ".selfservice.methods.oidc.config.providers.0.client_id |= \"$code_client_id\"" ./kratos/kratos.yml
# yq -i e ".selfservice.methods.oidc.config.providers.0.client_secret |= \"$code_client_secret\"" ./kratos/kratos.yml

docker compose up -d

docker compose exec hydra \
    hydra perform authorization-code \
    --client-id $code_client_id \
    --client-secret $code_client_secret \
    --endpoint http://127.0.0.1:4444 \
    --port 5555 \
    --scope openid --scope offline