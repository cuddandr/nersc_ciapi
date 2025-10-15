#!/bin/bash

webhook_db_id=${1}
runner_dir=$SCRATCH/temp

mkdir -p ${runner_dir}
gh_dir=$(mktemp -d -p ${runner_dir})
cd ${gh_dir}

echo "${webhook_db_id}" > webhook_id.txt
# python3 -m venv env
# source env/bin/activate
# pip install -r requirements

# python3 scripts/get_webhook.py
cp ~/payload.json .
repo=$(jq '.repository.full_name' payload.json)

curl -o actions-runner-linux-x64-2.328.0.tar.gz -L https://github.com/actions/runner/releases/download/v2.328.0/actions-runner-linux-x64-2.328.0.tar.gz
echo "01066fad3a2893e63e6ca880ae3a1fad5bf9329d60e77ee15f2b97c148c3cd4e  actions-runner-linux-x64-2.328.0.tar.gz" | shasum -a 256 -c
tar xzf ./actions-runner-linux-x64-2.328.0.tar.gz

token=$(gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  /repos/${repo}/actions/runners/registration-token | jq -r '.token')

echo "${token}" >> token.txt
./config.sh --unattended --url https://github.com/${repo} --token ${token} --ephemeral --labels perlmutter,gpu

echo "PAYLOAD_FILE=$(realpath payload.json)" >> .env
