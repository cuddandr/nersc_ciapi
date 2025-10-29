#!/bin/bash
module load python/3.11
CI_CLIENT_DIR=${PWD}

WEBHOOK_DB_ID=${1}
runner_dir=$SCRATCH/temp

mkdir -p ${runner_dir}
gh_dir=$(mktemp -d -p ${runner_dir})

VENV_NAME="env/"
if [ ! -d "${VENV_NAME}" ]; then
    echo "Creating Python venv at ${PWD}/${VENV_NAME}"
    python3 -m venv ${VENV_NAME}
    source ${VENV_NAME}/bin/activate
    pip install --no-cache-dir --upgrade -r requirements.txt
else
    echo "Sourcing existing venv at ${PWD}/${VENV_NAME}"
    source ${VENV_NAME}/bin/activate
fi

MONGODB_URI=""
MONGODB_DB_NAME="github_webhooks"
MONGODB_COLLECTION="webhooks"
python3 scripts/get_webhook.py --uri $MONGODB_URI -d $MONGODB_DB_NAME -c $MONGODB_COLLECTION --field _id --value $WEBHOOK_DB_ID > ${gh_dir}/payload.json

cd ${gh_dir}
echo "Current dir: ${PWD}"
repo=$(jq -r '.repository.full_name' payload.json)
echo "${repo}"

echo "Downloading GH self-hosted runner..."
curl -sS -o actions-runner-linux-x64-2.329.0.tar.gz -L https://github.com/actions/runner/releases/download/v2.329.0/actions-runner-linux-x64-2.329.0.tar.gz
echo "194f1e1e4bd02f80b7e9633fc546084d8d4e19f3928a324d512ea53430102e1d  actions-runner-linux-x64-2.329.0.tar.gz" | shasum -a 256 -c
tar xzf ./actions-runner-linux-x64-2.329.0.tar.gz

echo "Retrieving GH access token..."
token=$(gh api \
  --method POST \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  /repos/${repo}/actions/runners/registration-token | jq -r '.token')

echo "Configuring runner..."
echo "${token}" >> token.txt
# --name option to set the runner name
./config.sh --unattended --url https://github.com/${repo} --token ${token} --ephemeral --labels perlmutter,gpu

echo "PAYLOAD_FILE=$(realpath payload.json)" >> .env

echo "Starting job."
# srun ./run.sh
sbatch ${CI_CLIENT_DIR}/scripts/sbatch_runner.sh
