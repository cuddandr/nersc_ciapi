#!/bin/bash
module load python/3.11
ci_client_dir=${PWD}

log_dir=${ci_client_dir}/logs
log_file="start_runner_${1}.log"
mkdir -p ${log_dir}
exec &> "${log_dir}/${log_file}"

mongodb_env=${MONGODB_ENV:-"mongo_env.sh"}
if [ -f "${mongodb_env}" ]; then
    echo "Loading MONGODB vars from ${mongodb_env}"
    source ${mongodb_env}
fi

webhook_db_id=${1}
runner_dir=$SCRATCH/gh_runner
echo "Webhook ID: ${webhook_db_id}"

mkdir -p ${runner_dir}
gh_dir=$(mktemp -d -p ${runner_dir})
echo "Created ${gh_dir}"

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

echo "Downloading webhook payload..."
mongodb_url=${MONGODB_URL:-"mongodb://localhost:27017"}
mongodb_name=${MONGODB_NAME:-"github_webhooks"}
mongodb_collection=${MONGODB_COLLECTION:-"webhooks"}
python3 scripts/get_webhook.py --uri $mongodb_url -d $mongodb_name -c $mongodb_collection --field _id --value $webhook_db_id > ${gh_dir}/payload.json

cd ${gh_dir}
echo "Current dir: ${PWD}"
repo=$(jq -r '.repository.full_name' payload.json)
echo "Repository: ${repo}"

echo "Downloading GH self-hosted runner..."
curl -o actions-runner-linux-x64-2.332.0.tar.gz -L https://github.com/actions/runner/releases/download/v2.332.0/actions-runner-linux-x64-2.332.0.tar.gz
echo "f2094522a6b9afeab07ffb586d1eb3f190b6457074282796c497ce7dce9e0f2a  actions-runner-linux-x64-2.332.0.tar.gz" | shasum -a 256 -c
tar xzf ./actions-runner-linux-x64-2.332.0.tar.gz

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
sbatch ${ci_client_dir}/scripts/sbatch_runner.sh
