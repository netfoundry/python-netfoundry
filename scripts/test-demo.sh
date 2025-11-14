#!/bin/bash
# Test script for nfctl demo command
# Can be run locally or in GitHub Actions

set -o errexit
set -o xtrace
set -o pipefail

# Create temporary directory and config file
TEMP_DIR=$(mktemp -d)
TEMP_CONFIG="${TEMP_DIR}/nfctl.ini"
echo "Using temporary config: ${TEMP_CONFIG}"

# Cleanup on exit
trap 'rm -rf "${TEMP_DIR}"' EXIT

# Determine prefix based on environment
if [[ -n "${GITHUB_RUN_ID}" ]]; then
    # Running in GitHub Actions
    PREFIX="gh-${GITHUB_RUN_ID}"
else
    # Running locally - use timestamp or custom prefix
    PREFIX="${DEMO_PREFIX:-local-$(date +%s)}"
fi

echo "Using demo prefix: ${PREFIX} (override with DEMO_PREFIX)"

# Set profile (default: "default")
: "${NETFOUNDRY_PROFILE:=default}"
echo "Using profile: ${NETFOUNDRY_PROFILE} (override with NETFOUNDRY_PROFILE)"

# Helper function to run nfctl with the temp config and profile
nfctl() {
    command nfctl --profile "${NETFOUNDRY_PROFILE}" --config-file "${TEMP_CONFIG}" "$@"
}

# Configure nfctl with generated network name and basic settings
nfctl config \
    "general.network=$(command nfctl demo --echo-name --prefix "${PREFIX}")" \
    general.yes=True \
    general.verbose=yes || true # FIXME: sometimes config command exits with an error

# Set optional organization and network group from standard NetFoundry env vars
if [[ -n "${NETFOUNDRY_ORGANIZATION}" ]]; then
    nfctl config "general.organization=${NETFOUNDRY_ORGANIZATION}"
fi
if [[ -n "${NETFOUNDRY_NETWORK_GROUP}" ]]; then
    nfctl config "general.network_group=${NETFOUNDRY_NETWORK_GROUP}"
fi

# Run the demo
nfctl --wait 3000 demo \
    --size medium \
    --regions us-west-2 us-east-1 \
    --provider AWS

# Test service operations
nfctl list services

nfctl get service name=echo% > /tmp/echo.yml

nfctl delete service name=echo%

nfctl create service --file /tmp/echo.yml

# Cleanup: delete the network
nfctl delete network
