# Test Scripts

## test-demo.sh

Test script for the `nfctl demo` command. Can be run locally or in GitHub Actions.

### Usage

**In GitHub Actions:**

```yaml
- name: Run demo test
  env:
    NETFOUNDRY_CLIENT_ID: ${{ secrets.NETFOUNDRY_CLIENT_ID }}
    NETFOUNDRY_PASSWORD: ${{ secrets.NETFOUNDRY_PASSWORD }}
    NETFOUNDRY_OAUTH_URL: ${{ secrets.NETFOUNDRY_OAUTH_URL }}
  run: ./scripts/test-demo.sh
```

The script automatically detects GitHub Actions via `GITHUB_RUN_ID` and uses it in the network name prefix.

**Locally:**

```bash
# Use default prefix (local-<timestamp>)
./scripts/test-demo.sh

# Use custom prefix
DEMO_PREFIX=mytest ./scripts/test-demo.sh

# Specify organization and network group
NETFOUNDRY_ORGANIZATION=acme \
NETFOUNDRY_NETWORK_GROUP=testing \
DEMO_PREFIX=mytest \
./scripts/test-demo.sh
```

### What it does

1. Creates a temporary directory and config file (cleaned up on exit)
2. Generates a unique network name using `--echo-name`
3. Configures nfctl with all settings in the temp config:
   - Network name (generated)
   - Organization (from `NETFOUNDRY_ORGANIZATION` if set)
   - Network group (from `NETFOUNDRY_NETWORK_GROUP` if set)
   - Auto-confirm and verbose flags
4. Runs the demo with medium size, AWS provider, us-west-2 and us-east-1 regions
5. Tests service operations (list, get, delete, create)
6. Cleans up by deleting the network and removing temp directory

### Environment Variables

**Script Configuration:**

- `GITHUB_RUN_ID` - Auto-detected in GitHub Actions, used for network prefix
- `DEMO_PREFIX` - Custom prefix for local runs (default: `local-<timestamp>`)
- `NETFOUNDRY_PROFILE` - Profile name for token cache isolation (default: `default`)

**Standard NetFoundry Environment Variables:**

- `NETFOUNDRY_ORGANIZATION` - Optional organization name (omitted if unset)
- `NETFOUNDRY_NETWORK_GROUP` - Optional network group name (omitted if unset)
- `NETFOUNDRY_CLIENT_ID` - NetFoundry API credentials
- `NETFOUNDRY_PASSWORD` - NetFoundry API credentials  
- `NETFOUNDRY_OAUTH_URL` - NetFoundry OAuth URL
- `NETFOUNDRY_API_ACCOUNT` - Path to API credentials JSON file

These standard variables match those used by `nfctl login --eval` for consistency.

**Profile Usage:**

The `NETFOUNDRY_PROFILE` variable allows you to isolate token caches for different accounts. Each profile uses a separate cache file (`~/.cache/netfoundry/<profile>.json`), preventing conflicts when working with multiple NetFoundry accounts.

```bash
# Use a specific profile
NETFOUNDRY_PROFILE=advdev \
NETFOUNDRY_API_ACCOUNT=~/.config/netfoundry/advdev.json \
./scripts/test-demo.sh
```

### Features

- **Isolated config**: Each run uses a temporary config file that doesn't interfere with your existing nfctl configuration
- **Auto-cleanup**: Temporary directory is automatically removed on exit (success or failure)
- **Config-based scoping**: Organization and network group are set in the config file (from environment variables) rather than passed as CLI options on every command
