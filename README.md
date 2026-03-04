# jwtaztoken

CLI tool to decode and inspect Azure OAuth / JWT tokens.

## Quick Start

```bash
# Install and run with uv (no manual venv needed)
uv run jwtaztoken fetch
```

## Usage

### Fetch and decode a token from Azure CLI

```bash
# Default (Azure Management API)
uv run jwtaztoken fetch

# With OIDC discovery metadata
uv run jwtaztoken fetch --oidc

# Target a specific resource or scope
uv run jwtaztoken fetch --resource https://graph.microsoft.com/
uv run jwtaztoken fetch --scope https://graph.microsoft.com/.default

# JSON output
uv run jwtaztoken fetch --json
```

### Decode an existing token

```bash
# From argument
uv run jwtaztoken decode "eyJ0eXAi..."

# From pipe
az account get-access-token --query accessToken -o tsv | uv run jwtaztoken decode

# With OIDC metadata
az account get-access-token --query accessToken -o tsv | uv run jwtaztoken decode --oidc
```

## Prerequisites

- [uv](https://docs.astral.sh/uv/)
- [Azure CLI](https://aka.ms/installazurecli) — logged in via `az login`
