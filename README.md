# Forward Auth

This repository contains the `Forward Auth` Python package and two authentication middleware modules, `dachub_auth` and `incore_auth`, built upon the Forward Auth package.

## Structure

- **dachub_auth/**, **incore_auth/**: Source code for each authentication middleware module.
- **forward_auth/**: Python package with core utilities, such as `JWTAuthenticator`, for building authentication middleware.
- **Dockerfile.dachub_auth**, **Dockerfile.incore_auth**: Dockerfiles for building each authentication middleware.
- **GitHub Actions Workflow**: Automates building and pushing Docker images with manual selection between Dockerfiles.

## GitHub Actions Workflow

### Trigger
- **Manual Only**: Select either `Dockerfile.dachub_auth` or `Dockerfile.incore_auth`.

### Key Steps
1. **Extract Dockerfile Name**: Determines image name (`dachub-auth` or `incore-auth`).
2. **Build and Push**: Logs into GitHub and NCSA Hub registries, builds, and pushes the image.

### Required Environment Variables
- `KEYCLOAK_PUBLIC_KEY`, `KEYCLOAK_AUDIENCE`, `KEYCLOAK_URL`, etc.

### Artifacts
- **DACHUB Auth Docker Image**: hub.ncsa.illinois.edu/dachub/dachub_auth

## Local Build & Run

To build and run `dachub_auth` locally:

```bash
docker build -f Dockerfile.dachub_auth -t dachub_auth:test .
docker run -d -p 5000:5000 \
  -e FLASK_APP="app.py" \
  -e KEYCLOAK_PUBLIC_KEY="..." \
  -e KEYCLOAK_AUDIENCE="..." \
  -e KEYCLOAK_URL="..." \
  dachub_auth:test
```

To build and run `incore_auth`, replace `Dockerfile.dachub_auth` and `dachub_auth:test` with `Dockerfile.incore_auth` and `incore_auth:test`, respectively.
