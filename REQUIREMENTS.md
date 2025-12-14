# Token Vending Machine

## Requirements

### Core Functionality

The web service will receive HTTP requests having a Bearer token in the format: `Authorization: Bearer <service-account-token>`

The provided token is the content of the `token` field in the format of a token present in a Kubernetes Secret of type `kubernetes.io/service-account-token`.

The service will also load a templated IAM policy from a predefined folder in the filesystem, that can be mounted from a `ConfigMap` in a Kubernetes cluster.

The service should extract the `serviceaccount` and `namespace` from the token by calling the Kubernetes API. The service will be running in-cluster.

The service should use the extracted `serviceaccount` and `namespace` to render the IAM policy template, which will have placeholders for the `serviceaccount` and `namespace` to be replaced with the actual values.

Then the service should make an AWS STS `AssumeRole` call with the rendered IAM policy, and obtain AWS API Key, Secret Key and Session Token, returning them in a JSON response with keys:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`

### Configuration

The following environment variables should be set and expected by the service:

- `AWS_ROLE_ARN`: role to be assumed for the STS `AssumeRole` call
- `AWS_REGION`: region to be used for the STS `AssumeRole` call
- `AWS_ACCESS_KEY_ID`: AWS API Key for the STS `AssumeRole` call
- `AWS_SECRET_ACCESS_KEY`: AWS Secret Key for the STS `AssumeRole` call
- `PORT`: port the service listens on (default: 8000)
- `LOG_LEVEL`: log verbosity (default: INFO)
- `POLICY_TEMPLATE_PATH`: path to the IAM policy template (default: /etc/token-vending-machine/policy.json)
- `SESSION_DURATION_SECONDS`: duration of issued credentials (default: 3600)

### Templating

Use Jinja2 for policy template rendering, allowing:

- Simple variable substitution: `{{ namespace }}`, `{{ serviceaccount }}`
- Conditionals: `{% if namespace == "production" %}...{% endif %}`
- Filters and other Jinja2 features

### Logging

Implement structured JSON logging suitable for Kubernetes:

- Log to stdout in JSON format
- Include request ID tracking (via `X-Request-ID` header)
- Log request/response timing
- Include contextual information (namespace, service account, etc.)
- Configurable log level via environment variable

### Health Check

Provide a `/healthz` endpoint for Kubernetes liveness and readiness probes.

## Implementation

Use Python FastAPI with the latest version of the library.

Create a Dockerfile to build the service as a container image.

## Deployment

Provide Kubernetes manifests for:

- Namespace
- ServiceAccount with RBAC for TokenReview API access
- ConfigMap for the policy template
- Secret for AWS credentials
- Deployment with health probes and security context
- Service

Document the required AWS IAM setup:

- IAM user with permissions to call `sts:AssumeRole`
- IAM role with trust policy for the IAM user
- Role permissions that will be scoped down by the session policy

## CI/CD

### Docker Image Releases

Create a GitHub Actions workflow that:

- Triggers on tag push (`v*`)
- Builds and pushes Docker image to GitHub Container Registry (ghcr.io)
- Tags images with:
  - The version from the tag
  - Major.minor version
  - `latest`

### Continuous Integration

Create a CI workflow that runs on all pull requests:

- Lint with Ruff
- Type check with mypy
- Verify Docker build

### Dependency Management

Configure Dependabot for automatic dependency updates with tiered merge policy:

- Patch bumps: auto-merge after CI passes
- Minor bumps: auto-approve, require human merge
- Major bumps: fully manual review

Also update GitHub Actions versions automatically.
