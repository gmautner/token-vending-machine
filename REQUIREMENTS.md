# Token Vending Machine

## Requirements

The web service will receive HTTP requests having a Bearer token in the format: `Authorization: Bearer <service-account-token>`

The provided token is the content of the `token` field in the format of a token present in a Kubernetes Secret of type `kubernetes.io/service-account-token`.

The service will also load a templated IAM policy from a predefined folder in the filesystem, that can be mounted from a `ConfigMap` in a Kubernetes cluster.

The service should extract the `serviceaccount` and `namespace` from the token by calling the Kubernetes API. The service will be running in-cluster.

The service should use the extracted `serviceaccount` and `namespace` to render the IAM policy template, which will have placeholders for the `serviceaccount` and `namespace` to be replaced with the actual values.

Then the service should make an AWS STS `AssumeRole` call with the rendered IAM policy, and obtain AWS API Key, Secret Key and Session Token, returning them in a JSON response with keys:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`

The following environment variables should be set and expected by the service:

- `AWS_ROLE_ARN`: role to be assumed for the STS `AssumeRole` call
- `AWS_REGION`: region to be used for the STS `AssumeRole` call
- `AWS_ACCESS_KEY_ID`: AWS API Key for the STS `AssumeRole` call
- `AWS_SECRET_ACCESS_KEY`: AWS Secret Key for the STS `AssumeRole` call

## Implementation

Use Python FastAPI with the latest version of the library.

Create a Dockerfile to build the service as a container image.
