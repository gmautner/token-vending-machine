"""Token Vending Machine - Issues scoped AWS credentials based on Kubernetes service account identity."""

import os
from pathlib import Path
from typing import Annotated

import boto3
from fastapi import Depends, FastAPI, Header, HTTPException, status
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from pydantic import BaseModel
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    aws_role_arn: str
    aws_region: str
    aws_access_key_id: str
    aws_secret_access_key: str
    policy_template_path: str = "/etc/token-vending-machine/policy.json"
    session_duration_seconds: int = 3600

    class Config:
        env_file = ".env"


class AwsCredentials(BaseModel):
    """AWS credentials response model."""

    AWS_ACCESS_KEY_ID: str
    AWS_SECRET_ACCESS_KEY: str
    AWS_SESSION_TOKEN: str


def get_settings() -> Settings:
    """Dependency to get application settings."""
    return Settings()


def get_k8s_client() -> client.AuthenticationV1Api:
    """Dependency to get Kubernetes authentication API client."""
    config.load_incluster_config()
    return client.AuthenticationV1Api()


def get_sts_client(settings: Annotated[Settings, Depends(get_settings)]) -> boto3.client:
    """Dependency to get AWS STS client."""
    return boto3.client(
        "sts",
        region_name=settings.aws_region,
        aws_access_key_id=settings.aws_access_key_id,
        aws_secret_access_key=settings.aws_secret_access_key,
    )


app = FastAPI(
    title="Token Vending Machine",
    description="Issues scoped AWS credentials based on Kubernetes service account identity",
    version="1.0.0",
)


def extract_bearer_token(authorization: str = Header(...)) -> str:
    """Extract and validate Bearer token from Authorization header."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format. Expected 'Bearer <token>'",
        )
    return authorization[7:]  # Remove "Bearer " prefix


def validate_token_and_extract_identity(
    token: str,
    k8s_client: client.AuthenticationV1Api,
) -> tuple[str, str]:
    """
    Validate a Kubernetes service account token and extract identity.

    Returns:
        Tuple of (namespace, service_account_name)
    """
    token_review = client.V1TokenReview(
        spec=client.V1TokenReviewSpec(token=token)
    )

    try:
        response = k8s_client.create_token_review(token_review)
    except ApiException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Failed to validate token: {e.reason}",
        )

    if not response.status.authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is not valid or has expired",
        )

    # Username format: system:serviceaccount:<namespace>:<service-account-name>
    username = response.status.user.username
    if not username.startswith("system:serviceaccount:"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is not from a service account",
        )

    parts = username.split(":")
    if len(parts) != 4:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid service account token format",
        )

    namespace = parts[2]
    service_account = parts[3]

    return namespace, service_account


def load_and_render_policy(
    template_path: str,
    namespace: str,
    service_account: str,
) -> str:
    """Load IAM policy template and render with provided values."""
    try:
        policy_template = Path(template_path).read_text()
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Policy template not found",
        )
    except IOError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read policy template: {e}",
        )

    # Render the template with namespace and service account
    rendered_policy = policy_template.replace("${namespace}", namespace)
    rendered_policy = rendered_policy.replace("${serviceaccount}", service_account)

    return rendered_policy


def assume_role_with_policy(
    sts_client: boto3.client,
    role_arn: str,
    session_name: str,
    policy: str,
    duration_seconds: int,
) -> AwsCredentials:
    """Assume an AWS role with the given inline policy."""
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            Policy=policy,
            DurationSeconds=duration_seconds,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to assume role: {e}",
        )

    credentials = response["Credentials"]
    return AwsCredentials(
        AWS_ACCESS_KEY_ID=credentials["AccessKeyId"],
        AWS_SECRET_ACCESS_KEY=credentials["SecretAccessKey"],
        AWS_SESSION_TOKEN=credentials["SessionToken"],
    )


@app.get("/healthz")
def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/credentials", response_model=AwsCredentials)
def get_credentials(
    token: Annotated[str, Depends(extract_bearer_token)],
    settings: Annotated[Settings, Depends(get_settings)],
    k8s_client: Annotated[client.AuthenticationV1Api, Depends(get_k8s_client)],
    sts_client: Annotated[boto3.client, Depends(get_sts_client)],
) -> AwsCredentials:
    """
    Exchange a Kubernetes service account token for scoped AWS credentials.

    The token is validated against the Kubernetes API, and the service account's
    namespace and name are used to render an IAM policy template. The rendered
    policy is then used to assume an AWS role with scoped permissions.
    """
    # Validate token and extract identity
    namespace, service_account = validate_token_and_extract_identity(token, k8s_client)

    # Load and render the IAM policy template
    policy = load_and_render_policy(
        settings.policy_template_path,
        namespace,
        service_account,
    )

    # Generate a session name from the identity
    session_name = f"{namespace}-{service_account}"[:64]  # AWS limits to 64 chars

    # Assume the role with the scoped policy
    return assume_role_with_policy(
        sts_client,
        settings.aws_role_arn,
        session_name,
        policy,
        settings.session_duration_seconds,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)

