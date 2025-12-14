# Token Vending Machine

A Kubernetes-native service that exchanges Kubernetes service account tokens for scoped AWS credentials. This enables fine-grained AWS access control based on Kubernetes identity, without requiring AWS credentials in each workload.

## How It Works

```
┌─────────────────┐     ┌─────────────────────┐     ┌─────────────┐     ┌─────────────┐
│   K8s Workload  │────▶│  Token Vending      │────▶│  K8s API    │     │   AWS STS   │
│                 │     │  Machine            │     │  TokenReview│     │             │
│  SA Token       │     │                     │◀────│             │     │             │
└─────────────────┘     │  1. Validate token  │     └─────────────┘     │             │
                        │  2. Extract identity│                         │             │
                        │  3. Render policy   │────────────────────────▶│  AssumeRole │
                        │  4. Assume role     │◀────────────────────────│             │
                        │  5. Return creds    │                         └─────────────┘
                        └─────────────────────┘
```

1. A Kubernetes workload sends its service account token to the Token Vending Machine
2. The service validates the token against the Kubernetes API (TokenReview)
3. Extracts the `namespace` and `serviceaccount` from the token
4. Renders an IAM policy template with those values
5. Calls AWS STS `AssumeRole` with the scoped policy
6. Returns temporary AWS credentials to the workload

## API

### `POST /credentials`

Exchange a Kubernetes service account token for AWS credentials.

**Request:**

```http
POST /credentials HTTP/1.1
Authorization: Bearer <kubernetes-service-account-token>
Content-Type: application/json
```

The token should be a Kubernetes service account token, either:
- Mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`
- Created via `kubectl create token <serviceaccount>`

**Response:**

```json
{
  "AWS_ACCESS_KEY_ID": "ASIAXXXXXXXXXXX",
  "AWS_SECRET_ACCESS_KEY": "xxxxxxxxxxxxxxxxxxxxxxxx",
  "AWS_SESSION_TOKEN": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx..."
}
```

**Error Responses:**

| Status | Description |
|--------|-------------|
| 401 | Invalid or expired token, or token not from a service account |
| 500 | Failed to read policy template or assume AWS role |

### `GET /healthz`

Health check endpoint.

**Response:**

```json
{
  "status": "healthy"
}
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AWS_ROLE_ARN` | Yes | - | ARN of the AWS role to assume |
| `AWS_REGION` | Yes | - | AWS region for STS calls |
| `AWS_ACCESS_KEY_ID` | Yes | - | AWS credentials for the service |
| `AWS_SECRET_ACCESS_KEY` | Yes | - | AWS credentials for the service |
| `POLICY_TEMPLATE_PATH` | No | `/etc/token-vending-machine/policy.json` | Path to the IAM policy template |
| `SESSION_DURATION_SECONDS` | No | `3600` | Duration of issued credentials (1-12 hours) |
| `LOG_LEVEL` | No | `INFO` | Log verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `PORT` | No | `8000` | Port the service listens on |

## Policy Template

The policy template uses [Jinja2](https://jinja.palletsprojects.com/) syntax. The following variables are available:

| Variable | Description |
|----------|-------------|
| `{{ namespace }}` | Kubernetes namespace of the service account |
| `{{ serviceaccount }}` | Name of the service account |

### Example Template

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::my-bucket/{{ namespace }}/{{ serviceaccount }}/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": ["arn:aws:s3:::my-bucket"],
      "Condition": {
        "StringLike": {
          "s3:prefix": ["{{ namespace }}/{{ serviceaccount }}/*"]
        }
      }
    }
  ]
}
```

This example grants each workload access only to its own prefix in S3: `s3://my-bucket/<namespace>/<serviceaccount>/`.

### Advanced Templating

Since Jinja2 is used, you can leverage conditionals, filters, and more:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:*"],
      "Resource": [
        "arn:aws:s3:::{{ 'prod' if namespace == 'production' else 'dev' }}-bucket/{{ namespace }}/{{ serviceaccount }}/*"
      ]
    }
    {% if namespace == "production" %},
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt"],
      "Resource": ["arn:aws:kms:*:*:key/prod-key-id"]
    }
    {% endif %}
  ]
}
```

---

## Deployment

### Prerequisites

#### 1. AWS IAM User (for the Token Vending Machine)

Create an IAM user that the Token Vending Machine will use to call `sts:AssumeRole`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::ACCOUNT_ID:role/token-vending-machine-role"
    }
  ]
}
```

Generate access keys for this user and provide them as `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.

#### 2. AWS IAM Role (to be assumed)

Create the role that will be assumed with scoped policies:

**Trust Policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT_ID:user/token-vending-machine-user"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

**Permissions Policy:**

The role needs a broad permission set that will be *scoped down* by the inline policy from the template. For example:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": "*"
    }
  ]
}
```

> **Note:** The effective permissions are the *intersection* of the role's permissions and the inline session policy. The session policy can only restrict, never expand, the role's permissions.

---

### Kubernetes Manifests

#### Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: token-vending-machine
```

#### ServiceAccount and RBAC

The Token Vending Machine needs permission to call the `TokenReview` API:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: token-vending-machine
  namespace: token-vending-machine
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: token-vending-machine
rules:
  - apiGroups: ["authentication.k8s.io"]
    resources: ["tokenreviews"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: token-vending-machine
subjects:
  - kind: ServiceAccount
    name: token-vending-machine
    namespace: token-vending-machine
roleRef:
  kind: ClusterRole
  name: token-vending-machine
  apiGroup: rbac.authorization.k8s.io
```

#### ConfigMap (Policy Template)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: token-vending-machine-policy
  namespace: token-vending-machine
data:
  policy.json: |
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteObject"
          ],
          "Resource": [
            "arn:aws:s3:::my-bucket/${namespace}/${serviceaccount}/*"
          ]
        }
      ]
    }
```

#### Secret (AWS Credentials)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: token-vending-machine-aws
  namespace: token-vending-machine
type: Opaque
stringData:
  AWS_ACCESS_KEY_ID: "AKIAXXXXXXXXXXXXXXXX"
  AWS_SECRET_ACCESS_KEY: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

#### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: token-vending-machine
  namespace: token-vending-machine
spec:
  replicas: 2
  selector:
    matchLabels:
      app: token-vending-machine
  template:
    metadata:
      labels:
        app: token-vending-machine
    spec:
      serviceAccountName: token-vending-machine
      containers:
        - name: token-vending-machine
          image: token-vending-machine:latest
          ports:
            - containerPort: 8000
          env:
            - name: AWS_ROLE_ARN
              value: "arn:aws:iam::ACCOUNT_ID:role/token-vending-machine-role"
            - name: AWS_REGION
              value: "us-east-1"
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: token-vending-machine-aws
                  key: AWS_ACCESS_KEY_ID
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: token-vending-machine-aws
                  key: AWS_SECRET_ACCESS_KEY
            - name: POLICY_TEMPLATE_PATH
              value: "/etc/token-vending-machine/policy.json"
            - name: LOG_LEVEL
              value: "INFO"
          volumeMounts:
            - name: policy
              mountPath: /etc/token-vending-machine
              readOnly: true
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8000
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /healthz
              port: 8000
            initialDelaySeconds: 5
            periodSeconds: 5
          resources:
            requests:
              memory: "64Mi"
              cpu: "100m"
            limits:
              memory: "128Mi"
              cpu: "500m"
      volumes:
        - name: policy
          configMap:
            name: token-vending-machine-policy
```

#### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: token-vending-machine
  namespace: token-vending-machine
spec:
  selector:
    app: token-vending-machine
  ports:
    - port: 80
      targetPort: 8000
```

---

### Network Requirements

The Token Vending Machine needs:

1. **Kubernetes API access** — Automatically available in-cluster via the service account. No additional configuration needed.

2. **AWS STS access** — Outbound HTTPS to `sts.<region>.amazonaws.com`. Ensure:
   - NetworkPolicies allow egress to AWS endpoints
   - If using a proxy, configure `HTTPS_PROXY` environment variable

---

## Usage from Workloads

### Example: Python

```python
import os
import requests

# Read the service account token
with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
    token = f.read()

# Request AWS credentials
response = requests.post(
    "http://token-vending-machine.token-vending-machine.svc.cluster.local/credentials",
    headers={"Authorization": f"Bearer {token}"}
)
response.raise_for_status()
creds = response.json()

# Use with boto3
import boto3
s3 = boto3.client(
    "s3",
    aws_access_key_id=creds["AWS_ACCESS_KEY_ID"],
    aws_secret_access_key=creds["AWS_SECRET_ACCESS_KEY"],
    aws_session_token=creds["AWS_SESSION_TOKEN"],
)
```

### Example: Shell

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)

CREDS=$(curl -s -H "Authorization: Bearer $TOKEN" \
  http://token-vending-machine.token-vending-machine.svc.cluster.local/credentials)

export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .AWS_ACCESS_KEY_ID)
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .AWS_SECRET_ACCESS_KEY)
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .AWS_SESSION_TOKEN)

aws s3 ls s3://my-bucket/
```

---

## Building

```bash
docker build -t token-vending-machine:latest .
```

## Local Development

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run (requires environment variables and in-cluster config)
python main.py
```

## License

MIT

