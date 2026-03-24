# Deploy to AWS ECS (Option B – ALB health checks + custom domain)

Use this when ECS deployments stall because **new tasks are Unhealthy** (often HTTP **400** on `/health/`). Django rejects the ALB default `Host: <private IP>`; the app includes `AlbHealthCheckHostMiddleware` to fix **only** `/health/`.

## 1. Build and push with an immutable tag

Always use a **new tag** each release (not only `:latest`) so Fargate pulls the new image.

```bash
cd /path/to/RBAC
export AWS_REGION=ap-south-1
export AWS_ACCOUNT_ID=241732001689   # your account
export TAG=rbac-$(date +%Y%m%d-%H%M)   # e.g. rbac-20250322-1530

docker build --platform linux/amd64 -t rbac-ims:$TAG .

aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

docker tag rbac-ims:$TAG $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/rbac-ims:$TAG
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/rbac-ims:$TAG
```

Copy the full image URI for step 2:

`241732001689.dkr.ecr.ap-south-1.amazonaws.com/rbac-ims:YOUR_TAG`

## 2. ECS task definition – new revision

1. **ECS** → **Task definitions** → open `rbac-task` → **Create new revision**.
2. **Container** `rbac-app` → **Image**: paste the URI with **`YOUR_TAG`** (not an old digest).
3. **Environment variables** (adjust values; keep secrets from your current working revision):

| Key | Example / notes |
|-----|------------------|
| `ALLOWED_HOSTS` | `rbac-ims.com,rbac-alb-XXXX.ap-south-1.elb.amazonaws.com` (no spaces) |
| `HEALTH_CHECK_HOST` | `rbac-ims.com` (must be one of the hosts in `ALLOWED_HOSTS`) |
| `DEBUG` | `False` |
| `SECRET_KEY` | (unchanged) |
| `DATABASE_URL` | (unchanged) |
| `REDIS_URL` | (unchanged, if used) |
| `SENDGRID_API_KEY` | (unchanged, if used) |
| … | Copy **every** other key from the last **working** revision so nothing is dropped |

4. **Create** revision.

## 3. Target group `rbac-tg` (one-time sanity)

**EC2** → **Target groups** → `rbac-tg` → **Health checks** → **Edit**:

- **Path:** `/health/`
- **Port:** **Traffic port** (container **8000**), not fixed **80**
- **Success codes:** `200` or `200,301` (remove temporary `400` if you added it)

Save.

## 4. ECS service

1. **Health check grace period:** **120** seconds (or higher).
2. **Update service** → select the **new task definition revision**.
3. **Force new deployment** → **Update**.

Wait until **Deployments** = **Completed** and **Targets** = **1 Healthy** (or all new targets Healthy).

## 5. Cloudflare in front of ALB (SSL Flexible)

If you use **Cloudflare** with **Flexible** SSL, the ALB may see **HTTP** and send `X-Forwarded-Proto: http` while users use **https://yourdomain**. Django then mishandles CSRF/session cookies.

The app includes **`CloudflareForwardedProtoMiddleware`**, which reads **`CF-Visitor`** and sets **`X-Forwarded-Proto: https`** when appropriate.

Also set (optional, explicit):

```text
USE_X_FORWARDED_HOST=true
CSRF_TRUSTED_ORIGINS=https://rbac-ims.com,https://www.rbac-ims.com
```

(`USE_X_FORWARDED_HOST` defaults to **true** when `DEBUG=false`.)

## 6. OTP email: SendGrid while SES is in sandbox

If **Amazon SES** is still in **sandbox** (OTP fails for some users; CloudWatch shows `SES send_email failed`), you can send OTP via **SendGrid** until production access is approved.

**SendGrid setup (once):**

1. [SendGrid](https://sendgrid.com) → **Settings** → **API Keys** → create a key with **Mail Send** permission.
2. **Settings** → **Sender Authentication**: verify **Single Sender Verification** or **Domain Authentication** for the address you will use as `DEFAULT_FROM_EMAIL` (e.g. `noreply@rbac-ims.com`).

**ECS task definition environment** (new revision):

| Key | Value |
|-----|--------|
| `USE_SES` | `false` — **required** so the app uses SendGrid instead of SES first. |
| `SENDGRID_API_KEY` | Your `SG....` API key (prefer **Secrets Manager** / SSM, not plain text in the console if possible). |
| `DEFAULT_FROM_EMAIL` | Must match a **verified sender** in SendGrid (same as you use today). |

Remove or leave unset `AWS_SES_REGION_NAME` if you like; it is ignored when `USE_SES=false`.

**When SES production is approved:** set `USE_SES=true`, clear or unset `SENDGRID_API_KEY` if you want only SES, redeploy.

## 7. Verify

- `https://rbac-ims.com/health/` should return `ok`.
- `https://rbac-ims.com/login/` → login should not show **403 CSRF** if `ALLOWED_HOSTS` / `CSRF_TRUSTED_ORIGINS` include your site.
- After switching to SendGrid, try 2IC login; OTP should arrive without per-recipient SES verification.

## If it still fails (general)

- **ECS** → **Tasks** → match **private IP** of **Unhealthy** target → confirm **Image** digest matches ECR for **YOUR_TAG**.
- **CloudWatch** → log group `/ecs/rbac-task` → stream for that task → errors before `Starting gunicorn`.
