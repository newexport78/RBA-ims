# IMS — Internal Management System (RBAC)

## Key Features

### Authentication & Security
- **Single login** for all roles: username + password, then **OTP sent to email** (6-digit code).
- **Role-based access control (RBAC)**: each role has its own dashboard and allowed actions.
- **Login rate limiting**: too many failed attempts → temporary lockout (escalating: 30s → 1m → 30m → 24h). Clear with `python manage.py clear_login_ratelimit`.
- **Password rules**: validated on creation/change; optional “force change on next login”.
- **Session timeout**: configurable via Superadmin Settings.

### Roles & Capabilities

| Role | Key Features |
|------|--------------|
| **Superadmin** | Create the single **2IC** account (with optional phone, DOB). Manage users list, devices, audit log, settings, profile. Full system oversight. |
| **2IC** | **My employees**: create employees (employee number, name, phone, DOB, email, password). **Orders**: create orders with optional PDF, assign to employees (search by employee ID). **My profile**. **Cmd+V** on dashboard → popup to **download password-protected PDF** of employee list (password: last 3 digits of 2IC phone + DOB in DDMMYY + `1215`). |
| **Employee** | Log in with **employee number + password**. View **orders received** from 2IC, **download order PDFs** (each PDF opens with password: last 2 digits of employee number + last 3 of phone + DOB in DDMMYY). **Profile** (edit name, email, phone, password). |

### Orders & Documents
- **2IC creates orders**: title, description, optional PDF; assign to one or more employees (with search by employee ID).
- **Employee receives orders**: table of assigned orders; download PDF (encrypted with per-employee password).
- **Password-protected PDFs**: order PDFs and employee-list export use AES-256 encryption with role-specific passwords.

### Audit & Management
- **Audit log**: actions (login, user created, order created, etc.) with filters and CSV/Excel export.
- **Devices**: device registration and approval/block by Superadmin.
- **Settings**: session timeout, OTP expiry (Superadmin only).

---

## System Architecture (Simple)

```
┌─────────────────────────────────────────────────────────────────┐
│                         Browser (User)                            │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Django (config.urls)                          │
│  /login/  /otp/  /logout/  /dashboard/superadmin/  /twoic/  ...  │
└───────────────────────────────┬─────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   accounts    │     │     orders      │     │     config       │
│   (views,     │     │   (views,       │     │  (settings,      │
│   models,     │     │   models:       │     │   urls)          │
│   RBAC, OTP)  │     │   Order,        │     │                 │
│               │     │   OrderAssign.) │     │                 │
└───────┬───────┘     └────────┬────────┘     └────────┬────────┘
        │                     │                       │
        └─────────────────────┼───────────────────────┘
                              ▼
                    ┌─────────────────┐
                    │   Database      │
                    │ (SQLite/Postgres)│
                    │ + Cache (rate   │
                    │   limit)        │
                    └─────────────────┘
```

- **Single web app**: one codebase, one domain; role determines dashboard after login.
- **No separate microservices**: Django handles auth, dashboards, orders, and file serving.
- **Database**: one DB for users, OTPs, orders, assignments, audit, settings; optional DB cache for rate limiting.

---

## Technology Used

| Layer | Technology |
|-------|------------|
| **Backend** | Python 3, **Django 4.2+** (MVC-style: views, models, URL routing, auth) |
| **Database** | SQLite (dev) or **PostgreSQL** (production) via `psycopg2-binary`, `dj-database-url` |
| **Config** | **django-environ** (`.env` for `SECRET_KEY`, `DATABASE_URL`, `EMAIL_*`, etc.) |
| **Email** | Django `send_mail`; SMTP (e.g. Gmail) when `EMAIL_HOST` set in `.env`; else console backend for OTP |
| **PDF** | **pypdf** (with crypto): encrypt/decrypt order PDFs and employee-list PDF; **reportlab**: generate table PDF (employee number + name) |
| **Caching** | Django database cache (rate-limit keys) |
| **Frontend** | Server-rendered HTML (Django templates), CSS, minimal JavaScript (modals, search, role-based show/hide) |
| **Deployment** | **gunicorn** (WSGI); static/media via same app or CDN |
| **Other** | **openpyxl** (audit log Excel export) |

---

## Benefits

1. **Security**: OTP by email, role-only access, rate limiting, password-protected PDFs, no public signup.
2. **Clear hierarchy**: Superadmin → 2IC → Employee; 2IC only manages own employees and orders.
3. **Auditability**: Audit log and device list for oversight.
4. **Simple ops**: Single app, standard Django stack; easy to run locally or deploy with gunicorn + env vars.
5. **Flexible auth**: Same login flow for all; email OTP when SMTP configured.

---

## Future Improvements

1. **Email**: Add HTML email templates for OTP and optional notifications (e.g. “New order assigned”).
2. **2FA**: Optional TOTP (e.g. Google Authenticator) for Superadmin/2IC.
3. **Employee self-service**: Forgot password flow for employees (e.g. reset via email link or 2IC reset).
4. **Orders**: Due dates, reminders, and simple status workflow (e.g. Pending → In progress → Done).
5. **Reporting**: Dashboards/charts (orders per 2IC, completion rates) and scheduled report PDFs.
6. **Mobile**: Responsive templates or a small REST API + mobile app for employees (view orders, download PDFs).
7. **Backup**: Automated DB backups and optional audit-log export to external storage.
8. **Localisation**: Multi-language support (e.g. Django i18n) for labels and emails.

---

*This overview describes the current system with roles: **Superadmin**, **2IC**, and **Employee** only.*
