# IMS — Internal Management System (RBAC)

Secure internal web app with three roles: **Superadmin**, **Admin**, **User**. Single login + OTP by email, role-based dashboards.

## Phase 1: Login + OTP + role redirect; RBAC; one superadmin

- **Login**: Username + password → OTP sent to user's email (or console in dev).
- **OTP**: Enter 6-digit code → sign in and redirect by role.
- **RBAC**: All dashboard URLs require the correct role (enforced in backend).
- **Initial superadmin**: Created via management command (no public signup).

## Phase 2: Superadmin — create admin/user, activate/deactivate, reset password

- **Users list**: All admins and users; filter by role/status; search by name, username, email.
- **Create account**: Add admin or user (username, email, role, initial password, optional first/last name).
- **Activate / Deactivate**: Toggle per user (cannot deactivate yourself).
- **Reset password**: Set new password for any user; optional “Force change on next login”.
- **Force change flow**: If set, after OTP the user is sent to a “Set new password” page before the dashboard.

## Phase 3: Admin — my users, create order (PDF), assign users, list/detail, delete

- **My users**: List only users this admin created (`created_by` = this admin). Create-user form (role User only).
- **Orders**: List orders created by this admin. Create order: title, description, due date, optional PDF upload, assign to one or more of “my users”.
- **Order detail**: View order info and per-assignee status (Sent / Viewed / In progress / Completed). Download PDF link.
- **Delete order**: Confirm and delete (no edit in Phase 3).

## Phase 4: User — my orders, download PDF, submit progress, my submissions, read-only profile

- **My orders**: Table of assigned orders with Download PDF and Submit progress (already in place).
- **Submit progress**: Form per order with notes (text) and optional progress PDF. On submit, assignment status becomes Completed.
- **My submissions**: Read-only list of the user’s progress submissions (timestamp, order, notes, file link, status).
- **My profile**: Read-only page showing name, username, email (no edit).
- **Admin order detail**: “Progress submitted” column with date and link to progress PDF when user has submitted.

### Setup

```bash
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env        # optional: set DEBUG, SECRET_KEY, DATABASE_URL, etc.
python manage.py migrate
python manage.py create_superadmin --email your@email.com
# Enter password when prompted, or: --password YourPassword
```

### Run

```bash
python manage.py runserver
```

- **App**: http://127.0.0.1:8000/ (redirects to login or dashboard)
- **Login**: http://127.0.0.1:8000/login/
- **Django admin**: http://127.0.0.1:8000/admin/ (same User model; use superadmin account)

### Default superadmin (if you ran create_superadmin earlier)

- Username: `superadmin`
- Email: `superadmin@example.com`
- Password: whatever you set (e.g. `SuperAdmin1!`)

OTP in development is printed to the console (no SMTP needed). Set `EMAIL_*` in `.env` for real email.

### URLs

| URL | Who |
|-----|-----|
| `/`, `/login/` | Login page (all) |
| `/otp/` | OTP verification (after login step 1) |
| `/account/change-password/` | Set new password (when forced) |
| `/dashboard/superadmin/` | Superadmin dashboard |
| `/dashboard/superadmin/users/` | User list (create, activate/deactivate, reset password) |
| `/dashboard/admin/` | Admin dashboard (role Admin) |
| `/dashboard/admin/users/` | My users (admin-created only) |
| `/dashboard/admin/users/create/` | Create user (Admin only) |
| `/dashboard/admin/orders/` | Orders list (create, view, delete) |
| `/dashboard/user/` | User dashboard |
| `/logout/` | Logout |

Django admin is at `/admin/`. App dashboards are under `/dashboard/` so they don’t conflict.

### Phase 5–7 and deployment

- **Phase 5**: Devices list; audit log with filters and CSV/Excel export.
- **Phase 6**: Rate limiting, session timeout, password rules, file validation, Settings page.
- **Phase 7**: Status badges, pagination (users, orders, audit log), custom 404/500, DB indexes.

**Production**: See [DEPLOY.md](DEPLOY.md) for Render, environment variables, and backups.
# RBA-ims
