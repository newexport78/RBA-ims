# Testing checklist — Phase 1 & Phase 2

Use this to verify that Phase 1 and Phase 2 work as expected.

---

## Before you start

```bash
cd /Users/yeshiwangchk/Desktop/RBAC
source .venv/bin/activate   # or .venv\Scripts\activate on Windows
python manage.py runserver
```

Keep the terminal open so you can see OTP codes (they print to the console when email is not configured).

---

## Phase 1: Login + OTP + role redirect; RBAC; one superadmin

### 1.1 Login page

- [ ] Open **http://127.0.0.1:8000/** or **http://127.0.0.1:8000/login/**
- [ ] You see: “Log in” title, username field, password field, “Continue” button
- [ ] Subtext says you’ll receive a one-time code by email

### 1.2 Login with wrong credentials

- [ ] Enter wrong username or password → error message (e.g. “Invalid username or password”)
- [ ] Leave username or password empty → error message

### 1.3 Login with correct credentials (superadmin)

- [ ] Username: `superadmin`, Password: `SuperAdmin1!` (or what you set)
- [ ] Click “Continue” → you are redirected to **OTP** page
- [ ] OTP page shows “Check your email” and a code field
- [ ] In the **terminal** where `runserver` is running, you see an email with a **6-digit code**

### 1.4 OTP

- [ ] Enter wrong or expired code → error message
- [ ] Enter the correct code from the terminal → you are logged in and redirected

### 1.5 Role redirect (Superadmin)

- [ ] After valid OTP you land on **Superadmin dashboard** (`/dashboard/superadmin/`)
- [ ] Header shows: “IMS”, nav (Dashboard, Users, …), “Logged in as superadmin (Superadmin)”, “Log out”

### 1.6 Direct URL protection (RBAC)

- [ ] Log out (click “Log out”)
- [ ] Log in again as superadmin and complete OTP
- [ ] Open **http://127.0.0.1:8000/dashboard/user/** (User dashboard) in the same browser
- [ ] You are **redirected back** to Superadmin dashboard (user URL is not allowed for superadmin)
- [ ] Similarly, open **http://127.0.0.1:8000/dashboard/admin/** → redirected to your (superadmin) dashboard

### 1.7 Logout

- [ ] Click “Log out” → you are on the login page and see “You have been logged out”
- [ ] Visiting `/dashboard/superadmin/` again → you are sent to **login** (not dashboard)

### 1.8 Root and login when already logged in

- [ ] Log in again (username + password + OTP)
- [ ] Visit **http://127.0.0.1:8000/** or **http://127.0.0.1:8000/login/** → you are **redirected to Superadmin dashboard** (no login form)

---

## Phase 2: Superadmin — create admin/user, activate/deactivate, reset password

*Use the same superadmin account. Stay logged in from Phase 1 or log in again.*

### 2.1 Users list

- [ ] In Superadmin dashboard, click **Users** in the nav
- [ ] You see **Users** page at `/dashboard/superadmin/users/`
- [ ] Table shows at least the superadmin row: columns Name, Username, Email, Role, Status, Last login, Actions
- [ ] “Add user / Add admin” button is visible
- [ ] Search box and filters (role, status) are visible

### 2.2 Create an Admin

- [ ] Click “Add user / Add admin”
- [ ] Fill: Username `admin1`, Email `admin1@example.com`, Role **Admin**, Password `AdminPass1!` (8+ chars), optional first/last name
- [ ] Submit → success message and redirect back to **Users** list
- [ ] New row appears: `admin1`, Admin, Active

### 2.3 Create a User

- [ ] Click “Add user / Add admin” again
- [ ] Fill: Username `staff1`, Email `staff1@example.com`, Role **User**, Password `StaffPass1!`
- [ ] Submit → success and new row for `staff1`, User, Active

### 2.4 Create-account validation

- [ ] Try creating with **same username** as existing (e.g. `admin1`) → error “user already exists”
- [ ] Try with **same email** → error “email already exists”
- [ ] Try with **password shorter than 8** characters → error
- [ ] Try with **empty username or email** → error

### 2.5 Filter and search

- [ ] In Users list, set Role filter to **Admin** → only admin(s) and superadmin(s) if role is Superadmin
- [ ] Set Status to **Active** → only active users
- [ ] Type `admin1` in search → only matching row(s)
- [ ] Clear filters / search → full list again

### 2.6 Deactivate account

- [ ] For **admin1** (not yourself), click **Deactivate**
- [ ] Success message; Status for that row shows **Inactive**
- [ ] Open a private/incognito window (or another browser), go to login, try **admin1** / **AdminPass1!**
- [ ] After OTP (code in runserver terminal), or already at login: you should get a message that the account is **deactivated** (if you try login with admin1 credentials in step 1.2 style, the message appears at login)

  *To be precise: at login step 1, when you enter admin1 + password, the app checks `is_active`. So after deactivating admin1, logging in as admin1 should show “This account is deactivated.”*

- [ ] In Superadmin Users list, click **Activate** for admin1 → Status becomes Active again

### 2.7 Reset password (without force change)

- [ ] Click **Reset password** for `staff1`
- [ ] Set new password (e.g. `NewStaff1!`), leave **“Force change on next login”** **unchecked**
- [ ] Submit → success
- [ ] Log out; log in as **staff1** with **NewStaff1!** → OTP → you land on **User dashboard** (no password change screen)

### 2.8 Reset password with “Force change on next login”

- [ ] As superadmin, go to Users → **Reset password** for `staff1`
- [ ] Set password (e.g. `TempPass1!`) and **check “Force change on next login”** → Submit
- [ ] Log out; log in as **staff1** with **TempPass1!** → OTP
- [ ] You are **not** on User dashboard; you are on **“Set new password”** page
- [ ] Enter new password + confirm (e.g. `MyRealPass1!`) → Submit
- [ ] You are redirected to **User dashboard**
- [ ] Log out and log in again as staff1 with **MyRealPass1!** → OTP → you go straight to dashboard (no forced change screen)

### 2.9 Cannot deactivate yourself

- [ ] As superadmin, in Users list find your own row (superadmin)
- [ ] There should be **no “Deactivate”** button for yourself, or clicking it shows an error like “You cannot deactivate your own account” and you remain active

### 2.10 Dashboard links

- [ ] From Superadmin dashboard, the short description links to **Users** and that opens the user list
- [ ] From Users list, “Back to users” (or nav “Users”) returns to the list; “Add user / Add admin” goes to create form

---

## Quick reference: test accounts

| Role        | Username    | Password (example) | Use |
|------------|-------------|----------------------|-----|
| Superadmin | superadmin  | SuperAdmin1!        | Phase 1 & 2 (create, deactivate, reset) |
| Admin      | admin1      | AdminPass1!         | Create in 2.2; test deactivate/activate |
| User       | staff1      | NewStaff1! or after force change MyRealPass1! | Create in 2.3; test reset & force change |

---

## If something fails

- **OTP not in terminal**: Ensure you’re looking at the same terminal where `python manage.py runserver` is running. If `EMAIL_*` is set in `.env`, OTP goes to email instead.
- **Redirect loop or wrong page**: Clear browser cookies for `127.0.0.1` and log in again.
- **“No users” or missing accounts**: Run migrations: `python manage.py migrate`. Create superadmin if needed: `python manage.py create_superadmin --email your@email.com`.
