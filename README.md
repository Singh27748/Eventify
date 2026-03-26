# Eventify - Django Event Management System

Eventify is a Django event platform with public discovery, role-based accounts, organizer tooling, booking/payment flows, invoices, ticket PDFs, QR-based ticket access, and admin panels.

## Feature Highlights

- Multi-role auth: `User`, `Organizer`, `Admin`
- Google and GitHub OAuth login
- Email verification and TOTP-based 2FA with backup codes
- Smart event discovery with search, category filters, featured events, trending events, and location-oriented browsing
- Public and private event creation
- Event schedules, galleries, attendee management, and organizer analytics
- Multiple ticket types, QR tickets, ticket PDFs, payment history, invoices, cancellations, and Razorpay checkout
- Reminder notifications plus `send_event_reminders` management command

## Main User Flow

- Home -> Login / Register
- Register -> OTP Verify -> Auto Login -> Dashboard
- Forgot Password -> OTP Verify -> Reset Password -> Dashboard
- Dashboard -> Browse Events -> Event Detail -> Book Event -> Payment -> Booking Success
- My Bookings -> Ticket PDF / Invoice / Cancellation
- Organizer Dashboard -> My Events -> Participants / Revenue / Event Management
- Platform Admin -> Users / Events / Bookings / Payments / Support

## Run Locally

```bash
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

Open `http://127.0.0.1:8000`

## Useful Commands

```bash
python manage.py check
python manage.py send_event_reminders --days 1
```

## Environment Variables

```powershell
$env:GOOGLE_OAUTH_CLIENT_ID="your-google-client-id"
$env:GOOGLE_OAUTH_CLIENT_SECRET="your-google-client-secret"
$env:GITHUB_OAUTH_CLIENT_ID="your-github-client-id"
$env:GITHUB_OAUTH_CLIENT_SECRET="your-github-client-secret"
$env:RAZORPAY_KEY_ID="your-razorpay-key-id"
$env:RAZORPAY_KEY_SECRET="your-razorpay-key-secret"
```

## Demo Accounts

- User: `john@example.com` / `password123`
- Organizer: `organizer@example.com` / `organizer123`
- Admin: `asing27748@gmail.com` / `admin123`

## Stack

- Django
- SQLite
- Django templates + static CSS/JS

## Optional MySQL Setup

1. Create a database, for example `mydb`.
2. Set environment variables:

```powershell
$env:USE_MYSQL="1"
$env:MYSQL_DATABASE="mydb"
$env:MYSQL_USER="root"
$env:MYSQL_PASSWORD="your_password"
$env:MYSQL_HOST="127.0.0.1"
$env:MYSQL_PORT="3306"
```

3. Run migrations and start the app:

```bash
python manage.py migrate
python manage.py runserver
```

## Security / Transport Notes

- Panel `POST` payloads can be encrypted in the browser before submit.
- Django middleware decrypts encrypted panel payloads into `request.POST`.
- JSON responses can be encrypted by sending `X-Panel-Encryption: 1` with `X-CSRFToken`.
- Encrypted request field name: `__enc_payload`

## API Endpoints

- `POST /api/login/`
- `POST /api/register/send-otp/`
- `POST /api/register/verify-otp/`
- `GET /api/events/`
- `GET /api/events/trending/`

## Integration Notes

- Google and GitHub OAuth redirect back to the same Eventify auth routes and create/link local accounts by verified email.
- Razorpay is used for verified checkout when gateway keys are configured; the local payment flow remains available for development without external credentials.
- 2FA uses TOTP app codes plus backup codes.
