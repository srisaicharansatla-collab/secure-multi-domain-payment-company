# Secure Multi-Domain Payment Company

A local payment-company architecture prototype with separate customer, payment, admin, and API route surfaces. Payments are simulated and no card data is accepted or stored.

## Assignment deliverable

The completed architecture report is available at [`docs/Secure_Multi_Domain_Payment_Company_Architecture.docx`](docs/Secure_Multi_Domain_Payment_Company_Architecture.docx).

The report answers the secure multi-domain payment company assignment. It defines five applications with separate business purposes and documents each application's users, features, data, frontend, backend, database, and hosting. It also covers defense in depth, least privilege, Zero Trust, authentication, authorization, network segmentation, threat mitigations, a phased implementation roadmap, and a requirement crosswalk.

The architecture in the report is a proposed target design. The Flask application in this repository is a small local demonstration of selected security concepts; it is not the five independently deployed applications described in the report and does not provide real payment processing or production infrastructure isolation.

## Prototype objective

Payment companies operate several applications that handle different identities and privileges. This project demonstrates role checks, password hashing, CSRF, session boundaries, input validation, an auditable double-entry ledger, and safe payment simulation.

## Features

- Customer registration/login and admin login with role-based authorization.
- PBKDF2 password hashes, signed sessions, HttpOnly/SameSite cookies, CSRF protection, and security headers.
- Dedicated `/customer`, `/payment`, `/admin`, and `/api/v1` route namespaces.
- Idempotent demo payment creation and balanced debit/credit ledger records in SQLite.
- Structured security event logging and generic user-facing errors.
- No PAN, CVV, bank credentials, or real payment processor integration.

## Technology

Python 3.10+, Flask (Werkzeug is included), SQLite.

## Setup and run

```bash
python -m venv .venv
# Activate the environment
pip install -r requirements.txt
$env:APP_SECRET = 'use-a-long-random-secret'  # PowerShell; export APP_SECRET=... on macOS/Linux
python app.py
```

Open http://127.0.0.1:5100. Register a customer. Create an administrator using `python app.py --create-admin admin@example.test` and enter the password when prompted. For HTTPS deployment set `COOKIE_SECURE=1` behind a trusted reverse proxy. Do not expose Flask's development server.

## How it works

Authentication identifies the account and stores its user ID and role in a signed session. Customer routes can read only their account and create simulated payments. Admin routes require the admin role. The payment operation inserts one debit and one credit ledger entry inside a single database transaction and uses a unique idempotency key to prevent duplicate charges. The API exposes a minimal authenticated account status endpoint.

## Screenshots and demo

No screenshot or hosted demo is included. Capture customer registration, a simulated payment, and an admin ledger view from a local run.

## Tests

Run `python -m unittest discover -s tests -v` from this repository root.

## Security considerations

This prototype is not a real payment service and is not PCI DSS compliant. It never handles payment-card data. Signed cookie sessions are not server-side revocable before expiry. Production use requires a compliant payment processor, domain-specific cookie and origin policies, hardened reverse proxy/TLS, rate limits, MFA for administrators, secrets management, database controls, monitoring, incident response, and independent review. For clarity, route namespaces in this local demo represent separately deployable applications; they share one process and database and do not provide actual infrastructure isolation.

## Future improvements

Split the route surfaces into independent deployable services, use a dedicated identity provider, add signed service-to-service tokens, transaction limits and reversal workflows, and add integration/security tests.

