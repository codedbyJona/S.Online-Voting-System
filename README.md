# Secure Online Voting System

A secure online election platform for a cybersecurity university project.

## Features
- Citizen registration with validation and bcrypt password hashing
- JWT authentication using HTTP-only cookies
- 24-hour election timer and automatic closing
- Single vote per citizen
- Admin portal with audit logs and result export
- CSRF protection, secure HTTP headers, rate limiting, and login lockout
- Results page with charts and winner announcement

## Run locally
1. Install dependencies:
   ```bash
   npm install
   ```
2. Start the application:
   ```bash
   npm start
   ```
3. Open `http://localhost:4000`

## Admin credentials
- Username: `admin`
- Password: `Admin@2026!`

## Notes
- The app initializes the election timer on first startup and stores it in the database.
- Candidate photos use placeholder SVG assets in `public/images`.
