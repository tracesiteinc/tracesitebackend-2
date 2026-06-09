# 🛡️ Tracesite Backend API

**Nigeria 2026 Cyber-Safety Initiative** — Node.js/Express REST API powering the Tracesite URL scanning platform.

---

## Features

| Feature | Description |
|---|---|
| 🔍 URL Scanning | Heuristic threat analysis with Nigerian scam pattern detection |
| 👤 Auth | JWT-based register/login with bcrypt password hashing |
| 🚩 Community Reporting | Users report scam URLs; admins confirm/dismiss |
| 🌐 VirusTotal | Optional integration for enhanced scan accuracy |
| 🛡️ Rate Limiting | Per-route limits to prevent abuse |
| 🗄️ SQLite | Zero-config embedded database (upgrade to PostgreSQL in production) |

---

## Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment
```bash
cp .env.example .env
# Edit .env with your values
```

### 3. Start the server
```bash
# Development (with auto-reload)
npm run dev

# Production
npm start
```

The API runs at `http://localhost:5000`

---

## API Reference

### Auth

#### Register
```http
POST /api/auth/register
Content-Type: application/json

{
  "name": "Stanley Obi",
  "email": "stanley@example.com",
  "password": "securepassword123"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "stanley@example.com",
  "password": "securepassword123"
}
```
Returns a `token` — include it as `Authorization: Bearer <token>` on protected routes.

#### My Profile (protected)
```http
GET /api/auth/me
Authorization: Bearer <token>
```

---

### Scanning

#### Analyze a URL (public)
```http
POST /api/scan
Content-Type: application/json

{
  "url": "https://bvn-update-gtbank.xyz/login"
}
```

**Response:**
```json
{
  "success": true,
  "scan_id": 42,
  "url": "https://bvn-update-gtbank.xyz/login",
  "verdict": "scam",
  "score": 85,
  "details": {
    "signals": [
      "🔴 High-risk keywords detected: bvn-update",
      "🔶 Suspicious top-level domain: .xyz"
    ],
    "community": { "flagged": false, "report_count": 0 },
    "virustotal": null
  }
}
```

**Verdict scale:**
- `safe` — Score 0–20
- `suspicious` — Score 21–55
- `scam` — Score 56–100

#### Scan History (protected)
```http
GET /api/scan/history
Authorization: Bearer <token>
```

#### URL Lookup (public)
```http
GET /api/scan/lookup?url=https://suspicious-site.com
```

---

### Reporting

#### Submit a Report (protected)
```http
POST /api/report
Authorization: Bearer <token>
Content-Type: application/json

{
  "url": "https://palmpay-gift.online",
  "reason": "phishing",
  "description": "Fake PalmPay site asking for my PIN"
}
```

**Valid reasons:** `phishing`, `investment_scam`, `fake_ecommerce`, `malware`, `impersonation`, `other`

#### Reports for a URL (public)
```http
GET /api/report/url?url=https://palmpay-gift.online
```

#### Top Flagged URLs (public)
```http
GET /api/report/top-flagged
```

#### Pending Reports (admin only)
```http
GET /api/report/pending
Authorization: Bearer <admin-token>
```

#### Review a Report (admin only)
```http
PATCH /api/report/7
Authorization: Bearer <admin-token>
Content-Type: application/json

{ "status": "confirmed" }
```

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `PORT` | No | Server port (default: 5000) |
| `NODE_ENV` | No | `development` or `production` |
| `JWT_SECRET` | **Yes** | Secret key for signing JWTs |
| `JWT_EXPIRES_IN` | No | Token lifetime (default: `7d`) |
| `DB_PATH` | No | SQLite file path (default: `./tracesite.db`) |
| `VIRUSTOTAL_API_KEY` | No | Free key from virustotal.com — enhances accuracy |
| `CORS_ORIGINS` | No | Comma-separated allowed origins |
| `ADMIN_EMAIL` | No | This email gets admin role on register |

---

## Production Deployment

1. Set `NODE_ENV=production`
2. Use a strong random `JWT_SECRET` (e.g. `openssl rand -base64 64`)
3. Add your `VIRUSTOTAL_API_KEY` for best scan accuracy
4. Deploy to **Railway**, **Render**, **Heroku**, or a **VPS**
5. Put **Nginx** in front as a reverse proxy
6. For scale: swap SQLite → **PostgreSQL** (update `db/database.js`)

---

## Database Schema

```
users         — id, name, email, password, role, created_at
scans         — id, user_id, url, verdict, score, details, ip_address, created_at
reports       — id, user_id, url, reason, description, status, reviewed_by, created_at
flagged_urls  — id, url, report_count, confirmed, first_seen, last_reported
```

---

## Tech Stack

- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** SQLite (via better-sqlite3)
- **Auth:** JWT + bcryptjs
- **Security:** Helmet, CORS, express-rate-limit
- **Threat Intel:** Custom heuristics + VirusTotal API

---

*Built for the Nigeria 2026 Cyber-Safety Initiative. Protecting the next generation of digital Nigerians.*
