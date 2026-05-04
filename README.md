# Secure Auth System — Backend

REST API for user authentication built with Node.js, Express, JWT, and SQLite.

Part of a full-stack project — see the [React frontend](https://github.com/rrobertf/auth-app-frontend).

---

## Stack

- **Node.js** + Express 5
- **SQLite** via better-sqlite3
- **JWT** (jsonwebtoken) — 7-day token expiry
- **bcryptjs** — password hashing with salt rounds
- **dotenv** for environment config

## Setup

```bash
npm install
```

Create a `.env` file:

```
JWT_SECRET=your_secret_here
PORT=5001
```

Start the server:

```bash
npm run dev   # development (nodemon)
npm start     # production
```

Server runs on `http://localhost:5001`

## API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/api/auth/register` | Register a new user |
| `POST` | `/api/auth/login` | Login and receive JWT |
| `GET` | `/api/auth/me` | Verify token |
| `GET` | `/api/auth/profile` | Get full user profile |
| `POST` | `/api/auth/logout` | Logout (client-side token removal) |

Protected routes require:
```
Authorization: Bearer <token>
```

## Database

SQLite — auto-created on first run as `auth.db`.

```sql
users (id, username, email, password, role, created_at)
```

## Author

**Roberto Feliciano** · CS Student · UIPR Ponce  
[github.com/rrobertf](https://github.com/rrobertf)
