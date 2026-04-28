# SecureAuth - Backend

Full-Stack Authentication System with JWT, bcrypt, and SQLite

## 🎯 Features

- ✅ User Registration & Login
- ✅ Password Hashing (bcrypt)
- ✅ JWT Token Authentication
- ✅ SQLite Database
- ✅ CORS Support
- ✅ Production Ready

## 🛠 Tech Stack

- Node.js + Express
- SQLite
- JWT (jsonwebtoken)
- bcryptjs
- CORS

## 📦 Installation

```bash
npm install
npm run dev
```

Server runs on `http://localhost:5001`

## 🔌 API Endpoints

- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `GET /api/auth/me` - Get user profile
- `POST /api/auth/logout` - Logout user

## ⚙️ Environment Variables

Create `.env`: