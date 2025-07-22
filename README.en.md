# 🔐 AuthMeFast – Simple, Fast & Reusable Authentication

[![npm version](https://img.shields.io/npm/v/authmefast?style=flat-square)](https://www.npmjs.com/package/authmefast)

> 🇫🇷 [Version française ici](./README.md)

**AuthMeFast** is a professional TypeScript package to quickly add secure authentication to any Node.js webapp. It supports registration, login, JWT session management, password hashing, and database abstraction via adapters.

---

## 🚀 Installation

```bash
npm install authmefast
# or
yarn add authmefast
```

## ⚡ Quick Start (Express)

```typescript
import express from 'express';
import { createDevelopmentAuth, requireAuth } from 'authmefast';

const app = express();
app.use(express.json());

const authMeFast = await createDevelopmentAuth('your-super-secure-jwt-secret-key-32chars');

app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;
  const result = await authMeFast.authService.register({ email, password });
  res.json(result);
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const result = await authMeFast.authService.login({ email, password });
  res.json(result);
});

app.get('/profile', requireAuth(authMeFast.authService), (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000, () => console.log('🚀 Server started!'));
```

## ✨ Features
- 🔒 Email/Password authentication
- 🔑 Secure JWT (access/refresh)
- 🔁 Route protection middleware (Express/Fastify)
- 🧂 Password hashing with bcrypt
- ⚙️ Database adapter system (Memory, MongoDB, ...)
- 🧪 Fully typed with TypeScript
- 🚫 Built-in rate limiting
- 📊 Monitoring & stats
- 📚 Simple, modern API

## 🛡️ Security Best Practices
- Passwords hashed with bcrypt (configurable rounds)
- JWT signed with HS256
- Rate limiting against brute force
- Strict email/password validation
- Refresh token rotation & revocation
- Secure headers & CORS ready

## 📦 Modular Architecture
- Easily swap database adapters (Memory, MongoDB, ...)
- Add your own adapter by extending `BaseDatabaseAdapter`
- Use with Express, Fastify, or any Node.js framework

## 📚 Documentation
- [Full API documentation (fr)](./docs/API.md)
- [Examples folder](./examples/)

## 📝 License
MIT

---

> For French documentation, see [README.md](./README.md) 