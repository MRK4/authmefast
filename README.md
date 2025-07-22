# 🔐 AuthMeFast – L’authentification simple, rapide et réutilisable

[![npm version](https://img.shields.io/npm/v/authmefast?style=flat-square)](https://www.npmjs.com/package/authmefast)

> 🇬🇧 [English version available here](./README.en.md)

**AuthMeFast** est un package TypeScript conçu pour faciliter l'ajout rapide d'un système d'authentification sécurisé dans toute webapp Node.js. Il prend en charge l’inscription, la connexion, la gestion des sessions (JWT), le hash de mot de passe, et l'abstraction de la base de données via des adaptateurs.

## ✨ Fonctionnalités

- 🔒 Authentification Email / Mot de passe
- 🔑 JWT sécurisés (access / refresh)
- 🔁 Middleware de protection de routes
- 🧂 Hash des mots de passe avec bcrypt
- ⚙️ Système d’adapter pour la base de données
- 🧪 Entièrement typé avec TypeScript
- 📦 Installation simple et rapide

---

## 🚀 Installation

```bash
npm install authmefast
# ou
yarn add authmefast
```

## 🏗️ Usage de base

### Configuration Express en 3 minutes

```typescript
import express from 'express';
import { createDevelopmentAuth, requireAuth } from 'authmefast';

const app = express();
app.use(express.json());

// 1. Initialiser AuthMeFast
const authMeFast = await createDevelopmentAuth('votre-secret-jwt-super-securise');

// 2. Routes d'authentification
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await authMeFast.authService.register({ email, password });
    res.json({ user: result.user, tokens: result.tokens });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await authMeFast.authService.login({ email, password });
    res.json({ user: result.user, tokens: result.tokens });
  } catch (error) {
    res.status(401).json({ error: error.message });
  }
});

// 3. Routes protégées
app.get('/profile', requireAuth(authMeFast.authService), (req, res) => {
  res.json({ user: req.user }); // req.user est automatiquement populé
});

app.listen(3000, () => console.log('🚀 Serveur démarré !'));
```

### Configuration avancée avec MongoDB

```typescript
import { AuthMeFast, MongoDBAdapter, createDefaultConfig } from 'authmefast';

// 1. Configuration avec MongoDB
const adapter = new MongoDBAdapter({
  uri: 'mongodb://localhost:27017',
  dbName: 'myapp'
});

const config = createDefaultConfig('your-super-secure-jwt-secret');
const authMeFast = new AuthMeFast({ adapter, config });

await authMeFast.initialize();

// 2. Service disponible
const authService = authMeFast.authService;
```

## 🔧 Architecture modulaire

### Adaptateurs de base de données

**AuthMeFast** utilise un système d'adaptateurs pour supporter différentes bases de données :

```typescript
// Adaptateur en mémoire (développement/tests)
import { MemoryDatabaseAdapter } from 'authmefast';
const memoryAdapter = new MemoryDatabaseAdapter();

// Adaptateur MongoDB (production)
import { MongoDBAdapter } from 'authmefast';
const mongoAdapter = new MongoDBAdapter({
  uri: 'mongodb://localhost:27017',
  dbName: 'production'
});

// Créer votre propre adaptateur
class PostgreSQLAdapter extends BaseDatabaseAdapter {
  // Implémentation personnalisée...
}
```

### Configuration sécurisée

```typescript
import { createDefaultConfig, AuthConfig } from 'authmefast';

const config: AuthConfig = {
  jwtSecret: 'your-256-bit-secret-key-here', // OBLIGATOIRE
  accessTokenExpiry: '15m',      // Durée de vie access token
  refreshTokenExpiry: '7d',      // Durée de vie refresh token  
  bcryptRounds: 12,              // Rounds bcrypt (10-15)
  issuer: 'monapp.com',          // Émetteur JWT
  audience: 'web-app',           // Audience JWT
  rateLimiting: {
    maxAttempts: 5,              // Max tentatives connexion
    windowMs: 15 * 60 * 1000,    // Fenêtre de temps
    blockDurationMs: 60 * 60 * 1000 // Durée blocage
  }
};
```

## 🛡️ Middleware et protection

### Protection de routes Express

```typescript
import { requireAuth, optionalAuth, requireRoles } from 'authmefast';

// Authentification obligatoire
app.get('/profile', requireAuth(authService), (req, res) => {
  console.log(req.user); // Utilisateur authentifié
});

// Authentification optionnelle
app.get('/public', optionalAuth(authService), (req, res) => {
  if (req.user) {
    res.json({ message: `Bonjour ${req.user.email}` });
  } else {
    res.json({ message: 'Contenu public' });
  }
});

// Vérification de rôles
app.get('/admin', requireRoles(authService, ['admin']), (req, res) => {
  res.json({ message: 'Zone admin' });
});
```

### Middleware personnalisé

```typescript
import { ExpressAuthMiddleware } from 'authmefast';

const authMiddleware = new ExpressAuthMiddleware(authService);

// Middleware avec options personnalisées
const customAuth = authMiddleware.authenticate({
  optional: true,
  skipInactive: false,
  skipRoutes: ['/health', '/metrics'],
  extractToken: (req) => req.headers['x-auth-token'] // Token custom
});
```

## ⚡ Fonctionnalités avancées

### Rate limiting intelligent

```typescript
// Rate limiting automatique intégré
const result = await authService.login(credentials); // Rate limited automatiquement

// Rate limiting personnalisé
const rateLimiter = authMiddleware.rateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 100,         // 100 requêtes max
  keyGenerator: (req) => req.ip + req.user?.id // Clé personnalisée
});

app.use('/api', rateLimiter);
```

### Évaluation force des mots de passe

```typescript
const strength = authService.assessPasswordStrength('MonMotDePasse123!');
console.log(strength);
// {
//   score: 85,
//   level: 'Fort',
//   suggestions: ['Utilisez plus de 16 caractères pour une sécurité maximale']
// }
```

### Gestion avancée des tokens

```typescript
// Rafraîchissement de tokens
const newTokens = await authService.refreshToken(oldRefreshToken);

// Vérification de token
const user = await authService.verifyToken(accessToken);

// Révocation de tous les tokens d'un utilisateur
await authService.logoutAll(userId);

// Génération de tokens spéciaux
const resetToken = await jwtService.generatePasswordResetToken(userId, email);
const verifyToken = await jwtService.generateEmailVerificationToken(userId, email);
```

## 🧪 Tests et qualité

### Tests unitaires intégrés

```bash
# Lancer les tests
npm test

# Tests avec couverture
npm run test:coverage

# Tests en mode watch
npm run test:watch
```

### Exemple de test

```typescript
import { AuthService, MemoryDatabaseAdapter, createDefaultConfig } from 'authmefast';

describe('AuthService', () => {
  let authService: AuthService;
  
  beforeEach(async () => {
    const adapter = new MemoryDatabaseAdapter();
    await adapter.connect();
    const config = createDefaultConfig('test-secret');
    authService = new AuthService(adapter, config);
  });

  test('should register user successfully', async () => {
    const result = await authService.register({
      email: 'test@example.com',
      password: 'TestPassword123!'
    });
    
    expect(result.user.email).toBe('test@example.com');
    expect(result.tokens.accessToken).toBeDefined();
  });
});
```

## 📊 Monitoring et diagnostics

### Statistiques en temps réel

```typescript
// Obtenir les statistiques
const stats = await authMeFast.getStats();
console.log(stats);
// {
//   isConnected: true,
//   name: 'MongoDBAdapter',
//   userCount: 1547,
//   activeTokens: 892,
//   database: 'production'
// }

// Nettoyage automatique
await authMeFast.cleanup(); // Supprime tokens expirés, tentatives anciennes
```

## 🔐 Sécurité et bonnes pratiques

### Points clés de sécurité

- ✅ **Mots de passe** hachés avec bcrypt (rounds configurables)
- ✅ **JWT sécurisés** avec algorithme HS256
- ✅ **Rate limiting** contre attaques brute force
- ✅ **Validation stricte** des emails et mots de passe
- ✅ **Tokens de rafraîchissement** avec rotation
- ✅ **Sessions révocables** côté serveur
- ✅ **Headers sécurisés** et CORS configurables

### Configuration production

```typescript
const productionConfig = {
  jwtSecret: process.env.JWT_SECRET, // Variable d'environnement
  accessTokenExpiry: '10m',          // Tokens courts en production
  refreshTokenExpiry: '7d',
  bcryptRounds: 14,                  // Plus de rounds en production
  rateLimiting: {
    maxAttempts: 3,                  // Plus strict
    windowMs: 10 * 60 * 1000,        // 10 minutes
    blockDurationMs: 2 * 60 * 60 * 1000 // 2 heures
  }
};
```

## 📚 Exemples complets

Consultez le dossier `examples/` pour des implémentations complètes :

- **[Express basique](examples/express-basic.js)** - API REST complète
- **[MongoDB adapter](examples/mongodb-adapter.ts)** - Adaptateur production
- **[Tests API](examples/test-api.js)** - Tests d'intégration

## 🚀 Déploiement

### Variables d'environnement

```bash
# Production
JWT_SECRET=your-super-secure-256-bit-secret-key
NODE_ENV=production
DATABASE_URL=mongodb://user:pass@host:port/database

# Développement
JWT_SECRET=dev-secret-key-at-least-32-chars
NODE_ENV=development

```
