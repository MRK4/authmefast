# 📚 AuthMeFast - Documentation API

## Table des matières

1. [Services principaux](#services-principaux)
2. [Types et interfaces](#types-et-interfaces)
3. [Adaptateurs](#adaptateurs)
4. [Middleware](#middleware)
5. [Utilitaires](#utilitaires)
6. [Gestion d'erreurs](#gestion-derreurs)

## Services principaux

### AuthService

Le service principal d'authentification.

#### Constructeur

```typescript
constructor(adapter: DatabaseAdapter, config: AuthConfig)
```

#### Méthodes

##### `register(userData: CreateUserData): Promise<{ user: User; tokens: AuthTokens }>`

Inscrit un nouvel utilisateur.

```typescript
const result = await authService.register({
  email: 'user@example.com',
  password: 'SecurePassword123!',
  metadata: { role: 'user' }
});
```

##### `login(credentials: LoginCredentials): Promise<{ user: User; tokens: AuthTokens }>`

Connecte un utilisateur existant.

```typescript
const result = await authService.login({
  email: 'user@example.com',
  password: 'SecurePassword123!'
});
```

##### `verifyToken(accessToken: string): Promise<User>`

Vérifie un token d'accès et retourne l'utilisateur.

```typescript
const user = await authService.verifyToken(accessToken);
```

##### `refreshToken(refreshToken: string): Promise<AuthTokens>`

Génère de nouveaux tokens à partir d'un refresh token.

```typescript
const newTokens = await authService.refreshToken(refreshToken);
```

##### `changePassword(userId: string, oldPassword: string, newPassword: string): Promise<void>`

Change le mot de passe d'un utilisateur.

```typescript
await authService.changePassword(userId, 'oldPass', 'NewSecurePass123!');
```

### PasswordService

Service de gestion des mots de passe avec bcrypt.

#### Constructeur

```typescript
constructor(rounds: number = 12)
```

#### Méthodes

##### `hashPassword(password: string): Promise<string>`

Hache un mot de passe.

```typescript
const hash = await passwordService.hashPassword('myPassword');
```

##### `verifyPassword(password: string, hash: string): Promise<boolean>`

Vérifie un mot de passe contre son hash.

```typescript
const isValid = await passwordService.verifyPassword('myPassword', hash);
```

##### `assessPasswordStrength(password: string)`

Évalue la force d'un mot de passe.

```typescript
const assessment = passwordService.assessPasswordStrength('myPassword');
// { score: 65, level: 'Moyen', suggestions: [...] }
```

### JWTService

Service de gestion des JWT.

#### Constructeur

```typescript
constructor(config: AuthConfig)
```

#### Méthodes

##### `generateTokens(userId: string, email: string): Promise<AuthTokens>`

Génère une paire de tokens (access + refresh).

##### `verifyToken(token: string, expectedType?: 'access' | 'refresh'): Promise<TokenPayload>`

Vérifie et décode un JWT.

##### `extractTokenFromHeader(authHeader: string | undefined): string | null`

Extrait un token du header Authorization.

## Types et interfaces

### User

```typescript
interface User {
  readonly id: string;
  readonly email: string;
  readonly passwordHash: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly isActive: boolean;
  readonly metadata?: Record<string, unknown>;
}
```

### AuthConfig

```typescript
interface AuthConfig {
  readonly jwtSecret: string;
  readonly accessTokenExpiry?: string; // Default: '15m'
  readonly refreshTokenExpiry?: string; // Default: '7d'
  readonly bcryptRounds?: number; // Default: 12
  readonly issuer?: string;
  readonly audience?: string;
  readonly rateLimiting?: {
    readonly maxAttempts: number;
    readonly windowMs: number;
    readonly blockDurationMs: number;
  };
}
```

### AuthTokens

```typescript
interface AuthTokens {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresIn: number;
  readonly tokenType: 'Bearer';
}
```

### AuthError

```typescript
class AuthError extends Error {
  public readonly code: AuthErrorCode;
  public readonly statusCode: number;

  constructor(code: AuthErrorCode, message: string, statusCode?: number);
}
```

### AuthErrorCode

```typescript
enum AuthErrorCode {
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  USER_NOT_FOUND = 'USER_NOT_FOUND',
  EMAIL_ALREADY_EXISTS = 'EMAIL_ALREADY_EXISTS',
  INVALID_TOKEN = 'INVALID_TOKEN',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  INSUFFICIENT_PERMISSIONS = 'INSUFFICIENT_PERMISSIONS',
  RATE_LIMITED = 'RATE_LIMITED',
  WEAK_PASSWORD = 'WEAK_PASSWORD',
  INVALID_EMAIL = 'INVALID_EMAIL',
  USER_INACTIVE = 'USER_INACTIVE'
}
```

## Adaptateurs

### DatabaseAdapter

Interface de base pour tous les adaptateurs.

```typescript
interface DatabaseAdapter {
  // Gestion des utilisateurs
  createUser(userData: Omit<User, 'id' | 'createdAt' | 'updatedAt'>): Promise<User>;
  findUserByEmail(email: string): Promise<User | null>;
  findUserById(id: string): Promise<User | null>;
  updateUser(id: string, updates: Partial<Omit<User, 'id' | 'createdAt'>>): Promise<User>;
  deleteUser(id: string): Promise<void>;
  
  // Sessions et tokens
  storeRefreshToken(userId: string, token: string, expiresAt: Date): Promise<void>;
  validateRefreshToken(token: string): Promise<string | null>;
  revokeRefreshToken(token: string): Promise<void>;
  revokeAllUserTokens(userId: string): Promise<void>;
  
  // Rate limiting (optionnel)
  incrementLoginAttempts?(email: string): Promise<number>;
  resetLoginAttempts?(email: string): Promise<void>;
  isRateLimited?(email: string): Promise<boolean>;
}
```

### MemoryDatabaseAdapter

Adaptateur en mémoire pour le développement et les tests.

```typescript
const adapter = new MemoryDatabaseAdapter();
await adapter.connect();

// Méthodes spécifiques
const users = await adapter.getAllUsers(); // Dev/test uniquement
await adapter.reset(); // Vide toutes les données
```

### BaseDatabaseAdapter

Classe abstraite pour créer vos propres adaptateurs.

```typescript
class CustomAdapter extends BaseDatabaseAdapter {
  readonly name = 'CustomAdapter';
  
  // Implémentez les méthodes abstraites
  async connect() { /* ... */ }
  async createUser() { /* ... */ }
  // ...
}
```

## Middleware

### ExpressAuthMiddleware

Middleware pour Express.

#### Méthodes

##### `authenticate(options?: AuthMiddlewareOptions)`

Middleware d'authentification principal.

```typescript
const authMiddleware = new ExpressAuthMiddleware(authService);

// Authentification requise
app.use('/api/protected', authMiddleware.authenticate());

// Authentification optionnelle  
app.use('/api/public', authMiddleware.authenticate({ optional: true }));
```

##### `requireRoles(roles: string[])`

Middleware de vérification de rôles.

```typescript
app.use('/admin', authMiddleware.requireRoles(['admin']));
```

##### `requireOwnership(getUserIdFromParams)`

Middleware de vérification de propriété de ressource.

```typescript
app.use('/user/:id', authMiddleware.requireOwnership(req => req.params.id));
```

##### `rateLimiter(options)`

Middleware de rate limiting personnalisé.

```typescript
const limiter = authMiddleware.rateLimiter({
  windowMs: 15 * 60 * 1000,
  maxRequests: 100
});
```

### Fonctions utilitaires

```typescript
// Middleware simple
const authRequired = requireAuth(authService);
const authOptional = optionalAuth(authService);
const adminOnly = requireRoles(authService, ['admin']);

app.get('/profile', authRequired, handler);
app.get('/public', authOptional, handler);
app.get('/admin', adminOnly, handler);
```

## Utilitaires

### Validation

```typescript
// Validation d'email
const emailValidation = validateEmail('user@example.com');
// { isValid: true, errors: [] }

// Validation de mot de passe
const passwordValidation = validatePassword('MyPassword123!');
// { isValid: true, errors: [] }

// Nettoyage d'email
const cleanEmail = sanitizeEmail('  User@EXAMPLE.COM  ');
// 'user@example.com'

// Test de force de mot de passe
const isStrong = isStrongPassword('VeryStrongPassword123!@#');
// true
```

## Gestion d'erreurs

### Types d'erreurs

AuthMeFast utilise une classe `AuthError` personnalisée avec des codes spécifiques :

```typescript
try {
  await authService.login(credentials);
} catch (error) {
  if (error instanceof AuthError) {
    switch (error.code) {
      case AuthErrorCode.INVALID_CREDENTIALS:
        res.status(401).json({ message: 'Identifiants invalides' });
        break;
      case AuthErrorCode.RATE_LIMITED:
        res.status(429).json({ message: 'Trop de tentatives' });
        break;
      case AuthErrorCode.USER_INACTIVE:
        res.status(403).json({ message: 'Compte désactivé' });
        break;
      default:
        res.status(error.statusCode).json({ message: error.message });
    }
  }
}
```

### Codes d'erreur courants

| Code | Status | Description |
|------|--------|-------------|
| `INVALID_CREDENTIALS` | 401 | Email/mot de passe incorrect |
| `USER_NOT_FOUND` | 404 | Utilisateur introuvable |
| `EMAIL_ALREADY_EXISTS` | 409 | Email déjà utilisé |
| `INVALID_TOKEN` | 401 | Token JWT invalide |
| `TOKEN_EXPIRED` | 401 | Token JWT expiré |
| `RATE_LIMITED` | 429 | Trop de tentatives |
| `WEAK_PASSWORD` | 400 | Mot de passe faible |
| `USER_INACTIVE` | 403 | Compte désactivé |

### Bonnes pratiques

1. **Toujours vérifier le type d'erreur** avant de la traiter
2. **Ne pas exposer d'informations sensibles** dans les messages d'erreur
3. **Logger les erreurs côté serveur** pour le débogage
4. **Utiliser les codes de statut HTTP appropriés**

```typescript
// Middleware de gestion d'erreurs Express
app.use((error, req, res, next) => {
  if (error instanceof AuthError) {
    console.error(`Auth Error [${error.code}]:`, error.message);
    
    res.status(error.statusCode).json({
      error: {
        code: error.code,
        message: error.message
      }
    });
  } else {
    console.error('Unexpected error:', error);
    res.status(500).json({
      error: { message: 'Erreur serveur interne' }
    });
  }
});
``` 