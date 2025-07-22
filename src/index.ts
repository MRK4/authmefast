// ============================================================================
// 🔐 AuthMeFast - Point d'entrée principal
// ============================================================================

// Types principaux
export {
  User,
  CreateUserData,
  LoginCredentials,
  AuthTokens,
  TokenPayload,
  AuthConfig,
  DatabaseAdapter,
  AuthError,
  AuthErrorCode,
  AuthenticatedRequest,
  MiddlewareOptions,
  ValidationResult,
  PasswordStrengthOptions,
  RequireAuth
} from './types';

// Services principaux
export { AuthService } from './core/auth';
export { PasswordService } from './core/password';
export { JWTService } from './core/jwt';

// Import des types pour utilisation interne
import { DatabaseAdapter, AuthConfig } from './types';
import { AuthService } from './core/auth';
import { JWTService } from './core/jwt';
import { ExpressAuthMiddleware } from './middleware/express';
import { MemoryDatabaseAdapter } from './adapters/memory';

// Adaptateurs de base de données
export { BaseDatabaseAdapter } from './adapters/base';
export { MemoryDatabaseAdapter } from './adapters/memory';

// Middleware
export {
  ExpressAuthMiddleware,
  AuthMiddlewareOptions,
  createAuthMiddleware,
  requireAuth,
  optionalAuth,
  requireRoles
} from './middleware/express';

// Utilitaires
export {
  validateEmail,
  validatePassword,
  sanitizeEmail,
  isStrongPassword,
  validateUserId
} from './utils/validation';

// ============================================================================
// Fonction utilitaire principale pour créer rapidement AuthMeFast
// ============================================================================

export interface AuthMeFastOptions {
  adapter: DatabaseAdapter;
  config: AuthConfig;
}

export class AuthMeFast {
  public readonly authService: AuthService;
  public readonly adapter: DatabaseAdapter;
  
  constructor({ adapter, config }: AuthMeFastOptions) {
    this.adapter = adapter;
    this.authService = new AuthService(adapter, config);
  }

  /**
   * Initialise la connexion à la base de données
   */
  async initialize(): Promise<void> {
    await this.adapter.connect();
  }

  /**
   * Ferme proprement les connexions
   */
  async close(): Promise<void> {
    await this.adapter.disconnect();
  }

  /**
   * Nettoie les données expirées
   */
  async cleanup(): Promise<void> {
    await this.adapter.cleanup();
  }

  /**
   * Crée un middleware Express
   */
  createExpressMiddleware(): ExpressAuthMiddleware {
    return new ExpressAuthMiddleware(this.authService);
  }

  /**
   * Obtient les statistiques de l'adaptateur
   */
  async getStats(): Promise<ReturnType<DatabaseAdapter['getStats']>> {
    return await this.adapter.getStats();
  }
}

/**
 * Fonction factory pour créer rapidement une instance AuthMeFast
 */
export function createAuthMeFast(options: AuthMeFastOptions): AuthMeFast {
  return new AuthMeFast(options);
}

// ============================================================================
// Configuration par défaut et helpers
// ============================================================================

/**
 * Crée une configuration par défaut sécurisée
 */
export function createDefaultConfig(jwtSecret?: string): AuthConfig {
  return {
    jwtSecret: jwtSecret || JWTService.generateSecret(64),
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d',
    bcryptRounds: 12,
    issuer: 'AuthMeFast',
    audience: 'web-app',
    rateLimiting: {
      maxAttempts: 5,
      windowMs: 15 * 60 * 1000, // 15 minutes
      blockDurationMs: 60 * 60 * 1000 // 1 heure
    }
  };
}

/**
 * Crée rapidement une instance en mémoire pour le développement
 */
export async function createDevelopmentAuth(jwtSecret?: string): Promise<AuthMeFast> {
  const adapter = new MemoryDatabaseAdapter();
  const config = createDefaultConfig(jwtSecret);
  
  const authMeFast = new AuthMeFast({ adapter, config });
  await authMeFast.initialize();
  
  return authMeFast;
}

// ============================================================================
// Version du package
// ============================================================================

export const VERSION = '1.0.0'; 