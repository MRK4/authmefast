// ============================================================================
// Types de base pour AuthMeFast
// ============================================================================

export interface User {
  readonly id: string;
  readonly email: string;
  readonly passwordHash: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly isActive: boolean;
  readonly metadata: Record<string, unknown>;
}

export interface CreateUserData {
  readonly email: string;
  readonly password: string;
  readonly metadata?: Record<string, unknown>;
}

export interface AuthTokens {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresIn: number;
  readonly tokenType: 'Bearer';
}

export interface TokenPayload {
  readonly sub: string; // User ID
  readonly email: string;
  readonly iat: number;
  readonly exp: number;
  readonly type: 'access' | 'refresh';
}

export interface AuthConfig {
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

export interface LoginCredentials {
  readonly email: string;
  readonly password: string;
}

export interface PasswordResetRequest {
  readonly email: string;
}

export interface PasswordReset {
  readonly token: string;
  readonly newPassword: string;
}

// ============================================================================
// Interfaces pour les adaptateurs de base de données
// ============================================================================

export interface DatabaseAdapter {
  // Gestion des utilisateurs
  createUser(userData: Omit<User, 'id' | 'createdAt' | 'updatedAt'>): Promise<User>;
  findUserByEmail(email: string): Promise<User | null>;
  findUserById(id: string): Promise<User | null>;
  updateUser(id: string, updates: Partial<Omit<User, 'id' | 'createdAt'>>): Promise<User>;
  deleteUser(id: string): Promise<void>;

  // Sessions et tokens de rafraîchissement
  storeRefreshToken(userId: string, token: string, expiresAt: Date): Promise<void>;
  validateRefreshToken(token: string): Promise<string | null>;
  revokeRefreshToken(token: string): Promise<void>;
  revokeAllUserTokens(userId: string): Promise<void>;

  // Limitation de taux (optionnel)
  incrementLoginAttempts?(email: string): Promise<number>;
  resetLoginAttempts?(email: string): Promise<void>;
  isRateLimited?(email: string): Promise<boolean>;

  // Méthodes de cycle de vie
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  cleanup(): Promise<void>;
  getStats(): Promise<{
    isConnected: boolean;
    name: string;
    userCount?: number;
    activeTokens?: number;
    [key: string]: unknown;
  }>;
}

// ============================================================================
// Types pour les erreurs
// ============================================================================

export enum AuthErrorCode {
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

export class AuthError extends Error {
  public readonly code: AuthErrorCode;
  public readonly statusCode: number;

  constructor(code: AuthErrorCode, message: string, statusCode: number = 400) {
    super(message);
    this.name = 'AuthError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

// ============================================================================
// Types pour les middleware
// ============================================================================

export interface AuthenticatedRequest<T = Record<string, unknown>> {
  user: User;
  token: string;
  body?: T;
  params?: Record<string, string>;
  query?: Record<string, string>;
}

export interface MiddlewareOptions {
  readonly optional?: boolean; // Ne pas échouer si pas de token
  readonly skipInactive?: boolean; // Autoriser les utilisateurs inactifs
}

// ============================================================================
// Types utilitaires
// ============================================================================

export type RequireAuth<T> = T & { user: User };

export interface ValidationResult {
  readonly isValid: boolean;
  readonly errors: string[];
}

export interface PasswordStrengthOptions {
  readonly minLength?: number;
  readonly requireUppercase?: boolean;
  readonly requireLowercase?: boolean;
  readonly requireNumbers?: boolean;
  readonly requireSpecialChars?: boolean;
} 