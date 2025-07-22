import * as jwt from 'jsonwebtoken';
import { nanoid } from 'nanoid';
import { TokenPayload, AuthTokens, AuthConfig, AuthError, AuthErrorCode } from '../types';

// ============================================================================
// Service de gestion des JWT
// ============================================================================

export class JWTService {
  private readonly secret: string;
  private readonly accessTokenExpiry: string;
  private readonly refreshTokenExpiry: string;
  private readonly issuer?: string;
  private readonly audience?: string;

  constructor(config: AuthConfig) {
    if (!config.jwtSecret || config.jwtSecret.length < 32) {
      throw new Error('Le secret JWT doit faire au moins 32 caractères pour une sécurité optimale');
    }

    this.secret = config.jwtSecret;
    this.accessTokenExpiry = config.accessTokenExpiry || '15m';
    this.refreshTokenExpiry = config.refreshTokenExpiry || '7d';
    this.issuer = config.issuer ?? '';
    this.audience = config.audience ?? '';
  }

  /**
   * Génère une paire de tokens (accès + rafraîchissement)
   */
  async generateTokens(userId: string, email: string): Promise<AuthTokens> {
    try {
      const jti = nanoid(); // Unique token identifier
      
      const accessTokenPayload: Omit<TokenPayload, 'iat' | 'exp'> = {
        sub: userId,
        email,
        type: 'access'
      };

      const refreshTokenPayload: Omit<TokenPayload, 'iat' | 'exp'> = {
        sub: userId,
        email,
        type: 'refresh'
      };

      const accessToken = jwt.sign(accessTokenPayload, this.secret as string, {
        expiresIn: this.accessTokenExpiry,
        issuer: this.issuer,
        audience: this.audience,
        jwtid: jti,
        algorithm: 'HS256'
      } as jwt.SignOptions);

      const refreshToken = jwt.sign(refreshTokenPayload, this.secret as string, {
        expiresIn: this.refreshTokenExpiry,
        issuer: this.issuer,
        audience: this.audience,
        jwtid: nanoid(),
        algorithm: 'HS256'
      } as jwt.SignOptions);

      // Calculer le temps d'expiration en secondes
      const decoded = jwt.decode(accessToken) as TokenPayload;
      const expiresIn = decoded.exp - Math.floor(Date.now() / 1000);

      return {
        accessToken,
        refreshToken,
        expiresIn,
        tokenType: 'Bearer'
      };
    } catch (error) {
      throw new AuthError(
        AuthErrorCode.INVALID_TOKEN,
        'Erreur lors de la génération des tokens',
        500
      );
    }
  }

  /**
   * Vérifie et décode un token JWT
   */
  async verifyToken(token: string, expectedType: 'access' | 'refresh' = 'access'): Promise<TokenPayload> {
    try {
      const decoded = jwt.verify(token, this.secret, {
        issuer: this.issuer,
        audience: this.audience,
        algorithms: ['HS256']
      }) as TokenPayload;

      // Vérifier le type de token
      if (decoded.type !== expectedType) {
        throw new AuthError(
          AuthErrorCode.INVALID_TOKEN,
          `Type de token invalide. Attendu: ${expectedType}, reçu: ${decoded.type}`,
          401
        );
      }

      return decoded;
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }

      if (error instanceof jwt.JsonWebTokenError) {
        if (error.name === 'TokenExpiredError') {
          throw new AuthError(
            AuthErrorCode.TOKEN_EXPIRED,
            'Le token a expiré',
            401
          );
        }
        
        throw new AuthError(
          AuthErrorCode.INVALID_TOKEN,
          'Token invalide',
          401
        );
      }

      throw new AuthError(
        AuthErrorCode.INVALID_TOKEN,
        'Erreur lors de la vérification du token',
        500
      );
    }
  }

  /**
   * Décode un token sans vérification (pour inspection)
   */
  decodeToken(token: string): TokenPayload | null {
    try {
      return jwt.decode(token) as TokenPayload;
    } catch {
      return null;
    }
  }

  /**
   * Vérifie si un token est expiré sans le valider
   */
  isTokenExpired(token: string): boolean {
    try {
      const decoded = this.decodeToken(token);
      if (!decoded) return true;
      
      return decoded.exp < Math.floor(Date.now() / 1000);
    } catch {
      return true;
    }
  }

  /**
   * Extrait le token du header Authorization
   */
  extractTokenFromHeader(authHeader: string | undefined): string | null {
    if (!authHeader) return null;
    
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') return null;
    
    return typeof parts[1] === 'string' ? parts[1] : null;
  }

  /**
   * Génère un token de réinitialisation de mot de passe
   */
  async generatePasswordResetToken(userId: string, email: string): Promise<string> {
    try {
      const payload = {
        sub: userId,
        email,
        type: 'password_reset',
        purpose: 'reset_password'
      };

      return jwt.sign(payload, this.secret, {
        expiresIn: '1h', // Les tokens de reset expirent rapidement
        issuer: this.issuer,
        audience: this.audience,
        jwtid: nanoid(),
        algorithm: 'HS256'
      });
    } catch (error) {
      throw new AuthError(
        AuthErrorCode.INVALID_TOKEN,
        'Erreur lors de la génération du token de réinitialisation',
        500
      );
    }
  }

  /**
   * Vérifie un token de réinitialisation de mot de passe
   */
  async verifyPasswordResetToken(token: string): Promise<{ userId: string; email: string }> {
    try {
      const decoded = jwt.verify(token, this.secret, {
        issuer: this.issuer,
        audience: this.audience,
        algorithms: ['HS256']
      }) as any;

      if (decoded.type !== 'password_reset' || decoded.purpose !== 'reset_password') {
        throw new AuthError(
          AuthErrorCode.INVALID_TOKEN,
          'Token de réinitialisation invalide',
          401
        );
      }

      return {
        userId: decoded.sub,
        email: decoded.email
      };
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }

      if (error instanceof jwt.JsonWebTokenError) {
        throw new AuthError(
          AuthErrorCode.INVALID_TOKEN,
          'Token de réinitialisation invalide ou expiré',
          401
        );
      }

      throw new AuthError(
        AuthErrorCode.INVALID_TOKEN,
        'Erreur lors de la vérification du token de réinitialisation',
        500
      );
    }
  }

  /**
   * Crée un token sécurisé pour la vérification d'email
   */
  async generateEmailVerificationToken(userId: string, email: string): Promise<string> {
    try {
      const payload = {
        sub: userId,
        email,
        type: 'email_verification',
        purpose: 'verify_email'
      };

      return jwt.sign(payload, this.secret, {
        expiresIn: '24h',
        issuer: this.issuer,
        audience: this.audience,
        jwtid: nanoid(),
        algorithm: 'HS256'
      });
    } catch (error) {
      throw new AuthError(
        AuthErrorCode.INVALID_TOKEN,
        'Erreur lors de la génération du token de vérification email',
        500
      );
    }
  }

  /**
   * Calcule le temps restant avant expiration (en secondes)
   */
  getTimeToExpiry(token: string): number {
    const decoded = this.decodeToken(token);
    if (!decoded) return 0;
    
    const now = Math.floor(Date.now() / 1000);
    return Math.max(0, decoded.exp - now);
  }

  /**
   * Génère un secret JWT sécurisé (utilitaire)
   */
  static generateSecret(length: number = 64): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    let result = '';
    
    for (let i = 0; i < length; i++) {
      result += chars[Math.floor(Math.random() * chars.length)];
    }
    
    return result;
  }
} 