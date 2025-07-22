import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../core/auth';
import { AuthError, AuthErrorCode, User, MiddlewareOptions } from '../types';

// ============================================================================
// Interfaces pour Express
// ============================================================================

export interface AuthenticatedRequest extends Request {
  user: User;
  token: string;
}

export interface AuthMiddlewareOptions extends MiddlewareOptions {
  skipRoutes?: string[]; // Routes à ignorer
  extractToken?: (req: Request) => string | null; // Fonction personnalisée d'extraction de token
}

// ============================================================================
// Middleware d'authentification Express
// ============================================================================

export class ExpressAuthMiddleware {
  private readonly authService: AuthService;

  constructor(authService: AuthService) {
    this.authService = authService;
  }

  /**
   * Middleware principal d'authentification
   */
  authenticate(options: AuthMiddlewareOptions = {}) {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        // Vérifier si la route doit être ignorée
        if (options.skipRoutes && options.skipRoutes.includes(req.path)) {
          return next();
        }

        // Extraire le token
        const token = options.extractToken
          ? options.extractToken(req)
          : this.extractTokenFromRequest(req);

        if (!token) {
          if (options.optional) {
            return next(); // Continuer sans user si optionnel
          }
          
          return this.sendErrorResponse(res, new AuthError(
            AuthErrorCode.INVALID_TOKEN,
            'Token d\'authentification requis',
            401
          ));
        }

        // Vérifier le token et récupérer l'utilisateur
        const user = await this.authService.verifyToken(token);

        // Vérifier si l'utilisateur est actif (si requis)
        if (!options.skipInactive && !user.isActive) {
          return this.sendErrorResponse(res, new AuthError(
            AuthErrorCode.USER_INACTIVE,
            'Compte utilisateur inactif',
            403
          ));
        }

        // Ajouter l'utilisateur et le token à la requête
        (req as AuthenticatedRequest).user = user;
        (req as AuthenticatedRequest).token = token;

        next();
      } catch (error) {
        if (error instanceof AuthError) {
          return this.sendErrorResponse(res, error);
        }

        return this.sendErrorResponse(res, new AuthError(
          AuthErrorCode.INVALID_TOKEN,
          'Erreur d\'authentification',
          500
        ));
      }
    };
  }

  /**
   * Middleware pour vérifier des rôles spécifiques (si implémenté dans metadata)
   */
  requireRoles(roles: string[]) {
    return (req: Request, res: Response, next: NextFunction): void => {
      const authReq = req as AuthenticatedRequest;
      
      if (!authReq.user) {
        return this.sendErrorResponse(res, new AuthError(
          AuthErrorCode.INVALID_TOKEN,
          'Authentification requise',
          401
        ));
      }

      const userRoles = authReq.user.metadata?.roles as string[] || [];
      const hasRequiredRole = roles.some(role => userRoles.includes(role));

      if (!hasRequiredRole) {
        return this.sendErrorResponse(res, new AuthError(
          AuthErrorCode.INSUFFICIENT_PERMISSIONS,
          'Permissions insuffisantes',
          403
        ));
      }

      next();
    };
  }

  /**
   * Middleware pour vérifier que l'utilisateur est propriétaire d'une ressource
   */
  requireOwnership(getUserIdFromParams: (req: Request) => string) {
    return (req: Request, res: Response, next: NextFunction): void => {
      const authReq = req as AuthenticatedRequest;
      
      if (!authReq.user) {
        return this.sendErrorResponse(res, new AuthError(
          AuthErrorCode.INVALID_TOKEN,
          'Authentification requise',
          401
        ));
      }

      const targetUserId = getUserIdFromParams(req);
      
      if (authReq.user.id !== targetUserId) {
        return this.sendErrorResponse(res, new AuthError(
          AuthErrorCode.INSUFFICIENT_PERMISSIONS,
          'Accès à la ressource non autorisé',
          403
        ));
      }

      next();
    };
  }

  /**
   * Middleware de rate limiting personnalisé
   */
  rateLimiter(options: {
    windowMs: number;
    maxRequests: number;
    keyGenerator?: (req: Request) => string;
    skipSuccessful?: boolean;
  }) {
    const requests = new Map<string, { count: number; resetTime: number }>();
    
    return (req: Request, res: Response, next: NextFunction): void => {
      const key = options.keyGenerator ? options.keyGenerator(req) : req.ip || 'unknown';
      const now = Date.now();
      const windowStart = now - options.windowMs;

      // Nettoyer les anciennes entrées
      for (const [k, v] of requests.entries()) {
        if (v.resetTime < windowStart) {
          requests.delete(k);
        }
      }

      const current = requests.get(key) || { count: 0, resetTime: now + options.windowMs };
      
      if (current.resetTime < now) {
        current.count = 0;
        current.resetTime = now + options.windowMs;
      }

      current.count++;
      requests.set(key, current);

      if (current.count > options.maxRequests) {
        return this.sendErrorResponse(res, new AuthError(
          AuthErrorCode.RATE_LIMITED,
          'Trop de requêtes. Réessayez plus tard.',
          429
        ));
      }

      // Headers informatifs
      res.set({
        'X-RateLimit-Limit': options.maxRequests.toString(),
        'X-RateLimit-Remaining': Math.max(0, options.maxRequests - current.count).toString(),
        'X-RateLimit-Reset': new Date(current.resetTime).toISOString()
      });

      next();
    };
  }

  // ========================================================================
  // Méthodes utilitaires
  // ========================================================================

  private extractTokenFromRequest(req: Request): string | null {
    // Vérifier le header Authorization
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const token = this.authService.extractTokenFromHeader(authHeader);
      if (token) return token;
    }

    // Vérifier les cookies
    const cookieToken = req.cookies?.authToken;
    if (cookieToken) return cookieToken;

    // Vérifier les query params (non recommandé pour la production)
    const queryToken = req.query.token as string;
    if (queryToken) return queryToken;

    return null;
  }

  private sendErrorResponse(res: Response, error: AuthError): void {
    res.status(error.statusCode).json({
      error: {
        code: error.code,
        message: error.message,
        statusCode: error.statusCode
      }
    });
  }
}

// ============================================================================
// Fonctions utilitaires pour créer les middleware
// ============================================================================

/**
 * Crée un middleware d'authentification Express
 */
export function createAuthMiddleware(authService: AuthService): ExpressAuthMiddleware {
  return new ExpressAuthMiddleware(authService);
}

/**
 * Middleware simple pour l'authentification (fonction)
 */
export function requireAuth(authService: AuthService, options?: MiddlewareOptions) {
  const middleware = new ExpressAuthMiddleware(authService);
  return middleware.authenticate(options);
}

/**
 * Middleware optionnel (ne bloque pas si pas de token)
 */
export function optionalAuth(authService: AuthService) {
  const middleware = new ExpressAuthMiddleware(authService);
  return middleware.authenticate({ optional: true });
}

/**
 * Middleware pour vérifier des rôles
 */
export function requireRoles(authService: AuthService, roles: string[]) {
  const middleware = new ExpressAuthMiddleware(authService);
  return [
    middleware.authenticate(),
    middleware.requireRoles(roles)
  ];
} 