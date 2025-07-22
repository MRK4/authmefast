import { nanoid } from 'nanoid';
import {
  User,
  CreateUserData,
  LoginCredentials,
  AuthTokens,
  AuthConfig,
  DatabaseAdapter,
  AuthError,
  AuthErrorCode
} from '../types';
import { validateEmail, validatePassword, sanitizeEmail } from '../utils/validation';
import { PasswordService } from './password';
import { JWTService } from './jwt';

// ============================================================================
// Service d'authentification principal
// ============================================================================

export class AuthService {
  private readonly adapter: DatabaseAdapter;
  private readonly passwordService: PasswordService;
  private readonly jwtService: JWTService;
  private readonly config: AuthConfig;

  constructor(adapter: DatabaseAdapter, config: AuthConfig) {
    this.adapter = adapter;
    this.config = config;
    this.passwordService = new PasswordService(config.bcryptRounds);
    this.jwtService = new JWTService(config);
  }

  // ========================================================================
  // Inscription d'utilisateur
  // ========================================================================

  async register(userData: CreateUserData): Promise<{ user: User; tokens: AuthTokens }> {
    try {
      const { email, password, metadata } = userData;
      
      // Validation des données
      const emailValidation = validateEmail(email);
      if (!emailValidation.isValid) {
        throw new AuthError(
          AuthErrorCode.INVALID_EMAIL,
          emailValidation.errors.join(', '),
          400
        );
      }

      const passwordValidation = validatePassword(password);
      if (!passwordValidation.isValid) {
        throw new AuthError(
          AuthErrorCode.WEAK_PASSWORD,
          passwordValidation.errors.join(', '),
          400
        );
      }

      const sanitizedEmail = sanitizeEmail(email);

      // Vérifier si l'utilisateur existe déjà
      const existingUser = await this.adapter.findUserByEmail(sanitizedEmail);
      if (existingUser) {
        throw new AuthError(
          AuthErrorCode.EMAIL_ALREADY_EXISTS,
          'Un compte avec cet email existe déjà',
          409
        );
      }

      // Hacher le mot de passe
      const passwordHash = await this.passwordService.hashPassword(password);

      // Créer l'utilisateur
      const newUser = await this.adapter.createUser({
        email: sanitizedEmail,
        passwordHash,
        isActive: true,
        metadata: metadata || {}
      });

      // Générer les tokens
      const tokens = await this.jwtService.generateTokens(newUser.id, newUser.email);

      // Stocker le refresh token
      const refreshDecoded = this.jwtService.decodeToken(tokens.refreshToken);
      if (refreshDecoded) {
        await this.adapter.storeRefreshToken(
          newUser.id,
          tokens.refreshToken,
          new Date(refreshDecoded.exp * 1000)
        );
      }

      return { user: this.sanitizeUser(newUser), tokens };
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      
      throw new AuthError(
        AuthErrorCode.INVALID_CREDENTIALS,
        'Erreur lors de l\'inscription',
        500
      );
    }
  }

  // ========================================================================
  // Connexion d'utilisateur
  // ========================================================================

  async login(credentials: LoginCredentials): Promise<{ user: User; tokens: AuthTokens }> {
    try {
      const { email, password } = credentials;
      
      const sanitizedEmail = sanitizeEmail(email);

      // Vérifier la limitation de taux si configurée
      if (this.adapter.isRateLimited) {
        const isLimited = await this.adapter.isRateLimited(sanitizedEmail);
        if (isLimited) {
          throw new AuthError(
            AuthErrorCode.RATE_LIMITED,
            'Trop de tentatives de connexion. Veuillez réessayer plus tard.',
            429
          );
        }
      }

      // Trouver l'utilisateur
      const user = await this.adapter.findUserByEmail(sanitizedEmail);
      if (!user) {
        // Incrémenter les tentatives même si l'utilisateur n'existe pas
        if (this.adapter.incrementLoginAttempts) {
          await this.adapter.incrementLoginAttempts(sanitizedEmail);
        }
        
        throw new AuthError(
          AuthErrorCode.INVALID_CREDENTIALS,
          'Email ou mot de passe incorrect',
          401
        );
      }

      // Vérifier si l'utilisateur est actif
      if (!user.isActive) {
        throw new AuthError(
          AuthErrorCode.USER_INACTIVE,
          'Votre compte a été désactivé. Contactez l\'administrateur.',
          403
        );
      }

      // Vérifier le mot de passe
      const isValidPassword = await this.passwordService.verifyPassword(password, user.passwordHash);
      if (!isValidPassword) {
        if (this.adapter.incrementLoginAttempts) {
          await this.adapter.incrementLoginAttempts(sanitizedEmail);
        }
        
        throw new AuthError(
          AuthErrorCode.INVALID_CREDENTIALS,
          'Email ou mot de passe incorrect',
          401
        );
      }

      // Vérifier si le hash du mot de passe doit être mis à jour
      if (await this.passwordService.needsRehash(user.passwordHash)) {
        const newHash = await this.passwordService.hashPassword(password);
        await this.adapter.updateUser(user.id, { passwordHash: newHash });
      }

      // Réinitialiser les tentatives de connexion
      if (this.adapter.resetLoginAttempts) {
        await this.adapter.resetLoginAttempts(sanitizedEmail);
      }

      // Générer les tokens
      const tokens = await this.jwtService.generateTokens(user.id, user.email);

      // Stocker le refresh token
      const refreshDecoded = this.jwtService.decodeToken(tokens.refreshToken);
      if (refreshDecoded) {
        await this.adapter.storeRefreshToken(
          user.id,
          tokens.refreshToken,
          new Date(refreshDecoded.exp * 1000)
        );
      }

      return { user: this.sanitizeUser(user), tokens };
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      
      throw new AuthError(
        AuthErrorCode.INVALID_CREDENTIALS,
        'Erreur lors de la connexion',
        500
      );
    }
  }

  // ========================================================================
  // Rafraîchissement des tokens
  // ========================================================================

  async refreshToken(refreshToken: string): Promise<AuthTokens> {
    try {
      // Vérifier le format du token
      const decoded = await this.jwtService.verifyToken(refreshToken, 'refresh');

      // Vérifier que le token existe en base
      const userId = await this.adapter.validateRefreshToken(refreshToken);
      if (!userId || userId !== decoded.sub) {
        throw new AuthError(
          AuthErrorCode.INVALID_TOKEN,
          'Token de rafraîchissement invalide',
          401
        );
      }

      // Vérifier que l'utilisateur existe toujours
      const user = await this.adapter.findUserById(userId);
      if (!user || !user.isActive) {
        throw new AuthError(
          AuthErrorCode.USER_NOT_FOUND,
          'Utilisateur non trouvé ou inactif',
          404
        );
      }

      // Révoquer l'ancien token
      await this.adapter.revokeRefreshToken(refreshToken);

      // Générer de nouveaux tokens
      const tokens = await this.jwtService.generateTokens(user.id, user.email);

      // Stocker le nouveau refresh token
      const newRefreshDecoded = this.jwtService.decodeToken(tokens.refreshToken);
      if (newRefreshDecoded) {
        await this.adapter.storeRefreshToken(
          user.id,
          tokens.refreshToken,
          new Date(newRefreshDecoded.exp * 1000)
        );
      }

      return tokens;
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      
      throw new AuthError(
        AuthErrorCode.INVALID_TOKEN,
        'Erreur lors du rafraîchissement du token',
        500
      );
    }
  }

  // ========================================================================
  // Vérification des tokens
  // ========================================================================

  async verifyToken(accessToken: string): Promise<User> {
    try {
      const decoded = await this.jwtService.verifyToken(accessToken, 'access');
      
      const user = await this.adapter.findUserById(decoded.sub);
      if (!user) {
        throw new AuthError(
          AuthErrorCode.USER_NOT_FOUND,
          'Utilisateur non trouvé',
          404
        );
      }

      if (!user.isActive) {
        throw new AuthError(
          AuthErrorCode.USER_INACTIVE,
          'Utilisateur inactif',
          403
        );
      }

      return this.sanitizeUser(user);
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      
      throw new AuthError(
        AuthErrorCode.INVALID_TOKEN,
        'Token invalide',
        401
      );
    }
  }

  // ========================================================================
  // Déconnexion
  // ========================================================================

  async logout(refreshToken: string): Promise<void> {
    try {
      await this.adapter.revokeRefreshToken(refreshToken);
    } catch {
      // Ignorer les erreurs de déconnexion - le token pourrait déjà être expiré
    }
  }

  async logoutAll(userId: string): Promise<void> {
    try {
      await this.adapter.revokeAllUserTokens(userId);
    } catch (error) {
      throw new AuthError(
        AuthErrorCode.INVALID_CREDENTIALS,
        'Erreur lors de la déconnexion',
        500
      );
    }
  }

  // ========================================================================
  // Gestion des utilisateurs
  // ========================================================================

  async getUserById(id: string): Promise<User | null> {
    try {
      const user = await this.adapter.findUserById(id);
      return user ? this.sanitizeUser(user) : null;
    } catch {
      return null;
    }
  }

  async getUserByEmail(email: string): Promise<User | null> {
    try {
      const sanitizedEmail = sanitizeEmail(email);
      const user = await this.adapter.findUserByEmail(sanitizedEmail);
      return user ? this.sanitizeUser(user) : null;
    } catch {
      return null;
    }
  }

  async updateUser(userId: string, updates: Partial<Omit<User, 'id' | 'createdAt'>>): Promise<User> {
    try {
      const user = await this.adapter.updateUser(userId, {
        ...updates,
        updatedAt: new Date()
      });
      
      return this.sanitizeUser(user);
    } catch (error) {
      throw new AuthError(
        AuthErrorCode.INVALID_CREDENTIALS,
        'Erreur lors de la mise à jour de l\'utilisateur',
        500
      );
    }
  }

  async changePassword(userId: string, oldPassword: string, newPassword: string): Promise<void> {
    try {
      const user = await this.adapter.findUserById(userId);
      if (!user) {
        throw new AuthError(
          AuthErrorCode.USER_NOT_FOUND,
          'Utilisateur non trouvé',
          404
        );
      }

      // Vérifier l'ancien mot de passe
      const isValidOldPassword = await this.passwordService.verifyPassword(oldPassword, user.passwordHash);
      if (!isValidOldPassword) {
        throw new AuthError(
          AuthErrorCode.INVALID_CREDENTIALS,
          'Ancien mot de passe incorrect',
          400
        );
      }

      // Valider le nouveau mot de passe
      const validation = validatePassword(newPassword);
      if (!validation.isValid) {
        throw new AuthError(
          AuthErrorCode.WEAK_PASSWORD,
          validation.errors.join(', '),
          400
        );
      }

      // Hacher et sauvegarder le nouveau mot de passe
      const newPasswordHash = await this.passwordService.hashPassword(newPassword);
      await this.adapter.updateUser(userId, {
        passwordHash: newPasswordHash,
        updatedAt: new Date()
      });

      // Révoquer tous les tokens existants pour forcer une nouvelle connexion
      await this.adapter.revokeAllUserTokens(userId);
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      
      throw new AuthError(
        AuthErrorCode.INVALID_CREDENTIALS,
        'Erreur lors du changement de mot de passe',
        500
      );
    }
  }

  // ========================================================================
  // Utilitaires privés
  // ========================================================================

  private sanitizeUser(user: User): User {
    // Retourne l'utilisateur sans exposer des données sensibles
    return {
      id: user.id,
      email: user.email,
      passwordHash: user.passwordHash, // Nécessaire pour certaines opérations internes
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      isActive: user.isActive,
      metadata: user.metadata || {}
    };
  }

  // ========================================================================
  // Méthodes publiques utilitaires
  // ========================================================================

  /**
   * Vérifie la force d'un mot de passe
   */
  assessPasswordStrength(password: string): ReturnType<PasswordService['assessPasswordStrength']> {
    return this.passwordService.assessPasswordStrength(password);
  }

  /**
   * Extrait le token du header Authorization
   */
  extractTokenFromHeader(authHeader: string | undefined): string | null {
    return this.jwtService.extractTokenFromHeader(authHeader);
  }

  /**
   * Génère un secret JWT sécurisé
   */
  static generateJWTSecret(length?: number): string {
    return JWTService.generateSecret(length);
  }
} 