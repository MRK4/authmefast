import { nanoid } from 'nanoid';
import { User, DatabaseAdapter } from '../types';
import { BaseDatabaseAdapter } from './base';

// ============================================================================
// Interfaces internes
// ============================================================================

interface StoredUser extends User {}

interface RefreshToken {
  token: string;
  userId: string;
  expiresAt: Date;
  createdAt: Date;
}

interface LoginAttempt {
  email: string;
  attempts: number;
  firstAttempt: Date;
  lastAttempt: Date;
  blockedUntil?: Date;
}

// ============================================================================
// Adaptateur en mémoire
// ============================================================================

export class MemoryDatabaseAdapter extends BaseDatabaseAdapter implements DatabaseAdapter {
  readonly name = 'MemoryAdapter';
  
  private users: Map<string, StoredUser> = new Map();
  private usersByEmail: Map<string, StoredUser> = new Map();
  private refreshTokens: Map<string, RefreshToken> = new Map();
  private loginAttempts: Map<string, LoginAttempt> = new Map();
  
  private connected = false;

  get isConnected(): boolean {
    return this.connected;
  }

  // ========================================================================
  // Lifecycle
  // ========================================================================

  async connect(): Promise<void> {
    this.connected = true;
  }

  async disconnect(): Promise<void> {
    this.users.clear();
    this.usersByEmail.clear();
    this.refreshTokens.clear();
    this.loginAttempts.clear();
    this.connected = false;
  }

  async cleanup(): Promise<void> {
    this.ensureConnected();
    
    const now = new Date();
    
    // Nettoyer les refresh tokens expirés
    for (const [token, tokenData] of this.refreshTokens.entries()) {
      if (tokenData.expiresAt <= now) {
        this.refreshTokens.delete(token);
      }
    }

    // Nettoyer les tentatives de connexion anciennes (plus de 24h)
    const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    for (const [email, attempt] of this.loginAttempts.entries()) {
      if (attempt.lastAttempt <= dayAgo) {
        this.loginAttempts.delete(email);
      }
    }
  }

  // ========================================================================
  // Gestion des utilisateurs
  // ========================================================================

  async createUser(userData: Omit<User, 'id' | 'createdAt' | 'updatedAt'>): Promise<User> {
    this.ensureConnected();

    const id = nanoid();
    const now = new Date();
    
    const user: StoredUser = {
      id,
      email: this.normalizeEmail(userData.email),
      passwordHash: userData.passwordHash,
      isActive: userData.isActive,
      metadata: userData.metadata || {},
      createdAt: now,
      updatedAt: now
    };

    this.users.set(id, user);
    this.usersByEmail.set(user.email, user);

    return { ...user };
  }

  async findUserByEmail(email: string): Promise<User | null> {
    this.ensureConnected();
    
    const normalizedEmail = this.normalizeEmail(email);
    const user = this.usersByEmail.get(normalizedEmail);
    
    return user ? { ...user } : null;
  }

  async findUserById(id: string): Promise<User | null> {
    this.ensureConnected();
    
    const user = this.users.get(id);
    return user ? { ...user } : null;
  }

  async updateUser(id: string, updates: Partial<Omit<User, 'id' | 'createdAt'>>): Promise<User> {
    this.ensureConnected();

    const existingUser = this.users.get(id);
    if (!existingUser) {
      throw new Error('User not found');
    }

    // Si l'email change, mettre à jour l'index
    let normalizedEmail: string | undefined = undefined;
    if (updates.email && updates.email !== existingUser.email) {
      this.usersByEmail.delete(existingUser.email);
      normalizedEmail = this.normalizeEmail(updates.email);
    }

    const updatedUser: StoredUser = {
      ...existingUser,
      ...updates,
      email: normalizedEmail ? normalizedEmail : existingUser.email,
      id, // S'assurer que l'ID ne change pas
      createdAt: existingUser.createdAt, // S'assurer que createdAt ne change pas
      updatedAt: new Date()
    };

    this.users.set(id, updatedUser);
    // Toujours mettre à jour l'index par email
    this.usersByEmail.set(updatedUser.email, updatedUser);

    return { ...updatedUser };
  }

  async deleteUser(id: string): Promise<void> {
    this.ensureConnected();

    const user = this.users.get(id);
    if (!user) {
      throw new Error('User not found');
    }

    this.users.delete(id);
    this.usersByEmail.delete(user.email);
    
    // Nettoyer tous les tokens de cet utilisateur
    await this.revokeAllUserTokens(id);
  }

  // ========================================================================
  // Gestion des refresh tokens
  // ========================================================================

  async storeRefreshToken(userId: string, token: string, expiresAt: Date): Promise<void> {
    this.ensureConnected();

    this.refreshTokens.set(token, {
      token,
      userId,
      expiresAt,
      createdAt: new Date()
    });
  }

  async validateRefreshToken(token: string): Promise<string | null> {
    this.ensureConnected();

    const tokenData = this.refreshTokens.get(token);
    if (!tokenData) {
      return null;
    }

    if (tokenData.expiresAt <= new Date()) {
      this.refreshTokens.delete(token);
      return null;
    }

    return tokenData.userId;
  }

  async revokeRefreshToken(token: string): Promise<void> {
    this.ensureConnected();
    this.refreshTokens.delete(token);
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    this.ensureConnected();

    const tokensToRevoke: string[] = [];
    
    for (const [token, tokenData] of this.refreshTokens.entries()) {
      if (tokenData.userId === userId) {
        tokensToRevoke.push(token);
      }
    }

    for (const token of tokensToRevoke) {
      this.refreshTokens.delete(token);
    }
  }

  // ========================================================================
  // Rate limiting
  // ========================================================================

  async incrementLoginAttempts(email: string): Promise<number> {
    this.ensureConnected();

    const normalizedEmail = this.normalizeEmail(email);
    const now = new Date();
    const existing = this.loginAttempts.get(normalizedEmail);

    if (!existing) {
      const attempt: LoginAttempt = {
        email: normalizedEmail,
        attempts: 1,
        firstAttempt: now,
        lastAttempt: now
      };
      this.loginAttempts.set(normalizedEmail, attempt);
      return 1;
    }

    // Réinitialiser si plus de 15 minutes depuis la première tentative
    const fifteenMinutesAgo = new Date(now.getTime() - 15 * 60 * 1000);
    if (existing.firstAttempt <= fifteenMinutesAgo) {
      const attempt: LoginAttempt = {
        email: normalizedEmail,
        attempts: 1,
        firstAttempt: now,
        lastAttempt: now
      };
      this.loginAttempts.set(normalizedEmail, attempt);
      return 1;
    }

    existing.attempts += 1;
    existing.lastAttempt = now;

    // Bloquer après 5 tentatives pour 1 heure
    if (existing.attempts >= 5) {
      existing.blockedUntil = new Date(now.getTime() + 60 * 60 * 1000);
    }

    return existing.attempts;
  }

  async resetLoginAttempts(email: string): Promise<void> {
    this.ensureConnected();

    const normalizedEmail = this.normalizeEmail(email);
    this.loginAttempts.delete(normalizedEmail);
  }

  async isRateLimited(email: string): Promise<boolean> {
    this.ensureConnected();

    const normalizedEmail = this.normalizeEmail(email);
    const attempt = this.loginAttempts.get(normalizedEmail);
    
    if (!attempt) {
      return false;
    }

    const now = new Date();
    
    // Vérifier si toujours bloqué
    if (attempt.blockedUntil && attempt.blockedUntil > now) {
      return true;
    }

    // Si le blocage est expiré, nettoyer
    if (attempt.blockedUntil && attempt.blockedUntil <= now) {
      this.loginAttempts.delete(normalizedEmail);
      return false;
    }

    return false;
  }

  // ========================================================================
  // Statistiques et diagnostics
  // ========================================================================

  async getStats(): Promise<{
    isConnected: boolean;
    name: string;
    userCount: number;
    activeTokens: number;
  }> {
    await this.cleanup(); // Nettoyer avant de compter

    return {
      isConnected: this.isConnected,
      name: this.name,
      userCount: this.users.size,
      activeTokens: this.refreshTokens.size
    };
  }

  /**
   * Méthode utilitaire pour récupérer tous les utilisateurs (dev/test uniquement)
   */
  async getAllUsers(): Promise<User[]> {
    this.ensureConnected();
    return Array.from(this.users.values()).map(user => ({ ...user }));
  }

  /**
   * Méthode utilitaire pour vider toutes les données (dev/test uniquement)
   */
  async reset(): Promise<void> {
    this.ensureConnected();
    
    this.users.clear();
    this.usersByEmail.clear();
    this.refreshTokens.clear();
    this.loginAttempts.clear();
  }
} 