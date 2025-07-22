import { DatabaseAdapter } from '../types';

// ============================================================================
// Classe de base abstraite pour les adaptateurs de base de données
// ============================================================================

export abstract class BaseDatabaseAdapter implements DatabaseAdapter {
  /**
   * Nom de l'adaptateur pour identification
   */
  abstract readonly name: string;

  /**
   * Indique si l'adaptateur est connecté et prêt
   */
  abstract get isConnected(): boolean;

  /**
   * Initialise la connexion à la base de données
   */
  abstract connect(): Promise<void>;

  /**
   * Ferme la connexion à la base de données
   */
  abstract disconnect(): Promise<void>;

  /**
   * Nettoie les données expirées (tokens, tentatives de connexion, etc.)
   */
  abstract cleanup(): Promise<void>;

  // ========================================================================
  // Méthodes abstraites implémentées par les adaptateurs spécifiques
  // ========================================================================

  abstract createUser(userData: Parameters<DatabaseAdapter['createUser']>[0]): ReturnType<DatabaseAdapter['createUser']>;
  abstract findUserByEmail(email: string): ReturnType<DatabaseAdapter['findUserByEmail']>;
  abstract findUserById(id: string): ReturnType<DatabaseAdapter['findUserById']>;
  abstract updateUser(id: string, updates: Parameters<DatabaseAdapter['updateUser']>[1]): ReturnType<DatabaseAdapter['updateUser']>;
  abstract deleteUser(id: string): ReturnType<DatabaseAdapter['deleteUser']>;

  abstract storeRefreshToken(userId: string, token: string, expiresAt: Date): ReturnType<DatabaseAdapter['storeRefreshToken']>;
  abstract validateRefreshToken(token: string): ReturnType<DatabaseAdapter['validateRefreshToken']>;
  abstract revokeRefreshToken(token: string): ReturnType<DatabaseAdapter['revokeRefreshToken']>;
  abstract revokeAllUserTokens(userId: string): ReturnType<DatabaseAdapter['revokeAllUserTokens']>;

  // Méthodes optionnelles avec implémentation par défaut
  async incrementLoginAttempts?(email: string): Promise<number> {
    // Implémentation par défaut - peut être surchargée
    console.warn(`Rate limiting not implemented in ${this.name} adapter`);
    return 0;
  }

  async resetLoginAttempts?(email: string): Promise<void> {
    // Implémentation par défaut - peut être surchargée
    console.warn(`Rate limiting not implemented in ${this.name} adapter`);
  }

  async isRateLimited?(email: string): Promise<boolean> {
    // Implémentation par défaut - peut être surchargée
    console.warn(`Rate limiting not implemented in ${this.name} adapter`);
    return false;
  }

  // ========================================================================
  // Méthodes utilitaires communes
  // ========================================================================

  /**
   * Valide qu'une connexion est établie avant d'exécuter une opération
   */
  protected ensureConnected(): void {
    if (!this.isConnected) {
      throw new Error(`${this.name} adapter is not connected. Call connect() first.`);
    }
  }

  /**
   * Nettoie et valide un email
   */
  protected normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
  }

  /**
   * Génère un timestamp Unix pour les dates
   */
  protected toUnixTimestamp(date: Date): number {
    return Math.floor(date.getTime() / 1000);
  }

  /**
   * Convertit un timestamp Unix en Date
   */
  protected fromUnixTimestamp(timestamp: number): Date {
    return new Date(timestamp * 1000);
  }

  /**
   * Génère des statistiques sur l'état de l'adaptateur
   */
  async getStats(): Promise<{
    isConnected: boolean;
    name: string;
    userCount?: number;
    activeTokens?: number;
  }> {
    return {
      isConnected: this.isConnected,
      name: this.name
    };
  }
} 