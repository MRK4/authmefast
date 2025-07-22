import * as bcrypt from 'bcrypt';
import { AuthError, AuthErrorCode } from '../types';

// ============================================================================
// Service de gestion des mots de passe
// ============================================================================

export class PasswordService {
  private readonly rounds: number;

  constructor(rounds: number = 12) {
    if (rounds < 10 || rounds > 15) {
      throw new Error('Les rounds bcrypt doivent être entre 10 et 15 pour une sécurité optimale');
    }
    this.rounds = rounds;
  }

  /**
   * Hache un mot de passe avec bcrypt
   */
  async hashPassword(password: string): Promise<string> {
    try {
      // Vérification de sécurité supplémentaire
      if (!password || password.length === 0) {
        throw new AuthError(
          AuthErrorCode.WEAK_PASSWORD,
          'Le mot de passe ne peut pas être vide',
          400
        );
      }

      if (password.length > 72) {
        // bcrypt a une limite de 72 caractères
        throw new AuthError(
          AuthErrorCode.WEAK_PASSWORD,
          'Le mot de passe ne peut pas dépasser 72 caractères',
          400
        );
      }

      return await bcrypt.hash(password, this.rounds);
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      
      throw new AuthError(
        AuthErrorCode.WEAK_PASSWORD,
        'Erreur lors du hachage du mot de passe',
        500
      );
    }
  }

  /**
   * Vérifie un mot de passe contre son hash
   */
  async verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
      if (!password || !hash) {
        return false;
      }

      return await bcrypt.compare(password, hash);
    } catch {
      return false; // En cas d'erreur, on considère que le mot de passe est incorrect
    }
  }

  /**
   * Vérifie si un hash nécessite une mise à jour (changement du nombre de rounds)
   */
  async needsRehash(hash: string): Promise<boolean> {
    try {
      const saltRounds = this.extractRounds(hash);
      return saltRounds !== this.rounds;
    } catch {
      return true; // Si on ne peut pas analyser le hash, on le considère comme obsolète
    }
  }

  /**
   * Génère un mot de passe temporaire sécurisé
   */
  generateTemporaryPassword(length: number = 16): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*';
    let password = '';
    
    // S'assurer qu'on a au moins un caractère de chaque type requis
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const numbers = '0123456789';
    const special = '!@#$%^&*';
    
    password += upper[Math.floor(Math.random() * upper.length)];
    password += lower[Math.floor(Math.random() * lower.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += special[Math.floor(Math.random() * special.length)];
    
    // Compléter avec des caractères aléatoires
    for (let i = password.length; i < length; i++) {
      password += charset[Math.floor(Math.random() * charset.length)];
    }
    
    // Mélanger les caractères
    return password.split('').sort(() => Math.random() - 0.5).join('');
  }

  /**
   * Extrait le nombre de rounds d'un hash bcrypt
   */
  private extractRounds(hash: string): number {
    const match = hash.match(/^\$2[aby]?\$(\d{2})\$/);
    if (!match || !match[1]) {
      throw new Error('Format de hash bcrypt invalide');
    }
    return parseInt(match[1], 10);
  }

  /**
   * Vérifie la force d'un mot de passe et donne un score
   */
  assessPasswordStrength(password: string): {
    score: number; // 0-100
    level: 'Très faible' | 'Faible' | 'Moyen' | 'Fort' | 'Très fort';
    suggestions: string[];
  } {
    let score = 0;
    const suggestions: string[] = [];

    if (password.length >= 8) score += 15;
    else suggestions.push('Utilisez au moins 8 caractères');
    
    if (password.length >= 12) score += 10;
    else suggestions.push('Utilisez au moins 12 caractères pour plus de sécurité');
    
    if (/[a-z]/.test(password)) score += 15;
    else suggestions.push('Ajoutez des lettres minuscules');
    
    if (/[A-Z]/.test(password)) score += 15;
    else suggestions.push('Ajoutez des lettres majuscules');
    
    if (/\d/.test(password)) score += 15;
    else suggestions.push('Ajoutez des chiffres');
    
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>?]/.test(password)) score += 20;
    else suggestions.push('Ajoutez des caractères spéciaux');
    
    if (password.length > 16) score += 10;

    // Pénalités
    if (/(.)\1{2,}/.test(password)) {
      score -= 15; // Caractères répétés
      suggestions.push('Évitez les caractères répétés');
    }
    
    if (/(?:123|abc|qwe|asd|zxc)/i.test(password)) {
      score -= 20; // Séquences communes
      suggestions.push('Évitez les séquences communes (123, abc, etc.)');
    }

    score = Math.max(0, Math.min(100, score));

    let level: 'Très faible' | 'Faible' | 'Moyen' | 'Fort' | 'Très fort';
    if (score < 20) level = 'Très faible';
    else if (score < 40) level = 'Faible';
    else if (score < 60) level = 'Moyen';
    else if (score < 80) level = 'Fort';
    else level = 'Très fort';

    return { score, level, suggestions };
  }
} 