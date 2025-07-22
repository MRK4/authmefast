import { ValidationResult, PasswordStrengthOptions } from '../types';

// ============================================================================
// Validation d'email
// ============================================================================

const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

export function validateEmail(email: string): ValidationResult {
  const errors: string[] = [];

  if (!email || typeof email !== 'string') {
    errors.push('L\'email est requis');
  } else {
    const trimmedEmail = email.trim();
    
    if (trimmedEmail.length === 0) {
      errors.push('L\'email ne peut pas être vide');
    } else if (trimmedEmail.length > 254) {
      errors.push('L\'email est trop long (maximum 254 caractères)');
    } else if (!EMAIL_REGEX.test(trimmedEmail)) {
      errors.push('Format d\'email invalide');
    }
  }

  return {
    isValid: errors.length === 0,
    errors
  };
}

// ============================================================================
// Validation de mot de passe
// ============================================================================

export function validatePassword(
  password: string,
  options: PasswordStrengthOptions = {}
): ValidationResult {
  const {
    minLength = 8,
    requireUppercase = true,
    requireLowercase = true,
    requireNumbers = true,
    requireSpecialChars = true
  } = options;

  const errors: string[] = [];

  if (!password || typeof password !== 'string') {
    errors.push('Le mot de passe est requis');
    return { isValid: false, errors };
  }

  if (password.length < minLength) {
    errors.push(`Le mot de passe doit contenir au moins ${minLength} caractères`);
  }

  if (requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Le mot de passe doit contenir au moins une majuscule');
  }

  if (requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Le mot de passe doit contenir au moins une minuscule');
  }

  if (requireNumbers && !/\d/.test(password)) {
    errors.push('Le mot de passe doit contenir au moins un chiffre');
  }

  if (requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>?]/.test(password)) {
    errors.push('Le mot de passe doit contenir au moins un caractère spécial');
  }

  // Vérifications de sécurité supplémentaires
  if (password.length > 128) {
    errors.push('Le mot de passe est trop long (maximum 128 caractères)');
  }

  // Mots de passe communs à éviter
  const commonPasswords = [
    'password', '123456', '123456789', 'qwerty', 'abc123', 
    'password123', 'admin', 'letmein', 'welcome', 'monkey'
  ];
  
  if (commonPasswords.some(common => password.toLowerCase().includes(common.toLowerCase()))) {
    errors.push('Le mot de passe est trop commun');
  }

  return {
    isValid: errors.length === 0,
    errors
  };
}

// ============================================================================
// Utilitaires de nettoyage
// ============================================================================

export function sanitizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function isStrongPassword(password: string): boolean {
  const result = validatePassword(password, {
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true
  });
  
  return result.isValid;
}

// ============================================================================
// Validation d'ID utilisateur
// ============================================================================

export function validateUserId(id: string): ValidationResult {
  const errors: string[] = [];

  if (!id || typeof id !== 'string') {
    errors.push('L\'ID utilisateur est requis');
  } else if (id.trim().length === 0) {
    errors.push('L\'ID utilisateur ne peut pas être vide');
  } else if (id.length < 10 || id.length > 50) {
    errors.push('L\'ID utilisateur doit faire entre 10 et 50 caractères');
  }

  return {
    isValid: errors.length === 0,
    errors
  };
} 