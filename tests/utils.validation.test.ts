import { validateEmail, validatePassword, sanitizeEmail, isStrongPassword, validateUserId } from '../src/utils/validation';

describe('Validation utils', () => {
  it('should validate correct email', () => {
    const result = validateEmail('user@example.com');
    expect(result.isValid).toBe(true);
  });

  it('should reject invalid email', () => {
    const result = validateEmail('not-an-email');
    expect(result.isValid).toBe(false);
  });

  it('should validate strong password', () => {
    const result = validatePassword('F0rt!TestValide2024');
    expect(result.isValid).toBe(true);
  });

  it('should reject weak password', () => {
    const result = validatePassword('weak');
    expect(result.isValid).toBe(false);
  });

  it('should sanitize email', () => {
    expect(sanitizeEmail('  User@EXAMPLE.com  ')).toBe('user@example.com');
  });

  it('should check strong password', () => {
    expect(isStrongPassword('F0rt!TestValide2024')).toBe(true);
    expect(isStrongPassword('weak')).toBe(false);
  });

  it('should validate user id', () => {
    const valid = validateUserId('1234567890A');
    expect(valid.isValid).toBe(true);
    const invalid = validateUserId('');
    expect(invalid.isValid).toBe(false);
  });
}); 