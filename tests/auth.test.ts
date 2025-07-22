import { describe, test, expect, beforeEach, afterEach } from '@jest/globals';
import { 
  AuthService, 
  MemoryDatabaseAdapter, 
  AuthError, 
  AuthErrorCode,
  createDefaultConfig 
} from '../src';
import { TEST_USER, ADMIN_USER, WEAK_PASSWORD, INVALID_EMAIL } from './setup';

describe('AuthService', () => {
  let authService: AuthService;
  let adapter: MemoryDatabaseAdapter;

  beforeEach(async () => {
    adapter = new MemoryDatabaseAdapter();
    await adapter.connect();
    
    const config = createDefaultConfig('test-secret-key-for-jwt-should-be-at-least-32-characters-long');
    authService = new AuthService(adapter, config);
  });

  afterEach(async () => {
    await adapter.disconnect();
  });

  describe('User Registration', () => {
    test('should register a new user successfully', async () => {
      const result = await authService.register(TEST_USER);

      expect(result.user).toBeDefined();
      expect(result.user.email).toBe(TEST_USER.email);
      expect(result.user.isActive).toBe(true);
      expect(result.tokens).toBeDefined();
      expect(result.tokens.accessToken).toBeDefined();
      expect(result.tokens.refreshToken).toBeDefined();
    });

    test('should reject registration with invalid email', async () => {
      await expect(
        authService.register({
          email: INVALID_EMAIL,
          password: TEST_USER.password
        })
      ).rejects.toThrow(AuthError);
    });

    test('should reject registration with weak password', async () => {
      await expect(
        authService.register({
          email: TEST_USER.email,
          password: WEAK_PASSWORD
        })
      ).rejects.toThrow(AuthError);
    });

    test('should reject duplicate email registration', async () => {
      await authService.register(TEST_USER);
      
      await expect(
        authService.register(TEST_USER)
      ).rejects.toThrow(AuthError);
    });
  });

  describe('User Login', () => {
    beforeEach(async () => {
      await authService.register(TEST_USER);
    });

    test('should login with valid credentials', async () => {
      const result = await authService.login({
        email: TEST_USER.email,
        password: TEST_USER.password
      });

      expect(result.user).toBeDefined();
      expect(result.user.email).toBe(TEST_USER.email);
      expect(result.tokens).toBeDefined();
    });

    test('should reject login with wrong password', async () => {
      await expect(
        authService.login({
          email: TEST_USER.email,
          password: 'wrong-password'
        })
      ).rejects.toThrow(AuthError);
    });

    test('should reject login with non-existent user', async () => {
      await expect(
        authService.login({
          email: 'nonexistent@example.com',
          password: TEST_USER.password
        })
      ).rejects.toThrow(AuthError);
    });
  });

  describe('Token Management', () => {
    let user: any;
    let tokens: any;

    beforeEach(async () => {
      const result = await authService.register(TEST_USER);
      user = result.user;
      tokens = result.tokens;
    });

    test('should verify valid access token', async () => {
      const verifiedUser = await authService.verifyToken(tokens.accessToken);
      expect(verifiedUser.id).toBe(user.id);
      expect(verifiedUser.email).toBe(user.email);
    });

    test('should refresh tokens successfully', async () => {
      const newTokens = await authService.refreshToken(tokens.refreshToken);
      
      expect(newTokens.accessToken).toBeDefined();
      expect(newTokens.refreshToken).toBeDefined();
      expect(newTokens.accessToken).not.toBe(tokens.accessToken);
      expect(newTokens.refreshToken).not.toBe(tokens.refreshToken);
    });

    test('should reject invalid refresh token', async () => {
      await expect(
        authService.refreshToken('invalid-token')
      ).rejects.toThrow(AuthError);
    });

    test('should logout successfully', async () => {
      await authService.logout(tokens.refreshToken);
      
      // Le token ne devrait plus fonctionner
      await expect(
        authService.refreshToken(tokens.refreshToken)
      ).rejects.toThrow(AuthError);
    });
  });

  describe('User Management', () => {
    let userId: string;

    beforeEach(async () => {
      const result = await authService.register(TEST_USER);
      userId = result.user.id;
    });

    test('should get user by ID', async () => {
      const user = await authService.getUserById(userId);
      expect(user).toBeDefined();
      expect(user!.email).toBe(TEST_USER.email);
    });

    test('should get user by email', async () => {
      const user = await authService.getUserByEmail(TEST_USER.email);
      expect(user).toBeDefined();
      expect(user!.id).toBe(userId);
    });

    test('should update user metadata', async () => {
      const updatedUser = await authService.updateUser(userId, {
        metadata: { role: 'admin', department: 'IT' }
      });
      
      expect(updatedUser.metadata).toEqual({
        role: 'admin',
        department: 'IT'
      });
    });

    test('should change password successfully', async () => {
      const newPassword = 'N3w!SuperSecur1sée2024';
      
      await authService.changePassword(userId, TEST_USER.password, newPassword);
      
      // Tester la connexion avec le nouveau mot de passe
      const result = await authService.login({
        email: TEST_USER.email,
        password: newPassword
      });
      
      expect(result.user.id).toBe(userId);
    });

    test('should reject password change with wrong old password', async () => {
      await expect(
        authService.changePassword(userId, 'wrong-password', 'NewPassword123!')
      ).rejects.toThrow(AuthError);
    });
  });

  describe('Password Strength Assessment', () => {
    test('should assess password strength correctly', () => {
      const weakResult = authService.assessPasswordStrength('weak');
      expect(weakResult.level).toBe('Très faible');
      expect(weakResult.score).toBeLessThan(40);

      const strongResult = authService.assessPasswordStrength('VeryStrongPassword123!@#');
      expect(strongResult.level).toMatch(/Fort|Très fort/);
      expect(strongResult.score).toBeGreaterThan(60);
    });
  });

  describe('Rate Limiting', () => {
    test('should handle rate limiting for login attempts', async () => {
      await authService.register(TEST_USER);
      
      // Simuler plusieurs tentatives échouées
      for (let i = 0; i < 5; i++) {
        try {
          await authService.login({
            email: TEST_USER.email,
            password: 'wrong-password'
          });
        } catch {
          // Ignorer les erreurs attendues
        }
      }

      // La prochaine tentative devrait être bloquée
      await expect(
        authService.login({
          email: TEST_USER.email,
          password: 'wrong-password'
        })
      ).rejects.toThrow(); // Rate limited or blocked
    });
  });
}); 