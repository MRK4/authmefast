// ============================================================================
// Configuration globale des tests
// ============================================================================

import { jest } from '@jest/globals';

// Augmenter les timeouts pour les tests d'authentification
jest.setTimeout(10000);

// Supprimer les logs pendant les tests
const originalConsoleWarn = console.warn;
const originalConsoleError = console.error;

beforeAll(() => {
  console.warn = jest.fn();
  console.error = jest.fn();
});

afterAll(() => {
  console.warn = originalConsoleWarn;
  console.error = originalConsoleError;
});

// Nettoyer après chaque test
afterEach(() => {
  jest.clearAllMocks();
});

// Variables d'environnement pour les tests
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret-key-for-jwt-should-be-at-least-32-characters-long';

// ============================================================================
// Utilitaires de test
// ============================================================================

export const TEST_USER = {
  email: 'test@example.com',
  password: 'T3st!SuperSecur1sée2024',
  metadata: { role: 'user' }
};

export const ADMIN_USER = {
  email: 'admin@example.com',
  password: 'Adm1n!UltraSecur1sée2024',
  metadata: { role: 'admin' }
};

export const WEAK_PASSWORD = 'weak';
export const INVALID_EMAIL = 'not-an-email';

export function createMockRequest(overrides = {}) {
  return {
    headers: {},
    cookies: {},
    query: {},
    params: {},
    body: {},
    path: '/test',
    ip: '127.0.0.1',
    ...overrides
  };
}

export function createMockResponse() {
  const res = {
    status: jest.fn(() => res),
    json: jest.fn(() => res),
    set: jest.fn(() => res),
    cookie: jest.fn(() => res),
    clearCookie: jest.fn(() => res)
  };
  return res;
}

export function createMockNext() {
  return jest.fn();
} 