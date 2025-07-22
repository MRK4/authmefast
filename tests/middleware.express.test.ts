import { ExpressAuthMiddleware } from '../src/middleware/express';
import { AuthService } from '../src/core/auth';
import { MemoryDatabaseAdapter } from '../src/adapters/memory';
import { createDefaultConfig } from '../src';
import { createMockRequest, createMockResponse, createMockNext } from './setup';

const TEST_EMAIL = 'middleware@test.com';
const TEST_PASSWORD = 'F0rt!TestValide2024';

// Utilitaire pour créer un AuthService prêt à l'emploi
async function getAuthService() {
  const adapter = new MemoryDatabaseAdapter();
  await adapter.connect();
  const config = createDefaultConfig('test-middleware-secret-should-be-long-enough-123456');
  const authService = new AuthService(adapter, config);
  await authService.register({ email: TEST_EMAIL, password: TEST_PASSWORD });
  return authService;
}

describe('ExpressAuthMiddleware', () => {
  let authService: AuthService;
  let middleware: ExpressAuthMiddleware;

  beforeAll(async () => {
    authService = await getAuthService();
    middleware = new ExpressAuthMiddleware(authService);
  });

  it('should authenticate with valid token', async () => {
    const login = await authService.login({ email: TEST_EMAIL, password: TEST_PASSWORD });
    const req = createMockRequest({ headers: { authorization: `Bearer ${login.tokens.accessToken}` } });
    const res = createMockResponse();
    const next = createMockNext();
    await middleware.authenticate()(
      req as any,
      res as any,
      next as any
    );
    expect((req as any).user).toBeDefined();
    expect(next).toHaveBeenCalled();
  });

  it('should reject with invalid token', async () => {
    const req = createMockRequest({ headers: { authorization: 'Bearer invalid' } });
    const res = createMockResponse();
    const next = createMockNext();
    await middleware.authenticate()(req as any, res as any, next as any);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalled();
  });

  it('should allow optional auth', async () => {
    const req = createMockRequest();
    const res = createMockResponse();
    const next = createMockNext();
    await middleware.authenticate({ optional: true })(req as any, res as any, next as any);
    expect(next).toHaveBeenCalled();
  });

  it('should check roles', () => {
    const req = createMockRequest();
    (req as any).user = { id: '1', email: 'a', passwordHash: '', createdAt: new Date(), updatedAt: new Date(), isActive: true, metadata: { roles: ['admin'] } };
    const res = createMockResponse();
    const next = createMockNext();
    middleware.requireRoles(['admin'])(req as any, res as any, next as any);
    expect(next).toHaveBeenCalled();
  });

  it('should reject if role missing', () => {
    const req = createMockRequest();
    (req as any).user = { id: '1', email: 'a', passwordHash: '', createdAt: new Date(), updatedAt: new Date(), isActive: true, metadata: { roles: ['user'] } };
    const res = createMockResponse();
    const next = createMockNext();
    middleware.requireRoles(['admin'])(req as any, res as any, next as any);
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('should check ownership', () => {
    const req = createMockRequest({ params: { id: '1' } });
    (req as any).user = { id: '1', email: 'a', passwordHash: '', createdAt: new Date(), updatedAt: new Date(), isActive: true, metadata: {} };
    const res = createMockResponse();
    const next = createMockNext();
    middleware.requireOwnership(r => r.params.id || '')(req as any, res as any, next as any);
    expect(next).toHaveBeenCalled();
  });

  it('should reject ownership if not owner', () => {
    const req = createMockRequest({ params: { id: '2' } });
    (req as any).user = { id: '1', email: 'a', passwordHash: '', createdAt: new Date(), updatedAt: new Date(), isActive: true, metadata: {} };
    const res = createMockResponse();
    const next = createMockNext();
    middleware.requireOwnership(r => r.params.id || '')(req as any, res as any, next as any);
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it('should rate limit requests', () => {
    const req = createMockRequest({ ip: '127.0.0.1' });
    const res = createMockResponse();
    const next = createMockNext();
    const limiter = middleware.rateLimiter({ windowMs: 1000, maxRequests: 2 });
    limiter(req as any, res as any, next as any);
    limiter(req as any, res as any, next as any);
    // 3e requête doit être bloquée
    limiter(req as any, res as any, next as any);
    expect(res.status).toHaveBeenCalledWith(429);
  });
}); 