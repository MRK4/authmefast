import { MemoryDatabaseAdapter } from '../src/adapters/memory';
import { User } from '../src/types';

describe('MemoryDatabaseAdapter', () => {
  let adapter: MemoryDatabaseAdapter;
  let user: User;

  beforeEach(async () => {
    adapter = new MemoryDatabaseAdapter();
    await adapter.connect();
    user = await adapter.createUser({
      email: 'test@adapter.com',
      passwordHash: 'hash',
      isActive: true,
      metadata: { role: 'user' }
    });
  });

  afterEach(async () => {
    await adapter.disconnect();
  });

  it('should create and find user by email', async () => {
    const found = await adapter.findUserByEmail('test@adapter.com');
    expect(found).toBeDefined();
    expect(found!.email).toBe('test@adapter.com');
  });

  it('should find user by id', async () => {
    const found = await adapter.findUserById(user.id);
    expect(found).toBeDefined();
    expect(found!.id).toBe(user.id);
  });

  it('should update user metadata', async () => {
    const updated = await adapter.updateUser(user.id, { metadata: { role: 'admin' } });
    expect(updated.metadata.role).toBe('admin');
  });

  it('should delete user', async () => {
    await adapter.deleteUser(user.id);
    const found = await adapter.findUserById(user.id);
    expect(found).toBeNull();
  });

  it('should store and validate refresh token', async () => {
    await adapter.storeRefreshToken(user.id, 'token123', new Date(Date.now() + 10000));
    const userId = await adapter.validateRefreshToken('token123');
    expect(userId).toBe(user.id);
  });

  it('should revoke refresh token', async () => {
    await adapter.storeRefreshToken(user.id, 'token123', new Date(Date.now() + 10000));
    await adapter.revokeRefreshToken('token123');
    const userId = await adapter.validateRefreshToken('token123');
    expect(userId).toBeNull();
  });

  it('should handle rate limiting', async () => {
    for (let i = 0; i < 5; i++) {
      await adapter.incrementLoginAttempts(user.email);
    }
    const limited = await adapter.isRateLimited(user.email);
    expect(limited).toBe(true);
    await adapter.resetLoginAttempts(user.email);
    const limitedAfterReset = await adapter.isRateLimited(user.email);
    expect(limitedAfterReset).toBe(false);
  });

  it('should get stats', async () => {
    const stats = await adapter.getStats();
    expect(stats.isConnected).toBe(true);
    expect(stats.userCount).toBeGreaterThanOrEqual(1);
  });
}); 