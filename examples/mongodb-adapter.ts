// ============================================================================
// 🔐 AuthMeFast - Adaptateur MongoDB
// ============================================================================

import { MongoClient, Db, Collection, MongoClientOptions } from 'mongodb';
import { nanoid } from 'nanoid';
import { User, DatabaseAdapter } from '../src/types';
import { BaseDatabaseAdapter } from '../src/adapters/base';

// ============================================================================
// Interfaces pour MongoDB
// ============================================================================

interface MongoUser {
  _id: string;
  email: string;
  passwordHash: string;
  isActive: boolean;
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

interface MongoRefreshToken {
  _id: string;
  token: string;
  userId: string;
  expiresAt: Date;
  createdAt: Date;
}

interface MongoLoginAttempt {
  _id: string;
  email: string;
  attempts: number;
  firstAttempt: Date;
  lastAttempt: Date;
  blockedUntil?: Date;
}

// ============================================================================
// Configuration MongoDB
// ============================================================================

export interface MongoAdapterConfig {
  uri: string;
  dbName: string;
  options?: MongoClientOptions;
  collections?: {
    users?: string;
    refreshTokens?: string;
    loginAttempts?: string;
  };
}

// ============================================================================
// Adaptateur MongoDB
// ============================================================================

export class MongoDBAdapter extends BaseDatabaseAdapter implements DatabaseAdapter {
  readonly name = 'MongoDBAdapter';
  
  private client: MongoClient;
  private db: Db | null = null;
  private config: MongoAdapterConfig;
  
  // Collections
  private usersCollection!: Collection<MongoUser>;
  private tokensCollection!: Collection<MongoRefreshToken>;
  private attemptsCollection!: Collection<MongoLoginAttempt>;

  constructor(config: MongoAdapterConfig) {
    super();
    this.config = {
      collections: {
        users: 'users',
        refreshTokens: 'refresh_tokens',
        loginAttempts: 'login_attempts'
      },
      ...config
    };
    
    this.client = new MongoClient(config.uri, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      maxIdleTimeMS: 30000,
      ...config.options
    });
  }

  get isConnected(): boolean {
    return this.db !== null;
  }

  // ========================================================================
  // Lifecycle
  // ========================================================================

  async connect(): Promise<void> {
    try {
      await this.client.connect();
      this.db = this.client.db(this.config.dbName);
      
      // Initialiser les collections
      this.usersCollection = this.db.collection<MongoUser>(this.config.collections!.users!);
      this.tokensCollection = this.db.collection<MongoRefreshToken>(this.config.collections!.refreshTokens!);
      this.attemptsCollection = this.db.collection<MongoLoginAttempt>(this.config.collections!.loginAttempts!);
      
      // Créer les index
      await this.createIndexes();
      
      console.log(`✅ MongoDB connected to ${this.config.dbName}`);
    } catch (error) {
      throw new Error(`Failed to connect to MongoDB: ${error}`);
    }
  }

  async disconnect(): Promise<void> {
    if (this.client) {
      await this.client.close();
      this.db = null;
      console.log('✅ MongoDB disconnected');
    }
  }

  async cleanup(): Promise<void> {
    this.ensureConnected();
    
    const now = new Date();
    
    // Nettoyer les tokens expirés
    await this.tokensCollection.deleteMany({
      expiresAt: { $lte: now }
    });
    
    // Nettoyer les tentatives de connexion anciennes (plus de 24h)
    const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    await this.attemptsCollection.deleteMany({
      lastAttempt: { $lte: dayAgo }
    });
  }

  // ========================================================================
  // Index et optimisations
  // ========================================================================

  private async createIndexes(): Promise<void> {
    try {
      // Index sur les utilisateurs
      await this.usersCollection.createIndex({ email: 1 }, { unique: true });
      await this.usersCollection.createIndex({ isActive: 1 });
      await this.usersCollection.createIndex({ createdAt: 1 });
      
      // Index sur les tokens
      await this.tokensCollection.createIndex({ token: 1 }, { unique: true });
      await this.tokensCollection.createIndex({ userId: 1 });
      await this.tokensCollection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
      
      // Index sur les tentatives de connexion
      await this.attemptsCollection.createIndex({ email: 1 }, { unique: true });
      await this.attemptsCollection.createIndex({ lastAttempt: 1 }, { expireAfterSeconds: 24 * 60 * 60 });
    } catch (error) {
      console.warn('Warning: Could not create all indexes:', error);
    }
  }

  // ========================================================================
  // Gestion des utilisateurs
  // ========================================================================

  async createUser(userData: Omit<User, 'id' | 'createdAt' | 'updatedAt'>): Promise<User> {
    this.ensureConnected();
    
    const id = nanoid();
    const now = new Date();
    
    const mongoUser: MongoUser = {
      _id: id,
      email: this.normalizeEmail(userData.email),
      passwordHash: userData.passwordHash,
      isActive: userData.isActive,
      metadata: userData.metadata || {},
      createdAt: now,
      updatedAt: now
    };
    
    try {
      await this.usersCollection.insertOne(mongoUser);
      
      return this.mongoUserToUser(mongoUser);
    } catch (error: any) {
      if (error.code === 11000) { // Duplicate key error
        throw new Error('User with this email already exists');
      }
      throw error;
    }
  }

  async findUserByEmail(email: string): Promise<User | null> {
    this.ensureConnected();
    
    const normalizedEmail = this.normalizeEmail(email);
    const mongoUser = await this.usersCollection.findOne({ email: normalizedEmail });
    
    return mongoUser ? this.mongoUserToUser(mongoUser) : null;
  }

  async findUserById(id: string): Promise<User | null> {
    this.ensureConnected();
    
    const mongoUser = await this.usersCollection.findOne({ _id: id });
    
    return mongoUser ? this.mongoUserToUser(mongoUser) : null;
  }

  async updateUser(id: string, updates: Partial<Omit<User, 'id' | 'createdAt'>>): Promise<User> {
    this.ensureConnected();
    
    const updateDoc: Partial<MongoUser> = {
      ...updates,
      updatedAt: new Date()
    };
    
    if (updates.email) {
      updateDoc.email = this.normalizeEmail(updates.email);
    }
    
    const result = await this.usersCollection.findOneAndUpdate(
      { _id: id },
      { $set: updateDoc },
      { returnDocument: 'after' }
    );
    
    if (!result) {
      throw new Error('User not found');
    }
    
    return this.mongoUserToUser(result);
  }

  async deleteUser(id: string): Promise<void> {
    this.ensureConnected();
    
    const result = await this.usersCollection.deleteOne({ _id: id });
    
    if (result.deletedCount === 0) {
      throw new Error('User not found');
    }
    
    // Nettoyer les tokens associés
    await this.revokeAllUserTokens(id);
  }

  // ========================================================================
  // Gestion des refresh tokens
  // ========================================================================

  async storeRefreshToken(userId: string, token: string, expiresAt: Date): Promise<void> {
    this.ensureConnected();
    
    const mongoToken: MongoRefreshToken = {
      _id: nanoid(),
      token,
      userId,
      expiresAt,
      createdAt: new Date()
    };
    
    await this.tokensCollection.insertOne(mongoToken);
  }

  async validateRefreshToken(token: string): Promise<string | null> {
    this.ensureConnected();
    
    const mongoToken = await this.tokensCollection.findOne({
      token,
      expiresAt: { $gt: new Date() }
    });
    
    return mongoToken ? mongoToken.userId : null;
  }

  async revokeRefreshToken(token: string): Promise<void> {
    this.ensureConnected();
    
    await this.tokensCollection.deleteOne({ token });
  }

  async revokeAllUserTokens(userId: string): Promise<void> {
    this.ensureConnected();
    
    await this.tokensCollection.deleteMany({ userId });
  }

  // ========================================================================
  // Rate limiting
  // ========================================================================

  async incrementLoginAttempts(email: string): Promise<number> {
    this.ensureConnected();
    
    const normalizedEmail = this.normalizeEmail(email);
    const now = new Date();
    
    const result = await this.attemptsCollection.findOneAndUpdate(
      { email: normalizedEmail },
      {
        $inc: { attempts: 1 },
        $set: { lastAttempt: now },
        $setOnInsert: {
          _id: nanoid(),
          email: normalizedEmail,
          firstAttempt: now
        }
      },
      {
        upsert: true,
        returnDocument: 'after'
      }
    );
    
    const attempt = result!;
    
    // Réinitialiser si plus de 15 minutes depuis la première tentative
    const fifteenMinutesAgo = new Date(now.getTime() - 15 * 60 * 1000);
    if (attempt.firstAttempt <= fifteenMinutesAgo) {
      await this.attemptsCollection.updateOne(
        { email: normalizedEmail },
        {
          $set: {
            attempts: 1,
            firstAttempt: now,
            lastAttempt: now,
            $unset: { blockedUntil: 1 }
          }
        }
      );
      return 1;
    }
    
    // Bloquer après 5 tentatives pour 1 heure
    if (attempt.attempts >= 5) {
      await this.attemptsCollection.updateOne(
        { email: normalizedEmail },
        {
          $set: {
            blockedUntil: new Date(now.getTime() + 60 * 60 * 1000)
          }
        }
      );
    }
    
    return attempt.attempts;
  }

  async resetLoginAttempts(email: string): Promise<void> {
    this.ensureConnected();
    
    const normalizedEmail = this.normalizeEmail(email);
    await this.attemptsCollection.deleteOne({ email: normalizedEmail });
  }

  async isRateLimited(email: string): Promise<boolean> {
    this.ensureConnected();
    
    const normalizedEmail = this.normalizeEmail(email);
    const attempt = await this.attemptsCollection.findOne({ email: normalizedEmail });
    
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
      await this.resetLoginAttempts(normalizedEmail);
      return false;
    }
    
    return false;
  }

  // ========================================================================
  // Statistiques
  // ========================================================================

  async getStats(): Promise<{
    isConnected: boolean;
    name: string;
    userCount: number;
    activeTokens: number;
    database: string;
  }> {
    await this.cleanup(); // Nettoyer avant de compter
    
    const userCount = await this.usersCollection.countDocuments();
    const activeTokens = await this.tokensCollection.countDocuments({
      expiresAt: { $gt: new Date() }
    });
    
    return {
      isConnected: this.isConnected,
      name: this.name,
      userCount,
      activeTokens,
      database: this.config.dbName
    };
  }

  // ========================================================================
  // Utilitaires privés
  // ========================================================================

  private mongoUserToUser(mongoUser: MongoUser): User {
    return {
      id: mongoUser._id,
      email: mongoUser.email,
      passwordHash: mongoUser.passwordHash,
      isActive: mongoUser.isActive,
      metadata: mongoUser.metadata,
      createdAt: mongoUser.createdAt,
      updatedAt: mongoUser.updatedAt
    };
  }
}

// ============================================================================
// Factory function
// ============================================================================

export function createMongoDBAdapter(config: MongoAdapterConfig): MongoDBAdapter {
  return new MongoDBAdapter(config);
}

// ============================================================================
// Exemple d'utilisation
// ============================================================================

/*
import { AuthService, createDefaultConfig, MongoDBAdapter } from 'authmefast';

async function setupAuthWithMongoDB() {
  const adapter = new MongoDBAdapter({
    uri: 'mongodb://localhost:27017',
    dbName: 'myapp',
    options: {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000
    },
    collections: {
      users: 'users',
      refreshTokens: 'refresh_tokens', 
      loginAttempts: 'login_attempts'
    }
  });
  
  const config = createDefaultConfig('your-jwt-secret');
  const authService = new AuthService(adapter, config);
  
  await adapter.connect();
  
  return authService;
}
*/ 