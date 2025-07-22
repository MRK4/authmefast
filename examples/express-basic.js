// ============================================================================
// 🔐 AuthMeFast - Exemple Express basique
// ============================================================================

const express = require('express');
const { 
  createDevelopmentAuth,
  requireAuth, 
  optionalAuth, 
  AuthError,
  AuthErrorCode 
} = require('../dist'); // Utiliser 'authmefast' dans votre projet

const app = express();
app.use(express.json());

let authMeFast;

// ============================================================================
// Initialisation
// ============================================================================

async function initializeAuth() {
  try {
    // Créer une instance AuthMeFast pour le développement
    authMeFast = await createDevelopmentAuth('your-super-secret-jwt-key-at-least-32-characters');
    console.log('✅ AuthMeFast initialized successfully');
    
    const stats = await authMeFast.getStats();
    console.log('📊 Auth stats:', stats);
  } catch (error) {
    console.error('❌ Failed to initialize AuthMeFast:', error);
    process.exit(1);
  }
}

// ============================================================================
// Routes publiques
// ============================================================================

// Inscription
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password, metadata } = req.body;
    
    const result = await authMeFast.authService.register({
      email,
      password,
      metadata
    });

    // Ne pas renvoyer le passwordHash
    const { passwordHash, ...userPublic } = result.user;
    
    res.status(201).json({
      message: 'Inscription réussie',
      user: userPublic,
      tokens: result.tokens
    });
  } catch (error) {
    if (error instanceof AuthError) {
      return res.status(error.statusCode).json({
        error: error.message,
        code: error.code
      });
    }
    
    res.status(500).json({
      error: 'Erreur serveur lors de l\'inscription'
    });
  }
});

// Connexion
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const result = await authMeFast.authService.login({
      email,
      password
    });

    const { passwordHash, ...userPublic } = result.user;
    
    res.json({
      message: 'Connexion réussie',
      user: userPublic,
      tokens: result.tokens
    });
  } catch (error) {
    if (error instanceof AuthError) {
      return res.status(error.statusCode).json({
        error: error.message,
        code: error.code
      });
    }
    
    res.status(500).json({
      error: 'Erreur serveur lors de la connexion'
    });
  }
});

// Rafraîchissement de token
app.post('/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    const tokens = await authMeFast.authService.refreshToken(refreshToken);
    
    res.json({
      message: 'Token rafraîchi avec succès',
      tokens
    });
  } catch (error) {
    if (error instanceof AuthError) {
      return res.status(error.statusCode).json({
        error: error.message,
        code: error.code
      });
    }
    
    res.status(500).json({
      error: 'Erreur serveur lors du rafraîchissement'
    });
  }
});

// Déconnexion
app.post('/auth/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    await authMeFast.authService.logout(refreshToken);
    
    res.json({
      message: 'Déconnexion réussie'
    });
  } catch (error) {
    res.status(500).json({
      error: 'Erreur serveur lors de la déconnexion'
    });
  }
});

// ============================================================================
// Routes protégées
// ============================================================================

// Profil utilisateur (authentification requise)
app.get('/profile', requireAuth(authMeFast.authService), (req, res) => {
  const { passwordHash, ...userPublic } = req.user;
  
  res.json({
    message: 'Profil utilisateur',
    user: userPublic
  });
});

// Mise à jour du profil
app.put('/profile', requireAuth(authMeFast.authService), async (req, res) => {
  try {
    const { metadata } = req.body;
    
    const updatedUser = await authMeFast.authService.updateUser(req.user.id, {
      metadata: { ...req.user.metadata, ...metadata }
    });

    const { passwordHash, ...userPublic } = updatedUser;
    
    res.json({
      message: 'Profil mis à jour',
      user: userPublic
    });
  } catch (error) {
    if (error instanceof AuthError) {
      return res.status(error.statusCode).json({
        error: error.message,
        code: error.code
      });
    }
    
    res.status(500).json({
      error: 'Erreur serveur lors de la mise à jour'
    });
  }
});

// Changement de mot de passe
app.post('/auth/change-password', requireAuth(authMeFast.authService), async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    
    await authMeFast.authService.changePassword(req.user.id, oldPassword, newPassword);
    
    res.json({
      message: 'Mot de passe changé avec succès'
    });
  } catch (error) {
    if (error instanceof AuthError) {
      return res.status(error.statusCode).json({
        error: error.message,
        code: error.code
      });
    }
    
    res.status(500).json({
      error: 'Erreur serveur lors du changement de mot de passe'
    });
  }
});

// ============================================================================
// Routes avec authentification optionnelle
// ============================================================================

app.get('/public-content', optionalAuth(authMeFast.authService), (req, res) => {
  const content = {
    message: 'Contenu public accessible à tous',
    timestamp: new Date().toISOString()
  };

  if (req.user) {
    content.personalizedMessage = `Bonjour ${req.user.email} !`;
  }

  res.json(content);
});

// ============================================================================
// Utilitaires
// ============================================================================

// Évaluation de la force du mot de passe
app.post('/auth/password-strength', (req, res) => {
  const { password } = req.body;
  
  if (!authMeFast) {
    return res.status(500).json({ error: 'Service d\'authentification non initialisé' });
  }
  
  const assessment = authMeFast.authService.assessPasswordStrength(password);
  
  res.json({
    message: 'Évaluation de la force du mot de passe',
    assessment
  });
});

// Statistiques (développement uniquement)
app.get('/auth/stats', async (req, res) => {
  try {
    const stats = await authMeFast.getStats();
    res.json(stats);
  } catch (error) {
    res.status(500).json({
      error: 'Erreur lors de la récupération des statistiques'
    });
  }
});

// ============================================================================
// Gestion d'erreurs globale
// ============================================================================

app.use((error, req, res, next) => {
  console.error('Erreur non gérée:', error);
  
  res.status(500).json({
    error: 'Erreur serveur interne'
  });
});

// 404
app.use((req, res) => {
  res.status(404).json({
    error: 'Route non trouvée'
  });
});

// ============================================================================
// Démarrage du serveur
// ============================================================================

const PORT = process.env.PORT || 3000;

async function startServer() {
  await initializeAuth();
  
  app.listen(PORT, () => {
    console.log(`🚀 Serveur démarré sur le port ${PORT}`);
    console.log(`📖 API Documentation:`);
    console.log(`   POST   /auth/register       - Inscription`);
    console.log(`   POST   /auth/login          - Connexion`);
    console.log(`   POST   /auth/refresh        - Rafraîchir token`);
    console.log(`   POST   /auth/logout         - Déconnexion`);
    console.log(`   GET    /profile             - Profil (auth requis)`);
    console.log(`   PUT    /profile             - Maj profil (auth requis)`);
    console.log(`   POST   /auth/change-password - Changer mot de passe (auth requis)`);
    console.log(`   GET    /public-content      - Contenu public`);
    console.log(`   POST   /auth/password-strength - Test force mot de passe`);
    console.log(`   GET    /auth/stats          - Statistiques`);
  });
}

// Gestion propre de l'arrêt
process.on('SIGINT', async () => {
  console.log('\n🛑 Arrêt du serveur en cours...');
  
  if (authMeFast) {
    await authMeFast.close();
    console.log('✅ AuthMeFast fermé proprement');
  }
  
  process.exit(0);
});

startServer().catch(console.error); 