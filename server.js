const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
require('dotenv').config();
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// Configuration CORS AVANT les autres middlewares
app.use(cors({
  origin: ['http://localhost:4200'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Middleware pour extraire et valider le token
const extractToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    req.token = token;
    console.log(`[${new Date().toISOString()}] Token récupéré pour ${req.method} ${req.url}`);
  } else {
    console.log(`[${new Date().toISOString()}] Aucun token trouvé pour ${req.method} ${req.url}`);
    req.token = null;
  }
  
  next();
};

// Configuration du proxy CORRIGÉE
const createAuthProxyMiddleware = (target, pathRewrite) => {
  return createProxyMiddleware({
    target: target,
    changeOrigin: true,
    pathRewrite: pathRewrite,
    
    // Configuration des timeouts
    timeout: 30000,
    proxyTimeout: 30000,
    
    // Logs détaillés
    logLevel: 'debug',
    
    // CORRECTION 1: Ne pas parser le body ici, laisser http-proxy-middleware s'en charger
    parseReqBody: false,
    
    onProxyReq: (proxyReq, req, res) => {
      console.log(`[PROXY] ${req.method} ${req.originalUrl} -> ${target}${proxyReq.path}`);
      
      // Transmettre le token au service cible
      if (req.token) {
        proxyReq.setHeader('Authorization', `Bearer ${req.token}`);
        console.log(`[PROXY] Token transmis au service ${target}`);
      }
      
      // CORRECTION 2: Gestion simplifiée du body
      // Transmettre le Content-Type original
      if (req.headers['content-type']) {
        proxyReq.setHeader('Content-Type', req.headers['content-type']);
      }
      
      // Transmettre d'autres headers importants
      const headersToForward = ['accept', 'user-agent', 'referer', 'content-length'];
      headersToForward.forEach(header => {
        if (req.headers[header]) {
          proxyReq.setHeader(header, req.headers[header]);
        }
      });
      
      console.log(`[PROXY] Headers envoyés:`, proxyReq.getHeaders());
    },
    
    onProxyRes: (proxyRes, req, res) => {
      console.log(`[PROXY] Réponse: ${proxyRes.statusCode} de ${target} pour ${req.method} ${req.originalUrl}`);
      
      // Transmettre les headers de réponse CORS si nécessaire
      if (proxyRes.headers['access-control-allow-origin']) {
        res.setHeader('Access-Control-Allow-Origin', proxyRes.headers['access-control-allow-origin']);
      }
    },
    
    onError: (err, req, res) => {
      console.error(`[PROXY ERROR] ${err.code || 'UNKNOWN'}: ${err.message}`);
      console.error(`[PROXY ERROR] Target: ${target}`);
      console.error(`[PROXY ERROR] Request: ${req.method} ${req.originalUrl}`);
      
      if (!res.headersSent) {
        res.status(500).json({ 
          error: 'Erreur de communication avec le service',
          message: err.message,
          code: err.code,
          target: target
        });
      }
    }
  });
};

// CORRECTION 3: Appliquer le middleware d'extraction de token AVANT les parsers
app.use(extractToken);

// CORRECTION 4: Middleware pour parser le JSON ET les données URL-encoded
// SEULEMENT pour les routes qui ne sont PAS proxifiées
const conditionalBodyParser = (req, res, next) => {
  // Ne pas parser le body pour les routes qui seront proxifiées
  const proxiedRoutes = ['/users/', '/data_chercheur/'];
  const isProxiedRoute = proxiedRoutes.some(route => req.path.startsWith(route));
  
  if (isProxiedRoute) {
    return next();
  }
  
  // Parser le body seulement pour les routes locales
  express.json({ limit: '10mb' })(req, res, () => {
    express.urlencoded({ extended: true, limit: '10mb' })(req, res, next);
  });
};

app.use(conditionalBodyParser);

// Routes protégées - nécessitent un token
const requireAuth = (req, res, next) => {
  if (!req.token) {
    return res.status(401).json({ 
      error: 'Token d\'authentification requis',
      message: 'Veuillez vous connecter pour accéder à cette ressource'
    });
  }
  next();
};

// Middleware de debug pour les routes spécifiques
const debugRoute = (routeName) => (req, res, next) => {
  console.log(`[${routeName}] ${req.method} ${req.originalUrl}`);
  console.log(`[${routeName}] Content-Type:`, req.headers['content-type']);
  console.log(`[${routeName}] Content-Length:`, req.headers['content-length']);
  console.log(`[${routeName}] Token présent:`, !!req.token);
  next();
};

// Routes publiques (pas d'auth requise)
app.use('/users/login', 
  debugRoute('LOGIN'),
  createAuthProxyMiddleware(
    process.env.USER_SERVICE_URL,
    { '^/users/login': '' }
  )
);

app.use('/users/register', 
  debugRoute('REGISTER'),
  createAuthProxyMiddleware(
    process.env.USER_SERVICE_URL,
    { '^/users/register': '' }
  )
);

// Routes protégées pour les utilisateurs
app.use('/users', 
  requireAuth, 
  debugRoute('USERS'),
  createAuthProxyMiddleware(
    process.env.USER_SERVICE_URL,
    { '^/users': '' }
  )
);

// Proxy vers Data-Service pour chercheur (routes protégées)
app.use('/data_chercheur', 
  requireAuth, 
  debugRoute('DATA_CHERCHEUR'),
  createAuthProxyMiddleware(
    process.env.DATA_SERVICE_URL,
    { '^/data_chercheur': '' }
  )
);

// Route de test pour vérifier le token
app.get('/verify-token', (req, res) => {
  if (req.token) {
    res.json({ 
      message: 'Token reçu avec succès',
      tokenPreview: req.token.substring(0, 20) + '...'
    });
  } else {
    res.status(401).json({ 
      error: 'Aucun token fourni'
    });
  }
});

// Route de test de santé
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    services: {
      userService: process.env.USER_SERVICE_URL,
      dataService: process.env.DATA_SERVICE_URL
    }
  });
});

// Middleware de gestion d'erreurs globale
app.use((err, req, res, next) => {
  console.error('[GLOBAL ERROR]:', err);
  if (!res.headersSent) {
    res.status(500).json({
      error: 'Erreur interne du serveur',
      message: err.message
    });
  }
});

// Route par défaut
app.get('/', (req, res) => {
  res.json({
    message: 'API Gateway actif',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    services: {
      users: process.env.USER_SERVICE_URL,
      data_chercheur: process.env.DATA_SERVICE_URL
    }
  });
});

// Démarrer la gateway
app.listen(PORT, () => {
  console.log(`API Gateway is running on http://localhost:${PORT}`);
  console.log('Services configurés:');
  console.log(`- User Service: ${process.env.USER_SERVICE_URL}`);
  console.log(`- Data Service: ${process.env.DATA_SERVICE_URL}`);
  console.log('Routes disponibles:');
  console.log('- POST /users/login (public)');
  console.log('- POST /users/register (public)');
  console.log('- * /users/* (protégé)');
  console.log('- * /data_chercheur/* (protégé)');
  console.log('- GET /health (test)');
  console.log('- GET /verify-token (test)');
});

