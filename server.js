const express = require('express');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');
require('dotenv').config();
const cors = require('cors');
const NodeCache = require('node-cache');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3001;

// Cache unique pour toutes les réponses
const responseCache = new NodeCache({ 
  stdTTL: 3600,      
  checkperiod: 60,  
  useClones: false   
});

// Configuration CORS
app.use(cors({
  origin: ['http://localhost:4200'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Middleware pour extraire le token
const extractToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    req.token = token;
    console.log(`[${new Date().toISOString()}] Token récupéré pour ${req.method} ${req.url}`);
  } else {
    req.token = null;
  }
  
  next();
};

// Fonction pour déterminer si une requête doit utiliser un cache partagé
const shouldUseSharedCache = (req) => {
  const sharedCacheRoutes = [
    '/climate_data_weather',    
    '/stations',                 
    '/parametres',               
    '/config'                   
  ];
  
  return sharedCacheRoutes.some(route => req.originalUrl.includes(route));
};

// Fonction pour générer une clé de cache (avec option cache partagé)
const generateCacheKey = (req) => {
  const method = req.method;
  const url = req.originalUrl;
  const queryParams = JSON.stringify(req.query);
  const bodyParams = req.body ? JSON.stringify(req.body) : '';
  
  // DÉCISION: Cache partagé ou cache par utilisateur
  let userIdentifier = '';
  if (shouldUseSharedCache(req)) {
    // Cache partagé : pas d'identifiant utilisateur
    userIdentifier = 'shared';
    console.log(`[CACHE KEY] Mode partagé pour ${url}`);
  } else {
    // Cache privé : inclure le hash du token
    userIdentifier = req.token ? 
      crypto.createHash('md5').update(req.token).digest('hex').substring(0, 8) : 
      'anonymous';
    console.log(`[CACHE KEY] Mode privé pour ${url} - User: ${userIdentifier}`);
  }
  
  const keyString = `${method}:${url}:${queryParams}:${bodyParams}:${userIdentifier}`;
  return crypto.createHash('md5').update(keyString).digest('hex');
};

// Fonction pour déterminer si une requête doit être cachée
const shouldCacheRequest = (req) => {
  const noCacheRoutes = ['/login', '/register', '/logout'];
  if (noCacheRoutes.some(route => req.originalUrl.includes(route))) {
    return false;
  }
  
  if (req.method !== 'GET') {
    return false;
  }
  
  return true;
};

// Fonction pour déterminer le TTL selon le type de données
const getCacheTTL = (req) => {
  const url = req.originalUrl; 
  if (url.includes('/user') || url.includes('/activity') || url.includes('/info') || url.includes('/chercheur/meteo_open') || url.includes('/chercheur/meteo_openweather') || url.includes('/chercheur/meteo_weather')) {
    return 5; 
  }
    return 1200; 
};

// Middleware pour protéger les routes
const requireAuth = (req, res, next) => {
  if (!req.token) {
    return res.status(401).json({ 
      error: 'Token d\'authentification requis',
      message: 'Veuillez vous connecter pour accéder à cette ressource'
    });
  }
  next();
};

// MIDDLEWARE PRINCIPAL DE CACHE - Simplifié pour ne gérer que la vérification en amont
const masterCacheMiddleware = (req, res, next) => {
  console.log(`[MIDDLEWARE] Traitement de ${req.method} ${req.originalUrl}`);
  
  // Vérifier si cette requête doit être cachée
  if (!shouldCacheRequest(req)) {
    console.log(`[CACHE] Requête ${req.method} ${req.originalUrl} - PAS DE CACHE`);
    return next();
  }
  
  // Générer la clé de cache
  const cacheKey = generateCacheKey(req);
  
  console.log(`[CACHE DEBUG] Clé générée: ${cacheKey}`);
  console.log(`[CACHE DEBUG] Token hash: ${req.token ? crypto.createHash('md5').update(req.token).digest('hex').substring(0, 8) : 'anonymous'}`);
  
  // Vérifier le cache AVANT
  const cachedResponse = responseCache.get(cacheKey);
  console.log(`[CACHE DEBUG] Cache lookup: ${cachedResponse ? 'TROUVÉ' : 'NON TROUVÉ'}`);
  console.log(`[CACHE DEBUG] Nombre total de clés: ${responseCache.keys().length}`);
  
  if (cachedResponse) {
    console.log(`[CACHE HIT] ${req.method} ${req.originalUrl} - Réponse depuis le cache`);
    
    if (cachedResponse.headers) {
      Object.keys(cachedResponse.headers).forEach(headerName => {
        res.setHeader(headerName, cachedResponse.headers[headerName]);
      });
    }
    
    res.setHeader('X-Cache', 'HIT');
    res.setHeader('X-Cache-Key', cacheKey.substring(0, 8));
    
    return res.status(cachedResponse.statusCode || 200).json(cachedResponse.body);
  }
  
  console.log(`[CACHE MISS] ${req.method} ${req.originalUrl} - Appel au backend`);
  
  // Pas d'override res.json/send ici, car géré par le proxy
  next();
};

// Appliquer les middlewares de base
app.use(extractToken);
app.use(masterCacheMiddleware); // CACHE PRINCIPAL

// Fonction helper pour créer un proxy avec interception de réponse
const createProxyWithCache = (target) => {
  return createProxyMiddleware({
    target,
    changeOrigin: true,
    logLevel: 'debug',
    selfHandleResponse: true, // IMPORTANT : Le proxy ne gère pas l'envoi auto de la réponse
    
    on: {
      proxyReq: (proxyReq, req, res) => {
        console.log(`[PROXY REQ] ${req.method} ${req.originalUrl} -> ${target}`);
        if (req.token) {
          proxyReq.setHeader('Authorization', `Bearer ${req.token}`);
        }
      },
      
      proxyRes: responseInterceptor(async (buffer, proxyRes, req, res) => {
        console.log(`[INTERCEPT] Interception réponse - Status: ${proxyRes.statusCode}`);
        
        // Copier le status et les headers
        res.statusCode = proxyRes.statusCode;
        Object.entries(proxyRes.headers).forEach(([key, value]) => {
          res.setHeader(key, value);
        });
        
        // Vérifier si on doit cacher
        if (!shouldCacheRequest(req) || res.statusCode < 200 || res.statusCode >= 300) {
          console.log(`[CACHE SKIP] Pas de cache pour cette réponse`);
          return buffer; // Retourner le buffer inchangé
        }
        
        // Générer la clé et TTL
        const cacheKey = generateCacheKey(req);
        const cacheTTL = getCacheTTL(req);
        
        try {
          let parsedBody = buffer;
          const contentType = proxyRes.headers['content-type'];
          
          // Parser si JSON
          if (contentType && contentType.includes('application/json')) {
            parsedBody = JSON.parse(buffer.toString('utf8'));
          } else {
            // Si non JSON, stocker comme string
            parsedBody = buffer.toString('utf8');
          }
          
          const cacheData = {
            statusCode: res.statusCode,
            headers: { ...res.getHeaders() },
            body: parsedBody,
            cachedAt: new Date().toISOString()
          };
          
          // Nettoyer les headers sensibles
          delete cacheData.headers['set-cookie'];
          delete cacheData.headers['authorization'];
          
          responseCache.set(cacheKey, cacheData, cacheTTL);
          
          console.log(`[CACHE SET] Réponse cachée - Clé: ${cacheKey.substring(0, 8)} - TTL: ${cacheTTL}s`);
          console.log(`[CACHE SET] Status: ${res.statusCode}, Size: ${buffer.length} bytes`);
          
          // Vérification immédiate
          const verify = responseCache.get(cacheKey);
          console.log(`[CACHE SET] Vérification immédiate: ${verify ? ' OK' : '❌ ÉCHEC'}`);
          console.log(`[CACHE SET] Total clés maintenant: ${responseCache.keys().length}`);
          
          res.setHeader('X-Cache', 'MISS');
          res.setHeader('X-Cache-Key', cacheKey.substring(0, 8));
          
        } catch (error) {
          console.error(`[CACHE ERROR] Erreur stockage:`, error.message, error.stack);
        }
        
        // Retourner le buffer original pour envoi au client
        return buffer;
      }),
      
      error: (err, req, res) => {
        console.error(`[PROXY ERROR] ${err.message}`);
        if (!res.headersSent) {
          res.status(500).json({ error: `Erreur au niveau du serveur veillez réessayer après un instant `, message: err.message });
        }
      }
    }
  });
};

// Routes avec proxy
const userServiceProxy = createProxyWithCache(process.env.USER_SERVICE_URL);
const dataServiceProxy = createProxyWithCache(process.env.DATA_SERVICE_URL);

app.use('/users/login', userServiceProxy);
app.use('/users/register', userServiceProxy);
app.use('/users', requireAuth, userServiceProxy);
app.use('/data_chercheur', requireAuth, dataServiceProxy);

// Routes de gestion du cache
app.get('/cache/stats', (req, res) => {
  const stats = responseCache.getStats();
  const keys = responseCache.keys();
  
  res.json({
    statistics: stats,
    totalKeys: keys.length,
    hitRate: ((stats.hits / (stats.hits + stats.misses)) * 100).toFixed(2) + '%' || '0%',
    keys: keys.slice(0, 5),
    message: 'Statistiques du cache'
  });
});

app.get('/cache/debug', (req, res) => {
  const keys = responseCache.keys();
  const details = {};
  
  keys.forEach(key => {
    const data = responseCache.get(key);
    if (data) {
      details[key.substring(0, 16) + '...'] = {
        fullKey: key,
        cachedAt: data.cachedAt,
        statusCode: data.statusCode,
        bodySize: JSON.stringify(data.body).length,
        ttl: responseCache.getTtl(key)
      };
    }
  });
  
  res.json({
    totalKeys: keys.length,
    cacheStats: responseCache.getStats(),
    details: details,
    allKeys: keys
  });
});

app.delete('/cache/clear', requireAuth, (req, res) => {
  const count = responseCache.keys().length;
  responseCache.flushAll();
  console.log(`[CACHE] Cache vidé - ${count} entrées`);
  res.json({ message: 'Cache vidé', clearedEntries: count });
});

app.get('/health', (req, res) => {
  const stats = responseCache.getStats();
  res.json({
    status: 'healthy',
    cache: {
      hits: stats.hits,
      misses: stats.misses,
      keys: stats.keys,
      hitRate: ((stats.hits / (stats.hits + stats.misses)) * 100).toFixed(1) + '%' || '0%'
    },
    services: {
      userService: process.env.USER_SERVICE_URL,
      dataService: process.env.DATA_SERVICE_URL
    }
  });
});

app.get('/', (req, res) => {
  res.json({
    message: 'API Gateway v4.0 - Cache Master Middleware',
    version: '4.0.0',
    cache: { enabled: true, type: 'master-middleware' }
  });
});

app.use((err, req, res, next) => {
  console.error('[ERROR GLOBAL]:', err);
  if (!res.headersSent) {
    res.status(500).json({ error: 'Erreur serveur', message: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`\n API Gateway v4.0 démarré sur http://localhost:${PORT}`);
  console.log(`\n Services: User=${process.env.USER_SERVICE_URL} | Data=${process.env.DATA_SERVICE_URL}`);
});