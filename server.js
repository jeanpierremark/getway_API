const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
require('dotenv').config();
const cors = require('cors');


const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors({
  origin: ['http://localhost:4200'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Proxy vers User-Service
app.use('/users', createProxyMiddleware({
  target: process.env.USER_SERVICE_URL,
  changeOrigin: true,
  pathRewrite: { '^/users': '' }
}));

// Proxy vers Data-Service pour chercheur
app.use('/data_chercheur', createProxyMiddleware({
  target: process.env.Data_SERVICE_URL,
  changeOrigin: true,
  pathRewrite: { '^/data_chercheur': '' }
}));


// Démarrer la gateway
app.listen(PORT, () => {
  console.log(`API Gateway is running on http://localhost:${PORT}`);
});
