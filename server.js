require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const morgan    = require('morgan');
const rateLimit = require('express-rate-limit');

const authRoutes   = require('./routes/auth');
const scanRoutes   = require('./routes/scan');
const reportRoutes = require('./routes/report');

const app  = express();
const PORT = process.env.PORT || 5000;

// ─────────────────────────────────────────────
//  SECURITY MIDDLEWARE
// ─────────────────────────────────────────────
app.use(helmet());
app.set('trust proxy', 1);

// CORS
const allowedOrigins = (process.env.CORS_ORIGINS || 'http://localhost:3000')
  .split(',').map(o => o.trim());

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS policy: origin ${origin} not allowed`));
    }
  },
  credentials: true,
}));

// Rate limiting
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  standardHeaders: true,
  message: { success: false, message: 'Too many requests. Please wait a moment.' },
});

const scanLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  message: { success: false, message: 'Too many scans. Please slow down.' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: 'Too many auth attempts. Please wait 15 minutes.' },
});

app.use(globalLimiter);

// Body parsing
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false }));

// Logging
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
}

// ─────────────────────────────────────────────
//  HEALTH CHECK
// ─────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    success: true,
    service: 'Tracesite API',
    status:  'operational',
    time:    new Date().toISOString(),
    version: '1.0.0',
  });
});

// ─────────────────────────────────────────────
//  API ROUTES
// ─────────────────────────────────────────────
app.use('/api/auth',   authLimiter, authRoutes);
app.use('/api/scan',   scanLimiter, scanRoutes);
app.use('/api/report', reportRoutes);

// ─────────────────────────────────────────────
//  ROOT
// ─────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🛡️ Welcome to the Tracesite API — Protecting Nigeria\'s Digital Future',
    docs: {
      health:  'GET  /health',
      auth: {
        register: 'POST /api/auth/register',
        login:    'POST /api/auth/login',
        me:       'GET  /api/auth/me  [auth]',
      },
      scan: {
        analyze: 'POST /api/scan',
        history: 'GET  /api/scan/history  [auth]',
        lookup:  'GET  /api/scan/lookup?url=...',
        stats:   'GET  /api/scan/stats  [admin]',
      },
      report: {
        submit:     'POST  /api/report  [auth]',
        byUrl:      'GET   /api/report/url?url=...',
        topFlagged: 'GET   /api/report/top-flagged',
        pending:    'GET   /api/report/pending  [admin]',
        review:     'PATCH /api/report/:id  [admin]',
      },
    },
  });
});

// ─────────────────────────────────────────────
//  404 HANDLER
// ─────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: `Route ${req.method} ${req.path} not found.` });
});

// ─────────────────────────────────────────────
//  GLOBAL ERROR HANDLER
// ─────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(err.status || 500).json({
    success: false,
    message: process.env.NODE_ENV === 'production'
      ? 'An unexpected error occurred.'
      : err.message,
  });
});

// ─────────────────────────────────────────────
//  START SERVER
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
  ┌─────────────────────────────────────────┐
  │   🛡️  TRACESITE API — Server Running    │
  │   Port    : ${PORT}                        │
  │   Env     : ${process.env.NODE_ENV || 'development'}                 │
  │   VT API  : ${process.env.VIRUSTOTAL_API_KEY ? '✅ Connected' : '⚠️  Not configured'}           │
  └─────────────────────────────────────────┘
  `);
});

module.exports = app;
