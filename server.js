const express = require('express');
const cors    = require('cors');
const { RateLimiterMemory } = require('rate-limiter-flexible');

// ── Firebase SDK ───────────────────────────────────────
const { initializeApp, getApps }     = require('firebase/app');
const { getDatabase, ref, set, get, update, push } = require('firebase/database');

const firebaseConfig = {
  apiKey:            'AIzaSyAOjsSZrGmHK3E5QjGT-IamhPX9QLOt_Qk',
  authDomain:        'pixelwar2-69b05.firebaseapp.com',
  databaseURL:       'https://pixelwar2-69b05-default-rtdb.europe-west1.firebasedatabase.app',
  projectId:         'pixelwar2-69b05',
  storageBucket:     'pixelwar2-69b05.firebasestorage.app',
  messagingSenderId: '216084370377',
  appId:             '1:216084370377:web:c9ab6b4f22a5829898ce18',
};

const firebaseApp = getApps().length === 0 ? initializeApp(firebaseConfig) : getApps()[0];
const db          = getDatabase(firebaseApp);

// ── Express ────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3001;

// ── Admin key ──────────────────────────────────────────
// En prod : définir la variable d'environnement ADMIN_KEY
// Ex sur Railway : Settings → Variables → ADMIN_KEY=monMotDePasseSecret
const ADMIN_KEY = process.env.ADMIN_KEY;
if (!ADMIN_KEY) {
  console.error('⛔ ADMIN_KEY non définie ! Définissez la variable d\'environnement ADMIN_KEY avant de lancer en prod.');
  console.warn('   En dev : ADMIN_KEY=secret node server.js');
  process.exit(1); // refuse de démarrer sans clé admin
}

app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
app.use(express.json({ limit: '10kb' })); // limite taille body

// ── État admin (mémoire uniquement) ────────────────────
// panicMode : remis à false au redémarrage (comportement voulu)
// bannedIPs : perdus au redémarrage → à refaire si nécessaire
// Pour persister les bans, utilisez les règles Firebase directement
let panicMode = false;
let bannedIPs = new Set();

async function loadAdminState() {
  // Rien à charger — état repart à zéro au redémarrage
  console.log(`🛡️  Admin prêt : panic=false, bans=0`);
}

async function saveAdminState() {
  // No-op : on ne persiste plus dans Firebase pour éviter les erreurs de règles
  // Le panicMode et les bans sont en mémoire RAM du serveur
}

// ── Rate limiters ──────────────────────────────────────
const COOLDOWN_SECS   = 5;
const CHAT_LIMIT_SECS = 3; // 1 message toutes les 3s

const rateLimiterByUID = new RateLimiterMemory({
  points: 1, duration: COOLDOWN_SECS, blockDuration: COOLDOWN_SECS,
});
const rateLimiterByIP = new RateLimiterMemory({
  points: 10, duration: COOLDOWN_SECS, blockDuration: COOLDOWN_SECS,
});
const chatLimiterByUID = new RateLimiterMemory({
  points: 1, duration: CHAT_LIMIT_SECS, blockDuration: CHAT_LIMIT_SECS,
});
const chatLimiterByIP = new RateLimiterMemory({
  points: 5, duration: 10, blockDuration: 30, // 5 msgs/10s par IP, sinon ban 30s
});

function getIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0].trim()
      || req.socket?.remoteAddress || 'unknown';
}

// ── Validation ─────────────────────────────────────────
const COLOR_RE = /^#[0-9a-fA-F]{6}$/;
const SIZE     = 50;

function validCoords(x, y) {
  return Number.isInteger(x) && Number.isInteger(y)
      && x >= 0 && x < SIZE && y >= 0 && y < SIZE;
}

// ── Vérification token Firebase ────────────────────────
let adminAuth = null;
try {
  const admin   = require('firebase-admin');
  const keyPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (!admin.apps.length && keyPath) {
    admin.initializeApp({
      credential:  admin.credential.applicationDefault(),
      databaseURL: firebaseConfig.databaseURL,
    });
    adminAuth = admin.auth();
    console.log('🔐 Vérification tokens Firebase : ACTIVÉE');
  } else {
    console.warn('⚠️  Mode dév : tokens non vérifiés (GOOGLE_APPLICATION_CREDENTIALS non défini)');
  }
} catch (e) {
  console.warn('⚠️  firebase-admin absent → tokens non vérifiés en dev');
}

async function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer '))
    return res.status(401).json({ error: 'Token manquant' });

  const token = authHeader.split(' ')[1];

  if (adminAuth) {
    try {
      const decoded = await adminAuth.verifyIdToken(token);
      req.uid = decoded.uid;
      next();
    } catch (e) {
      return res.status(403).json({ error: 'Token invalide ou expiré' });
    }
  } else {
    // Dev : décoder le JWT sans vérifier la signature
    try {
      const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
      req.uid = payload.sub || payload.user_id || 'dev_user';
    } catch {
      req.uid = 'dev_user';
    }
    next();
  }
}

// ── Middleware admin ───────────────────────────────────
function verifyAdmin(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.key;
  if (!key || key !== ADMIN_KEY)
    return res.status(403).json({ error: 'Clé admin incorrecte' });
  next();
}

// ── Routes publiques ───────────────────────────────────
app.get('/status', (_req, res) => {
  res.json({ ok: true, panicMode, gridSize: SIZE, timestamp: Date.now() });
});

app.get('/stats', async (_req, res) => {
  try {
    const snap = await get(ref(db, 'grid'));
    res.json({ pixelCount: Object.keys(snap.val() || {}).length });
  } catch (e) {
    res.json({ pixelCount: 0 });
  }
});

app.get('/cooldown', verifyToken, async (req, res) => {
  try {
    await rateLimiterByUID.consume(req.uid, 0);
    res.json({ cooldown: 0, canPlace: true });
  } catch (r) {
    res.json({ cooldown: Math.ceil((r.msBeforeNext || 0) / 1000), canPlace: false });
  }
});

// ── Placer un pixel ────────────────────────────────────
app.post('/place-pixel', verifyToken, async (req, res) => {
  if (panicMode)
    return res.status(503).json({ error: '🚨 Placements suspendus par l\'administrateur' });

  const ip = getIP(req);
  if (bannedIPs.has(ip))
    return res.status(403).json({ error: 'Accès refusé' });

  const { x, y, color } = req.body;

  if (!validCoords(x, y))
    return res.status(400).json({ error: 'Coordonnées invalides' });
  if (!color || !COLOR_RE.test(color))
    return res.status(400).json({ error: 'Couleur invalide' });

  const pseudo = String(req.body.pseudo || 'Anonyme').substring(0, 20);
  if (pseudo.length < 1)
    return res.status(400).json({ error: 'Pseudo invalide' });

  // Cooldown par UID
  try {
    await rateLimiterByUID.consume(req.uid);
  } catch (r) {
    return res.status(429).json({
      error: 'Cooldown actif',
      cooldown: Math.ceil((r.msBeforeNext || 0) / 1000),
    });
  }

  // Anti-flood par IP
  try {
    await rateLimiterByIP.consume(ip);
  } catch {
    return res.status(429).json({ error: 'Trop de requêtes', cooldown: COOLDOWN_SECS });
  }

  const pixel = { color: color.toLowerCase(), pseudo, ts: Date.now() };

  try {
    await set(ref(db, `grid/${x}_${y}`), pixel);
  } catch (e) {
    return res.status(500).json({ error: 'Erreur serveur' });
  }

  console.log(`[pixel] ${pseudo} | UID:${req.uid.slice(0,8)} | IP:${ip} → (${x},${y}) ${color}`);
  res.json({ success: true, cooldown: COOLDOWN_SECS });
});

// ── Envoyer un message chat ────────────────────────────
app.post('/chat', verifyToken, async (req, res) => {
  if (panicMode)
    return res.status(503).json({ error: 'Chat suspendu' });

  const ip = getIP(req);
  if (bannedIPs.has(ip))
    return res.status(403).json({ error: 'Accès refusé' });

  const text   = String(req.body.text || '').trim().substring(0, 120);
  const pseudo = String(req.body.pseudo || 'Anonyme').substring(0, 20);

  if (!text) return res.status(400).json({ error: 'Message vide' });

  // Rate limit chat par UID
  try {
    await chatLimiterByUID.consume(req.uid);
  } catch (r) {
    return res.status(429).json({
      error: 'Trop vite !',
      cooldown: Math.ceil((r.msBeforeNext || 0) / 1000),
    });
  }

  // Rate limit chat par IP (anti-multi-comptes)
  try {
    await chatLimiterByIP.consume(ip);
  } catch {
    return res.status(429).json({ error: 'Trop de messages depuis cette IP', cooldown: 30 });
  }

  // Écriture dans Firebase
  try {
    await push(ref(db, 'chat'), { pseudo, text, ts: Date.now() });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ── Routes ADMIN ───────────────────────────────────────
app.get('/admin/status', verifyAdmin, (_req, res) => {
  res.json({ panicMode, bannedIPs: [...bannedIPs], timestamp: Date.now() });
});

app.post('/admin/panic', verifyAdmin, async (req, res) => {
  panicMode = req.body.active !== false;
  await saveAdminState();
  console.log(`🚨 Mode panique : ${panicMode ? 'ACTIVÉ' : 'DÉSACTIVÉ'}`);
  res.json({ panicMode, message: panicMode ? '🚨 Placements gelés' : '✅ Placements repris' });
});

app.delete('/admin/panic', verifyAdmin, async (_req, res) => {
  panicMode = false;
  await saveAdminState();
  res.json({ panicMode: false, message: '✅ Placements repris' });
});

app.post('/admin/ban', verifyAdmin, async (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP manquante' });
  bannedIPs.add(ip);
  await saveAdminState();
  console.log(`🚫 IP bannie : ${ip}`);
  res.json({ banned: [...bannedIPs] });
});

app.delete('/admin/ban', verifyAdmin, async (req, res) => {
  const { ip } = req.body;
  bannedIPs.delete(ip);
  await saveAdminState();
  res.json({ banned: [...bannedIPs] });
});

// POST /admin/clear-region → vider une région spécifique
app.post('/admin/clear-region', verifyAdmin, async (req, res) => {
  const { x1, y1, x2, y2 } = req.body;
  
  // Validation des coordonnées
  const coords = [x1, y1, x2, y2].map(n => parseInt(n));
  if (coords.some(isNaN)) {
    return res.status(400).json({ error: 'Coordonnées invalides' });
  }
  
  const [cx1, cy1, cx2, cy2] = coords;
  
  // Normaliser les coordonnées (ordre croissant)
  const minX = Math.max(0, Math.min(SIZE - 1, Math.min(cx1, cx2)));
  const maxX = Math.max(0, Math.min(SIZE - 1, Math.max(cx1, cx2)));
  const minY = Math.max(0, Math.min(SIZE - 1, Math.min(cy1, cy2)));
  const maxY = Math.max(0, Math.min(SIZE - 1, Math.max(cy1, cy2)));
  
  try {
    // Effacer la région dans Firebase
    const updates = {};
    for (let x = minX; x <= maxX; x++) {
      for (let y = minY; y <= maxY; y++) {
        updates[`${x}_${y}`] = { color: '#000000', pseudo: 'System', ts: Date.now() };
      }
    }
    
    await set(ref(db, 'grid'), updates);
    console.log(`🗑️ Région effacée : (${minX},${minY}) → (${maxX},${maxY})`);
    
    res.json({ 
      success: true, 
      message: `Région (${minX},${minY}) → (${maxX},${maxY}) effacée`,
      pixelsCleared: (maxX - minX + 1) * (maxY - minY + 1)
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/admin/reset-grid', verifyAdmin, async (_req, res) => {
  try {
    await set(ref(db, 'grid'), null);
    console.log('🗑️  Grille réinitialisée');
    res.json({ success: true, message: 'Grille vidée' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Démarrage ──────────────────────────────────────────
async function start() {
  await loadAdminState();
  app.listen(PORT, () => {
    console.log(`\n🎮 Pixel War → http://localhost:${PORT}`);
    console.log(`   Cooldown pixels : ${COOLDOWN_SECS}s`);
    console.log(`   Cooldown chat   : ${CHAT_LIMIT_SECS}s`);
    console.log(`   Admin key       : ✅ configurée`);
    console.log(`   Token auth      : ${adminAuth ? '🔐 Firebase Admin' : '🛠  Mode dév'}\n`);
  });
}

start();
