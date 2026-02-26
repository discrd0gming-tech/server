const express = require('express');
const cors    = require('cors');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const fetch = require('node-fetch');

// ── Firebase Admin SDK ───────────────────────────────
const admin = require('firebase-admin');

// En production, utilise les variables d'environnement de Render
if (!admin.apps.length) {
  if (process.env.FIREBASE_PRIVATE_KEY) {
    // Mode production avec vraie clé
    const serviceAccount = {
      projectId: "pixelwar2-69b05",
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL || "firebase-adminsdk-xxxxx@pixelwar2-69b05.iam.gserviceaccount.com"
    };
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
      databaseURL: "https://pixelwar2-69b05-default-rtdb.europe-west1.firebasedatabase.app"
    });
  } else {
    // Mode développement - utilise le client SDK temporairement
    console.warn('⚠️ Mode dév : Firebase Admin SDK non configuré');
    const { initializeApp } = require('firebase/app');
    const { getDatabase } = require('firebase/database');
    
    const firebaseConfig = {
      apiKey: 'AIzaSyAOjsSZrGmHK3E5QjGT-IamhPX9QLOt_Qk',
      authDomain: 'pixelwar2-69b05.firebaseapp.com',
      databaseURL: 'https://pixelwar2-69b05-default-rtdb.europe-west1.firebasedatabase.app',
      projectId: 'pixelwar2-69b05',
      storageBucket: 'pixelwar2-69b05.firebasestorage.app',
      messagingSenderId: '216084370377',
      appId: '1:216084370377:web:c9ab6b4f22a5829898ce18',
    };
    
    const firebaseApp = initializeApp(firebaseConfig);
    const db = getDatabase(firebaseApp);
    
    // Créer un objet compatible avec l'API Admin
    global.db = {
      ref: (path) => {
        const dbRef = db.ref(path);
        return {
          set: (data) => dbRef.set(data),
          get: () => dbRef.get().then(snap => ({ val: () => snap.val() })),
          path: path
        };
      }
    };
  }
}

const db = admin.apps.length ? admin.database() : global.db;

// Helper functions pour la compatibilité
function ref(path) {
  return db.ref(path);
}

function set(dbRef, data) {
  return dbRef.set(data);
}

function get(dbRef) {
  return dbRef.get();
}

// ── Express ────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3001;

app.use(cors({ origin: process.env.ALLOWED_ORIGIN || '*' }));
app.use(express.json());

// ── Mode panique ───────────────────────────────────────
let panicMode    = false;
const ADMIN_KEY  = process.env.ADMIN_KEY || 'changeme-avant-prod'; // variable d'env en prod

// ── Rate limiters ──────────────────────────────────────
const COOLDOWN_SECS = 30;

const rateLimiterByUID = new RateLimiterMemory({
  points: 1, duration: COOLDOWN_SECS, blockDuration: COOLDOWN_SECS,
});
const rateLimiterByIP = new RateLimiterMemory({
  points: 10, duration: COOLDOWN_SECS, blockDuration: COOLDOWN_SECS,
});

// Blacklist IPs (bans manuels ou automatiques)
const bannedIPs = new Set();

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
// Utilise firebase-admin si dispo + clé de service, sinon mode dév
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
    console.warn('⚠️  Mode dév : tokens non vérifiés (définissez GOOGLE_APPLICATION_CREDENTIALS en prod)');
  }
} catch (e) {
  console.warn('⚠️  firebase-admin absent → tokens non vérifiés');
}

async function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer '))
    return res.status(401).json({ error: 'Token manquant' });

  const token = authHeader.split(' ')[1];

  if (adminAuth) {
    // ✅ PRODUCTION : vrai token Firebase vérifié
    try {
      const decoded = await adminAuth.verifyIdToken(token);
      req.uid = decoded.uid;
      next();
    } catch (e) {
      return res.status(403).json({ error: 'Token invalide ou expiré' });
    }
  } else {
    // 🛠 DÉVELOPPEMENT : on utilise l'UID envoyé dans le header ou le body
    // Le token Firebase anonyme a un format JWT dont les 28 premiers chars sont identiques
    // pour tout le monde → on décode la payload du JWT pour extraire le vrai sub (UID)
    try {
      const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
      req.uid = payload.sub || payload.user_id || token.substring(0, 28) || 'dev_user';
    } catch {
      req.uid = token.substring(0, 28) || 'dev_user';
    }
    next();
  }
}

// ── Middleware admin ───────────────────────────────────
function verifyAdmin(req, res, next) {
  const key = req.headers['x-admin-key'] || req.query.key;
  if (key !== ADMIN_KEY)
    return res.status(403).json({ error: 'Clé admin incorrecte' });
  next();
}

// ── Routes publiques ───────────────────────────────────

// Statut général
app.get('/status', (_req, res) => {
  res.json({ ok: true, panicMode, timestamp: Date.now() });
});

// Stats (pixel count depuis Firebase)
app.get('/stats', async (_req, res) => {
  try {
    const snap = await get(ref(db, 'grid'));
    const data = snap.val() || {};
    res.json({ pixelCount: Object.keys(data).length });
  } catch (e) {
    res.json({ pixelCount: 0 });
  }
});

// Cooldown
app.get('/cooldown', verifyToken, async (req, res) => {
  try {
    await rateLimiterByUID.consume(req.uid, 0);
    res.json({ cooldown: 0, canPlace: true });
  } catch (r) {
    res.json({ cooldown: Math.ceil((r.msBeforeNext || 0) / 1000), canPlace: false });
  }
});

// Placer un pixel
app.post('/place-pixel', verifyToken, async (req, res) => {
  // Mode panique → tout bloqué
  if (panicMode)
    return res.status(503).json({ error: '🚨 Placements suspendus par l\'administrateur' });

  // IP bannie
  const ip = getIP(req);
  if (bannedIPs.has(ip))
    return res.status(403).json({ error: 'Accès refusé' });

  const { x, y, color } = req.body;

  if (!validCoords(x, y))
    return res.status(400).json({ error: 'Coordonnées invalides' });
  if (!color || !COLOR_RE.test(color))
    return res.status(400).json({ error: 'Couleur invalide' });

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
    // Ban automatique si quelqu'un spam vraiment fort (plus de 3x la limite)
    // ici on blacklist pas encore automatiquement, juste on bloque la requête
    return res.status(429).json({ error: 'Trop de requêtes', cooldown: COOLDOWN_SECS });
  }

  const pseudo = String(req.body.pseudo || 'Anonyme').substring(0, 20);
  const ts     = Date.now();
  const pixel  = { color: color.toLowerCase(), pseudo, ts };

  // Écriture directe dans Firebase (seule source de vérité)
  try {
    console.log('🔥 Tentative d\'écriture Firebase:', `grid/${x}_${y}`, pixel);
    
    // Utiliser HTTP direct pour écrire dans Firebase
    const firebaseUrl = `https://pixelwar2-69b05-default-rtdb.europe-west1.firebasedatabase.app/grid/${x}_${y}.json`;
    const response = await fetch(firebaseUrl, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(pixel)
    });
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    console.log('✅ Écriture Firebase réussie');
  } catch (e) {
    console.error('❌ Firebase write error:', e.message);
    console.error('Stack:', e.stack);
    return res.status(500).json({ error: 'Erreur serveur Firebase' });
  }

  console.log(`[pixel] ${pseudo} (${ip}) → (${x},${y}) ${color}`);
  res.json({ success: true, cooldown: COOLDOWN_SECS });
});

// ── Routes ADMIN ───────────────────────────────────────

// GET /admin/status → infos
app.get('/admin/status', verifyAdmin, (_req, res) => {
  res.json({
    panicMode,
    bannedIPs:   [...bannedIPs],
    timestamp:   Date.now(),
  });
});

// POST /admin/panic → activer/désactiver le freeze
app.post('/admin/panic', verifyAdmin, (req, res) => {
  panicMode = req.body.active !== false; // true par défaut
  console.log(`🚨 Mode panique : ${panicMode ? 'ACTIVÉ' : 'DÉSACTIVÉ'}`);
  res.json({ panicMode, message: panicMode ? '🚨 Placements gelés' : '✅ Placements repris' });
});

// DELETE /admin/panic → désactiver le freeze
app.delete('/admin/panic', verifyAdmin, (_req, res) => {
  panicMode = false;
  console.log('✅ Mode panique désactivé');
  res.json({ panicMode: false, message: '✅ Placements repris' });
});

// POST /admin/ban → bannir une IP
app.post('/admin/ban', verifyAdmin, (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP manquante' });
  bannedIPs.add(ip);
  console.log(`🚫 IP bannie : ${ip}`);
  res.json({ banned: [...bannedIPs] });
});

// DELETE /admin/ban → débannir une IP
app.delete('/admin/ban', verifyAdmin, (req, res) => {
  const { ip } = req.body;
  bannedIPs.delete(ip);
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

// POST /admin/reset-grid → vider toute la grille
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
app.listen(PORT, () => {
  console.log(`\n🎮 Pixel War → http://localhost:${PORT}`);
  console.log(`   Cooldown   : ${COOLDOWN_SECS}s`);
  console.log(`   Admin key  : ${ADMIN_KEY === 'changeme-avant-prod' ? '⚠️  PAR DÉFAUT (changez ADMIN_KEY en prod !)' : '✅ configurée'}`);
  console.log(`   Token auth : ${adminAuth ? '🔐 Firebase Admin' : '🛠 Mode dév (non vérifié)'}\n`);
});
