require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');

let pdfParse = null;
let mammoth = null;
try { pdfParse = require('pdf-parse'); } catch (e) {}
try { mammoth = require('mammoth'); } catch (e) {}

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');
const SECRET_FILE = path.join(DATA_DIR, 'session.secret');
const WORKSPACE_FILE = path.join(DATA_DIR, 'workspace.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

let SESSION_SECRET = process.env.SESSION_SECRET || '';
if (!SESSION_SECRET) {
  if (fs.existsSync(SECRET_FILE)) {
    SESSION_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
  } else {
    SESSION_SECRET = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(SECRET_FILE, SESSION_SECRET, 'utf8');
  }
}

// Rate Limiter
const requestCounts = new Map();
function rateLimiter(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 60 * 1000;
  const maxRequests = 500;

  if (!requestCounts.has(ip)) {
    requestCounts.set(ip, { count: 1, startTime: now });
  } else {
    let data = requestCounts.get(ip);
    if (now - data.startTime > windowMs) {
      data.count = 1;
      data.startTime = now;
    } else {
      data.count++;
      if (data.count > maxRequests) {
        return res.status(429).json({ error: 'Too many requests, please try again later.' });
      }
    }
  }
  next();
}
app.use(rateLimiter);

function loadAuthData() {
  if (!fs.existsSync(AUTH_FILE)) {
    const initial = {
      owner: null,
      ownerClaimCode: process.env.OWNER_CLAIM_CODE || '411826',
      users: [],
      payments: [],
      otps: {},
      sessions: {}
    };
    fs.writeFileSync(AUTH_FILE, JSON.stringify(initial, null, 2), 'utf8');
    return initial;
  }
  try {
    const raw = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
    raw.users = raw.users || [];
    raw.payments = raw.payments || [];
    raw.otps = raw.otps || {};
    raw.sessions = raw.sessions || {};
    if (!raw.ownerClaimCode) raw.ownerClaimCode = process.env.OWNER_CLAIM_CODE || '411826';
    return raw;
  } catch (e) {
    return {
      owner: null,
      ownerClaimCode: process.env.OWNER_CLAIM_CODE || '411826',
      users: [],
      payments: [],
      otps: {},
      sessions: {}
    };
  }
}

function saveAuthData(data) {
  fs.writeFileSync(AUTH_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function loadWorkspaceData() {
  if (!fs.existsSync(WORKSPACE_FILE)) {
    const initWs = { agents: [], projects: [], knowledge: [], files: [], providers: {}, customProviders: [] };
    fs.writeFileSync(WORKSPACE_FILE, JSON.stringify(initWs, null, 2), 'utf8');
    return initWs;
  }
  try {
    const ws = JSON.parse(fs.readFileSync(WORKSPACE_FILE, 'utf8'));
    ws.agents = ws.agents || [];
    ws.projects = ws.projects || [];
    ws.knowledge = ws.knowledge || [];
    ws.files = ws.files || [];
    ws.providers = ws.providers || {};
    ws.customProviders = ws.customProviders || [];
    return ws;
  } catch (e) {
    return { agents: [], projects: [], knowledge: [], files: [], providers: {}, customProviders: [] };
  }
}

function saveWorkspaceData(data) {
  fs.writeFileSync(WORKSPACE_FILE, JSON.stringify(data, null, 2), 'utf8');
}

app.use(express.json({ limit: '30mb' }));
app.use(express.urlencoded({ extended: true, limit: '30mb' }));

app.use((req, res, next) => {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Orbit-Token');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

function signToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  if (sig !== expected) return null;
  try { return JSON.parse(Buffer.from(data, 'base64url').toString('utf8')); }
  catch (e) { return null; }
}

function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (rc) {
    rc.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      const key = parts.shift().trim();
      const val = decodeURI(parts.join('='));
      list[key] = val;
    });
  }
  return list;
}

function getSessionUser(req) {
  const cookies = parseCookies(req);
  const token = req.headers['x-orbit-token'] || cookies['orbit_session'];
  if (!token) return null;
  const decoded = verifyToken(token);
  if (!decoded) return null;
  const auth = loadAuthData();
  if (decoded.role === 'owner' && auth.owner && auth.owner.id === decoded.id) {
    return { ...auth.owner, role: 'owner', tier: 'pro' };
  }
  const user = auth.users.find(u => u.id === decoded.id && !u.revoked);
  if (user) return { ...user, role: 'guest', tier: user.tier || 'free' };
  return null;
}

function setSessionCookie(res, userObj) {
  const token = signToken({
    id: userObj.id,
    role: userObj.role,
    tier: userObj.tier || (userObj.role === 'owner' ? 'pro' : 'free'),
    phone: userObj.phone,
    iat: Date.now()
  });
  res.setHeader('Set-Cookie', `orbit_session=${token}; HttpOnly; Path=/; Max-Age=${30 * 24 * 3600}; SameSite=Lax`);
  return token;
}

function requireAuth(req, res, next) {
  const user = getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Authentication required. Please login first.' });
  req.user = user;
  next();
}

function requireOwner(req, res, next) {
  const user = getSessionUser(req);
  if (!user || user.role !== 'owner') return res.status(403).json({ error: 'Owner permissions required.' });
  req.user = user;
  next();
}

// =========================================================
// MOBILE OTP AUTH ROUTES (NO ADMIN APPROVAL NEEDED)
// =========================================================
app.get('/api/auth/status', (req, res) => {
  const auth = loadAuthData();
  const cookies = parseCookies(req);
  const token = req.headers['x-orbit-token'] || cookies['orbit_session'];

  if (!token) return res.json({ ok: true, hasOwner: Boolean(auth.owner), authenticated: false, user: null });
  const decoded = verifyToken(token);
  if (!decoded) return res.json({ ok: true, hasOwner: Boolean(auth.owner), authenticated: false, user: null });

  if (decoded.role !== 'owner') {
    const userInDb = auth.users.find(u => u.id === decoded.id);
    if (!userInDb || userInDb.revoked) {
      return res.status(403).json({ error: 'Access revoked by admin', revoked: true });
    }
  }

  const user = getSessionUser(req);
  res.json({ ok: true, hasOwner: Boolean(auth.owner), authenticated: Boolean(user), user: user || null });
});

app.post('/api/auth/owner/claim', (req, res) => {
  const { name, phone, claimCode } = req.body;
  if (!phone || !claimCode) {
    return res.status(400).json({ error: 'Owner phone and claim code are required.' });
  }
  const auth = loadAuthData();
  const validClaimCode = String(auth.ownerClaimCode || process.env.OWNER_CLAIM_CODE || '411826').trim();

  if (String(claimCode).trim() !== validClaimCode) {
    return res.status(403).json({ error: 'Invalid Owner Claim Code.' });
  }

  const ownerUser = {
    id: auth.owner?.id || 'owner_' + crypto.randomBytes(6).toString('hex'),
    name: (name || auth.owner?.name || 'Mayur Sonawane (Owner)').trim(),
    phone: phone.trim(),
    role: 'owner',
    tier: 'pro',
    createdAt: auth.owner?.createdAt || new Date().toISOString()
  };

  auth.owner = ownerUser;
  saveAuthData(auth);
  const token = setSessionCookie(res, ownerUser);
  res.json({ ok: true, user: ownerUser, token });
});

app.post('/api/auth/issue-phone', (req, res) => {
  const { phone } = req.body;
  if (!phone || phone.length < 10) return res.status(400).json({ error: 'Valid mobile number required' });
  
  const cleanPhone = phone.trim();
  const auth = loadAuthData();

  let user = auth.users.find(u => u.phone === cleanPhone);
  if (!user) {
    user = {
      id: 'usr_' + crypto.randomBytes(6).toString('hex'),
      name: 'User ' + cleanPhone.slice(-4),
      phone: cleanPhone,
      role: 'guest',
      tier: 'free',
      revoked: false,
      createdAt: new Date().toISOString()
    };
    auth.users.push(user);
  }

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  auth.otps = auth.otps || {};
  auth.otps[cleanPhone] = { otp, createdAt: new Date().toISOString(), expiresAt: Date.now() + 10 * 60 * 1000 };
  saveAuthData(auth);

  console.log(`[ORBIT AI MOBILE OTP] Phone: ${cleanPhone} | OTP: ${otp}`);

  res.json({
    ok: true,
    devOtp: otp,
    message: `6-digit OTP generated for mobile number ${cleanPhone}. (OTP: ${otp})`
  });
});

app.post('/api/auth/verify-phone', (req, res) => {
  const { phone, otp } = req.body;
  if (!phone || !otp) return res.status(400).json({ error: 'Phone and OTP required' });
  const cleanPhone = phone.trim();

  const auth = loadAuthData();
  const record = auth.otps ? auth.otps[cleanPhone] : null;
  if (!record || record.otp !== String(otp).trim() || (record.expiresAt && Date.now() > record.expiresAt)) {
    return res.status(401).json({ error: 'Invalid or expired OTP.' });
  }
  delete auth.otps[cleanPhone];
  saveAuthData(auth);

  if (auth.owner && auth.owner.phone === cleanPhone) {
    const ownerObj = { ...auth.owner, role: 'owner', tier: 'pro' };
    const token = setSessionCookie(res, ownerObj);
    return res.json({ ok: true, user: ownerObj, token });
  }
  const user = auth.users.find(u => u.phone === cleanPhone && !u.revoked);
  if (!user) return res.status(403).json({ error: 'User access revoked' });

  const guestObj = { ...user, role: 'guest', tier: user.tier || 'free' };
  const token = setSessionCookie(res, guestObj);
  res.json({ ok: true, user: guestObj, token });
});

app.post('/api/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'orbit_session=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});

// =========================================================
// PRO SUBSCRIPTION (₹799 MANUAL / QR CODE PAYMENT VERIFY)
// =========================================================
const PRO_PRICE_INR = 799;

app.post('/api/payment/verify-manual', requireAuth, (req, res) => {
  const { paymentId, upiId } = req.body;
  if (!paymentId) {
    return res.status(400).json({ error: 'कृपया पेमेंट ट्रान्झॅक्शन आयडी (Transaction ID) टाका.' });
  }

  const auth = loadAuthData();
  const user = auth.users.find(u => u.id === req.user.id || u.phone === req.user.phone);
  
  if (user) {
    user.tier = 'pro';
    user.proActivatedAt = new Date().toISOString();
  }

  auth.payments = auth.payments || [];
  auth.payments.unshift({
    id: paymentId,
    upiId: upiId || 'UPI / QR Payment',
    phone: req.user.phone,
    name: req.user.name,
    amountInr: PRO_PRICE_INR,
    status: 'paid',
    paidAt: new Date().toISOString()
  });

  saveAuthData(auth);

  const updatedUser = user ? { ...user, role: 'guest', tier: 'pro' } : { ...req.user, tier: 'pro' };
  const token = setSessionCookie(res, updatedUser);

  res.json({
    ok: true,
    user: updatedUser,
    token,
    message: 'पेमेंट यशस्वीरित्या व्हेरिफाय झाले! तुमचे ORBIT AI Pro सबस्क्रिप्शन आता ॲक्टिव्ह झाले आहे.'
  });
});

app.get('/api/auth/users', requireOwner, (req, res) => {
  const auth = loadAuthData();
  res.json({ ok: true, users: auth.users || [], payments: auth.payments || [] });
});

app.post('/api/auth/users/revoke', requireOwner, (req, res) => {
  const { userId, revoked } = req.body;
  const auth = loadAuthData();
  const user = auth.users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.revoked = Boolean(revoked);
  saveAuthData(auth);
  res.json({ ok: true, user });
});

// =========================================================
// HEALTH, MODELS & CHAT
// =========================================================
app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    version: '3.0.0',
    openrouterConfigured: Boolean(process.env.OPENROUTER_API_KEY),
    kieConfigured: Boolean(process.env.KIE_API_KEY),
    parsers: { pdf: Boolean(pdfParse), docx: Boolean(mammoth) }
  });
});

app.get('/api/models', requireAuth, async (req, res) => {
  const apiKey = process.env.OPENROUTER_API_KEY;
  const ws = loadWorkspaceData();
  const defaults = [
    { id: 'openrouter/auto', name: 'OpenRouter Auto (Smart Router)', free: true },
    { id: 'meta-llama/llama-3.1-8b-instruct:free', name: 'Llama 3.1 8B (Free)', free: true },
    { id: 'google/gemma-2-9b-it:free', name: 'Google Gemma 2 9B (Free)', free: true }
  ];

  let openrouterModels = defaults;
  if (apiKey) {
    try {
      const resp = await fetch('https://openrouter.ai/api/v1/models', {
        headers: { 'Authorization': `Bearer ${apiKey}` }
      });
      const data = await resp.json();
      if (Array.isArray(data.data) && data.data.length) {
        openrouterModels = [defaults[0], ...data.data];
      }
    } catch (e) {}
  }

  res.json({
    ok: true,
    models: openrouterModels,
    customProviders: (ws.customProviders || []).map(p => ({
      id: p.id,
      name: p.name,
      endpoint: p.endpoint,
      models: p.models || []
    }))
  });
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, `${Date.now()}_${file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_')}`)
});
const upload = multer({ storage, limits: { fileSize: 18 * 1024 * 1024 } });

app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
  const ws = loadWorkspaceData();
  let extractedText = '';
  const ext = path.extname(req.file.originalname).toLowerCase();

  try {
    if (pdfParse && (req.file.mimetype === 'application/pdf' || ext === '.pdf')) {
      const buffer = fs.readFileSync(req.file.path);
      const parsed = await pdfParse(buffer);
      extractedText = parsed.text || '';
    } else if (mammoth && (ext === '.docx' || req.file.mimetype.includes('wordprocessingml'))) {
      const result = await mammoth.extractRawText({ path: req.file.path });
      extractedText = result.value || '';
    } else if (['.txt', '.md', '.csv', '.json', '.js', '.py', '.html', '.css'].includes(ext)) {
      extractedText = fs.readFileSync(req.file.path, 'utf8');
    }
  } catch (e) {}

  const fileMeta = {
    id: 'file_' + crypto.randomBytes(6).toString('hex'),
    originalName: req.file.originalname,
    filename: req.file.filename,
    size: req.file.size,
    url: `/api/files/download/${req.file.filename}`,
    extractedText: extractedText.slice(0, 25000),
    uploadedAt: new Date().toISOString()
  };

  ws.files.unshift(fileMeta);
  saveWorkspaceData(ws);
  res.json({ ok: true, file: fileMeta });
});

app.get('/api/files', requireAuth, (req, res) => {
  const ws = loadWorkspaceData();
  res.json({ ok: true, files: ws.files || [] });
});

app.get('/api/workspace', requireAuth, (req, res) => {
  const ws = loadWorkspaceData();
  res.json({ ok: true, agents: ws.agents, projects: ws.projects, knowledge: ws.knowledge });
});

app.post('/api/chat', requireAuth, async (req, res) => {
  const { messages = [], model = 'openrouter/auto', attachments = [], projectId = null } = req.body;
  const ws = loadWorkspaceData();

  let systemContext = [];
  if (projectId) {
    const proj = (ws.projects || []).find(p => p.id === projectId);
    if (proj) systemContext.push(`Project Context (${proj.name}): ${proj.instructions}`);
  }
  if (ws.knowledge && ws.knowledge.length) {
    const kbSnippet = ws.knowledge.slice(0, 5).map(k => `[${k.title}]: ${k.content.slice(0, 1000)}`).join('\n');
    systemContext.push(`Knowledge Base:\n${kbSnippet}`);
  }
  if (Array.isArray(attachments) && attachments.length) {
    const attText = attachments.map(a => `Attached File (${a.originalName}):\n${a.extractedText || ''}`).join('\n\n');
    systemContext.push(attText);
  }

  const finalMessages = systemContext.length
    ? [{ role: 'system', content: systemContext.join('\n\n') }, ...messages]
    : messages;

  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'OPENROUTER_API_KEY missing in .env' });

  try {
    const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'http://localhost:3000',
        'X-Title': 'ORBIT AI Private OS'
      },
      body: JSON.stringify({ model, messages: finalMessages })
    });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data?.error?.message || 'Model request failed');
    res.json({ ok: true, reply: data?.choices?.[0]?.message?.content || 'No response' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`ORBIT AI Server running on http://localhost:${PORT}`));
