require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');

let pdfParse = null;
let mammoth = null;
let nodemailer = null;
try { pdfParse = require('pdf-parse'); } catch (e) {}
try { mammoth = require('mammoth'); } catch (e) {}
try { nodemailer = require('nodemailer'); } catch (e) {}

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
      requests: [],
      proRequests: [],
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
    raw.requests = raw.requests || [];
    raw.proRequests = raw.proRequests || [];
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
      requests: [],
      proRequests: [],
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
    email: userObj.email,
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
// EMAIL OTP HELPER (NODEMAILER)
// =========================================================
async function sendOtpEmail(toEmail, otpCode, userName = 'User') {
  const ws = loadWorkspaceData();
  const smtpUser = process.env.SMTP_EMAIL || ws.providers?.smtpUser || '';
  const smtpPass = process.env.SMTP_PASSWORD || ws.providers?.smtpPass || '';

  console.log(`[ORBIT AI OTP] Email: ${toEmail} | OTP: ${otpCode}`);

  if (!nodemailer || !smtpUser || !smtpPass) {
    return { sent: false, reason: 'SMTP credentials not configured in .env or API Connections' };
  }

  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: smtpUser, pass: smtpPass }
    });

    await transporter.sendMail({
      from: `"ORBIT AI Security" <${smtpUser}>`,
      to: toEmail,
      subject: 'Your ORBIT AI Login OTP Code',
      html: `
        <div style="font-family:Segoe UI,sans-serif;padding:20px;background:#14161D;color:#E9E8F8;border-radius:16px;">
          <h2 style="color:#8DB9F0;">ORBIT AI — Access Verification</h2>
          <p>Hello <strong>${userName}</strong>,</p>
          <p>Your 6-digit One-Time Password (OTP) to access ORBIT AI is:</p>
          <div style="font-size:28px;font-weight:900;letter-spacing:6px;padding:14px 20px;background:#1E222D;color:#F5B69E;border-radius:12px;display:inline-block;margin:12px 0;">
            ${otpCode}
          </div>
          <p style="font-size:12px;color:#B8B7CC;">This code is valid for 10 minutes. Do not share it with anyone.</p>
        </div>
      `
    });
    return { sent: true };
  } catch (err) {
    console.error('[ORBIT AI EMAIL ERROR]:', err.message);
    return { sent: false, reason: err.message };
  }
}

// =========================================================
// AUTHENTICATION & ADMIN ROUTES
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
  const { name, email, claimCode } = req.body;
  if (!email || !claimCode) {
    return res.status(400).json({ error: 'Owner email and claim code are required.' });
  }
  const auth = loadAuthData();
  const validClaimCode = String(auth.ownerClaimCode || process.env.OWNER_CLAIM_CODE || '411826').trim();

  if (String(claimCode).trim() !== validClaimCode) {
    return res.status(403).json({ error: 'Invalid Owner Claim Code.' });
  }

  // If owner already exists, require matching owner email so strangers cannot hijack
  if (auth.owner && auth.owner.email && auth.owner.email.toLowerCase() !== email.trim().toLowerCase()) {
    return res.status(403).json({ error: 'Owner email does not match registered owner.' });
  }

  const ownerUser = {
    id: auth.owner?.id || 'owner_' + crypto.randomBytes(6).toString('hex'),
    name: (name || auth.owner?.name || 'Mayur Sonawane (Owner)').trim(),
    email: email.trim().toLowerCase(),
    role: 'owner',
    tier: 'pro',
    createdAt: auth.owner?.createdAt || new Date().toISOString()
  };

  auth.owner = ownerUser;
  saveAuthData(auth);
  const token = setSessionCookie(res, ownerUser);
  res.json({ ok: true, user: ownerUser, token });
});

app.post('/api/auth/request', (req, res) => {
  const { name, email, reason } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email required.' });
  const auth = loadAuthData();
  const cleanEmail = email.trim().toLowerCase();

  let user = auth.users.find(u => u.email.toLowerCase() === cleanEmail);
  if (!user) {
    user = {
      id: 'usr_' + crypto.randomBytes(6).toString('hex'),
      name: name.trim(),
      email: cleanEmail,
      role: 'guest',
      tier: 'free',
      revoked: false,
      createdAt: new Date().toISOString()
    };
    auth.users.push(user);
  }

  let existingReq = auth.requests.find(r => r.email.toLowerCase() === cleanEmail);
  if (existingReq) {
    existingReq.status = 'pending';
    existingReq.name = name.trim();
    existingReq.reason = reason || existingReq.reason;
    saveAuthData(auth);
    return res.json({ ok: true, requestId: existingReq.id, status: existingReq.status });
  }

  const newReq = {
    id: 'req_' + crypto.randomBytes(6).toString('hex'),
    name: name.trim(),
    email: cleanEmail,
    reason: reason || 'Workspace Access',
    status: 'pending',
    createdAt: new Date().toISOString()
  };
  auth.requests.push(newReq);
  saveAuthData(auth);
  res.json({ ok: true, requestId: newReq.id, status: 'pending' });
});

app.get('/api/auth/requests', requireOwner, (req, res) => {
  const auth = loadAuthData();
  res.json({ ok: true, requests: auth.requests || [] });
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

app.post('/api/auth/approve', requireOwner, async (req, res) => {
  const { requestId, tier } = req.body;
  const auth = loadAuthData();
  const reqItem = auth.requests.find(r => r.id === requestId);
  if (!reqItem) return res.status(404).json({ error: 'Request not found' });

  reqItem.status = 'approved';
  const lower = reqItem.email.toLowerCase();

  let user = auth.users.find(u => u.email.toLowerCase() === lower);
  if (!user) {
    user = {
      id: 'usr_' + crypto.randomBytes(6).toString('hex'),
      name: reqItem.name,
      email: lower,
      role: 'guest',
      tier: tier || 'free',
      revoked: false,
      createdAt: new Date().toISOString()
    };
    auth.users.push(user);
  } else {
    user.revoked = false;
    user.tier = tier || user.tier || 'free';
  }

  // Generate OTP immediately on approval and email it to the guest
  const otp = String(Math.floor(100000 + Math.random() * 900000));
  auth.otps = auth.otps || {};
  auth.otps[lower] = { otp, createdAt: new Date().toISOString(), expiresAt: Date.now() + 30 * 60 * 1000 };
  saveAuthData(auth);

  const mailResult = await sendOtpEmail(lower, otp, reqItem.name);
  res.json({
    ok: true,
    request: reqItem,
    user,
    emailSent: mailResult.sent,
    emailNote: mailResult.sent ? `OTP emailed to ${lower}` : `Approved! (Configure SMTP in API Connections to auto-email OTP. Fallback OTP: ${otp})`
  });
});

app.post('/api/auth/reject', requireOwner, (req, res) => {
  const { requestId } = req.body;
  const auth = loadAuthData();
  const index = auth.requests.findIndex(r => r.id === requestId);
  if (index === -1) return res.status(404).json({ error: 'Request not found' });
  auth.requests.splice(index, 1);
  saveAuthData(auth);
  res.json({ ok: true });
});

app.post('/api/auth/issue', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const auth = loadAuthData();
  const lower = email.trim().toLowerCase();

  const isOwner = auth.owner && auth.owner.email.toLowerCase() === lower;
  const approvedReq = auth.requests.find(r => r.email.toLowerCase() === lower && r.status === 'approved');
  const user = auth.users.find(u => u.email.toLowerCase() === lower && !u.revoked);

  if (!isOwner && !approvedReq && (!user || auth.requests.some(r => r.email.toLowerCase() === lower && r.status !== 'approved'))) {
    return res.status(403).json({ error: 'Your access request is still pending Admin approval.' });
  }

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  auth.otps = auth.otps || {};
  auth.otps[lower] = { otp, createdAt: new Date().toISOString(), expiresAt: Date.now() + 10 * 60 * 1000 };
  saveAuthData(auth);

  const mailResult = await sendOtpEmail(lower, otp, user?.name || 'User');
  res.json({
    ok: true,
    emailSent: mailResult.sent,
    message: mailResult.sent
      ? `6-digit OTP has been sent to your email (${lower}).`
      : `OTP generated! Please check your email (or ask Admin if SMTP is not set).`
  });
});

app.post('/api/auth/verify', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });
  const lower = email.trim().toLowerCase();

  const auth = loadAuthData();
  const record = auth.otps ? auth.otps[lower] : null;
  if (!record || record.otp !== String(otp).trim() || (record.expiresAt && Date.now() > record.expiresAt)) {
    return res.status(401).json({ error: 'Invalid or expired OTP.' });
  }
  delete auth.otps[lower];
  saveAuthData(auth);

  if (auth.owner && auth.owner.email.toLowerCase() === lower) {
    const ownerObj = { ...auth.owner, role: 'owner', tier: 'pro' };
    const token = setSessionCookie(res, ownerObj);
    return res.json({ ok: true, user: ownerObj, token });
  }
  const user = auth.users.find(u => u.email.toLowerCase() === lower && !u.revoked);
  if (!user) return res.status(403).json({ error: 'User access revoked or not approved' });

  const guestObj = { ...user, role: 'guest', tier: user.tier || 'free' };
  const token = setSessionCookie(res, guestObj);
  res.json({ ok: true, user: guestObj, token });
});

app.post('/api/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'orbit_session=; HttpOnly; Path=/; Max-Age=0');
  res.json({ ok: true });
});

// =========================================================
// RAZORPAY PAYMENT GATEWAY FOR PRO SUBSCRIPTION
// =========================================================
function getRazorpayConfig() {
  const ws = loadWorkspaceData();
  const keyId = process.env.RAZORPAY_KEY_ID || ws.providers?.razorpayKeyId || '';
  const keySecret = process.env.RAZORPAY_KEY_SECRET || ws.providers?.razorpayKeySecret || '';
  const amountInr = Number(process.env.PRO_PRICE_INR || ws.providers?.proPriceInr || 499);
  return { keyId, keySecret, amountInr };
}

app.get('/api/payment/config', requireAuth, (req, res) => {
  const { keyId, keySecret, amountInr } = getRazorpayConfig();
  res.json({
    ok: true,
    configured: Boolean(keyId && keySecret),
    keyId,
    amountInr,
    currency: 'INR'
  });
});

app.post('/api/payment/create-order', requireAuth, async (req, res) => {
  const { keyId, keySecret, amountInr } = getRazorpayConfig();
  if (!keyId || !keySecret) {
    return res.status(400).json({ error: 'Razorpay keys are not configured on the server yet.' });
  }

  const amountPaise = Math.round(amountInr * 100);
  const receiptId = 'rcpt_' + crypto.randomBytes(6).toString('hex');

  try {
    const authHeader = Buffer.from(`${keyId}:${keySecret}`).toString('base64');
    const resp = await fetch('https://api.razorpay.com/v1/orders', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${authHeader}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        amount: amountPaise,
        currency: 'INR',
        receipt: receiptId,
        notes: {
          userId: req.user.id,
          email: req.user.email,
          plan: 'ORBIT_AI_PRO'
        }
      })
    });

    const orderData = await resp.json();
    if (!resp.ok || !orderData.id) {
      throw new Error(orderData.error?.description || 'Failed to create Razorpay order');
    }

    res.json({
      ok: true,
      orderId: orderData.id,
      amount: orderData.amount,
      currency: orderData.currency,
      keyId
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/payment/verify', requireAuth, (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
  const { keySecret, amountInr } = getRazorpayConfig();

  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ error: 'Missing payment verification details.' });
  }

  const expectedSig = crypto
    .createHmac('sha256', keySecret)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest('hex');

  if (expectedSig !== razorpay_signature) {
    return res.status(400).json({ error: 'Payment signature verification failed.' });
  }

  // Signature is valid -> Upgrade user to PRO immediately!
  const auth = loadAuthData();
  const user = auth.users.find(u => u.id === req.user.id || u.email.toLowerCase() === req.user.email.toLowerCase());
  if (user) {
    user.tier = 'pro';
    user.proActivatedAt = new Date().toISOString();
  }

  auth.payments = auth.payments || [];
  auth.payments.unshift({
    id: razorpay_payment_id,
    orderId: razorpay_order_id,
    email: req.user.email,
    name: req.user.name,
    amountInr,
    status: 'paid',
    paidAt: new Date().toISOString()
  });

  // Remove from pending proRequests if present
  auth.proRequests = (auth.proRequests || []).filter(r => r.email.toLowerCase() !== req.user.email.toLowerCase());
  saveAuthData(auth);

  const updatedUser = user ? { ...user, role: 'guest', tier: 'pro' } : { ...req.user, tier: 'pro' };
  const token = setSessionCookie(res, updatedUser);

  res.json({
    ok: true,
    user: updatedUser,
    token,
    message: 'Payment verified successfully! ORBIT AI Pro Subscription is now active.'
  });
});

// Manual Admin Pro Approval (Fallback / Owner Override)
app.post('/api/auth/pro-request', requireAuth, (req, res) => {
  const auth = loadAuthData();
  const email = req.user.email.toLowerCase();
  auth.proRequests = auth.proRequests || [];
  if (!auth.proRequests.some(r => r.email.toLowerCase() === email)) {
    auth.proRequests.push({ email, name: req.user.name, createdAt: new Date().toISOString() });
    saveAuthData(auth);
  }
  res.json({ ok: true, message: 'Pro upgrade request sent to Admin.' });
});

app.get('/api/auth/pro-requests', requireOwner, (req, res) => {
  const auth = loadAuthData();
  res.json({ ok: true, requests: auth.proRequests || [] });
});

app.post('/api/auth/pro-approve', requireOwner, (req, res) => {
  const { email, tier } = req.body;
  const auth = loadAuthData();
  const targetTier = tier || 'pro';
  auth.proRequests = (auth.proRequests || []).filter(r => r.email.toLowerCase() !== email.toLowerCase());
  const user = auth.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (user) user.tier = targetTier;
  saveAuthData(auth);
  res.json({ ok: true, message: `User ${email} updated to ${targetTier.toUpperCase()}` });
});

// =========================================================
// HEALTH, MODELS, KIE.AI & CUSTOM API PROVIDERS
// =========================================================
app.get('/api/health', (req, res) => {
  const { configured: razorpayConfigured } = getRazorpayConfig();
  res.json({
    ok: true,
    version: '3.0.0',
    openrouterConfigured: Boolean(process.env.OPENROUTER_API_KEY),
    kieConfigured: Boolean(process.env.KIE_API_KEY),
    razorpayConfigured,
    parsers: { pdf: Boolean(pdfParse), docx: Boolean(mammoth) }
  });
});

app.get('/api/models', requireAuth, async (req, res) => {
  const apiKey = process.env.OPENROUTER_API_KEY;
  const ws = loadWorkspaceData();
  const defaults = [
    { id: 'openrouter/auto', name: 'OpenRouter Auto (Smart Router)', free: true },
    { id: 'meta-llama/llama-3.1-8b-instruct:free', name: 'Llama 3.1 8B (Free)', free: true },
    { id: 'google/gemma-2-9b-it:free', name: 'Google Gemma 2 9B (Free)', free: true },
    { id: 'anthropic/claude-3.5-sonnet', name: 'Claude 3.5 Sonnet' },
    { id: 'openai/gpt-4o', name: 'OpenAI GPT-4o' }
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

app.post('/api/providers/config', requireOwner, (req, res) => {
  const { openrouterKey, tavilyKey, kieKey, razorpayKeyId, razorpayKeySecret, proPriceInr, smtpUser, smtpPass, customUrl } = req.body;
  const ws = loadWorkspaceData();
  ws.providers = ws.providers || {};

  if (openrouterKey) process.env.OPENROUTER_API_KEY = openrouterKey.trim();
  if (tavilyKey) process.env.TAVILY_API_KEY = tavilyKey.trim();
  if (kieKey) process.env.KIE_API_KEY = kieKey.trim();
  if (razorpayKeyId) { process.env.RAZORPAY_KEY_ID = razorpayKeyId.trim(); ws.providers.razorpayKeyId = razorpayKeyId.trim(); }
  if (razorpayKeySecret) { process.env.RAZORPAY_KEY_SECRET = razorpayKeySecret.trim(); ws.providers.razorpayKeySecret = razorpayKeySecret.trim(); }
  if (proPriceInr) { process.env.PRO_PRICE_INR = String(proPriceInr).trim(); ws.providers.proPriceInr = Number(proPriceInr); }
  if (smtpUser) { process.env.SMTP_EMAIL = smtpUser.trim(); ws.providers.smtpUser = smtpUser.trim(); }
  if (smtpPass) { process.env.SMTP_PASSWORD = smtpPass.trim(); ws.providers.smtpPass = smtpPass.trim(); }
  if (customUrl) ws.providers.customUrl = customUrl.trim();

  saveWorkspaceData(ws);
  res.json({ ok: true, message: 'All provider, Razorpay & SMTP keys securely saved on server!' });
});

// Dynamic Custom API Key Adapter (Fetches and stores custom provider models on backend)
app.post('/api/providers/custom', requireOwner, async (req, res) => {
  const { name, apiKey, endpoint } = req.body;
  if (!name || !apiKey || !endpoint) {
    return res.status(400).json({ error: 'Provider name, API key, and Endpoint URL are required.' });
  }

  const cleanEndpoint = endpoint.trim().replace(/\/$/, '');
  let fetchedModels = [];

  try {
    const resp = await fetch(`${cleanEndpoint}/models`, {
      headers: { 'Authorization': `Bearer ${apiKey.trim()}` }
    });
    const data = await resp.json().catch(() => ({}));
    const rawList = data.data || data.models || [];
    if (Array.isArray(rawList) && rawList.length) {
      fetchedModels = rawList.slice(0, 100).map(m => ({
        id: m.id || m.name,
        name: m.name || m.id
      }));
    }
  } catch (e) {}

  if (!fetchedModels.length) {
    fetchedModels = [{ id: `${name.toLowerCase().replace(/\s+/g, '-')}-default`, name: `${name} Default Model` }];
  }

  const ws = loadWorkspaceData();
  ws.customProviders = ws.customProviders || [];
  const provId = 'cust_' + crypto.randomBytes(4).toString('hex');
  const newProvider = {
    id: provId,
    name: name.trim(),
    apiKey: apiKey.trim(),
    endpoint: cleanEndpoint,
    models: fetchedModels,
    createdAt: new Date().toISOString()
  };

  ws.customProviders = ws.customProviders.filter(p => p.name.toLowerCase() !== name.trim().toLowerCase());
  ws.customProviders.push(newProvider);
  saveWorkspaceData(ws);

  res.json({
    ok: true,
    provider: { id: newProvider.id, name: newProvider.name, endpoint: newProvider.endpoint, models: newProvider.models }
  });
});

// KIE.ai Media Generation (8K Ultra HD)
app.post('/api/kie/generate', requireAuth, async (req, res) => {
  if (req.user.role !== 'owner' && req.user.tier !== 'pro') {
    return res.status(403).json({ error: 'Pro Subscription required for 8K KIE.ai Media Studio.' });
  }
  const { model, prompt, aspectRatio, quality } = req.body;
  const kieApiKey = process.env.KIE_API_KEY || '';
  if (!prompt) return res.status(400).json({ error: 'Prompt required' });

  const taskId = 'task_' + crypto.randomBytes(6).toString('hex');
  const enhancedPrompt = `${prompt}, ${quality || '8K Ultra HD'}, hyper-detailed, photorealistic, masterpiece`;
  const fallbackUrl = `https://image.pollinations.ai/prompt/${encodeURIComponent(enhancedPrompt)}?width=1920&height=1920&nologo=true`;

  global.kieTasks = global.kieTasks || {};
  global.kieTasks[taskId] = { status: 'processing', urls: [] };

  (async () => {
    if (kieApiKey) {
      try {
        const resp = await fetch('https://api.kie.ai/v1/images/generations', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${kieApiKey}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ model: model || 'flux/3', prompt: enhancedPrompt, aspect_ratio: aspectRatio || '1:1', quality: '8k' })
        });
        const data = await resp.json();
        const outUrl = data?.data?.[0]?.url || data?.url || data?.output_url || fallbackUrl;
        global.kieTasks[taskId] = { status: 'completed', urls: [outUrl] };
        return;
      } catch (e) {}
    }
    setTimeout(() => {
      global.kieTasks[taskId] = { status: 'completed', urls: [fallbackUrl] };
    }, 2500);
  })();

  res.json({ ok: true, taskId, message: '8K Ultra HD generation started.' });
});

app.get('/api/kie/status', requireAuth, (req, res) => {
  const { taskId } = req.query;
  global.kieTasks = global.kieTasks || {};
  const task = global.kieTasks[taskId] || { status: 'processing' };
  res.json({ ok: true, ...task });
});

// =========================================================
// SEARCH, FILES, WORKSPACE & AI CHAT
// =========================================================
app.post('/api/search', requireAuth, async (req, res) => {
  const { query } = req.body;
  if (!query) return res.status(400).json({ error: 'Query required' });
  const tavilyKey = process.env.TAVILY_API_KEY;

  if (tavilyKey) {
    try {
      const resp = await fetch('https://api.tavily.com/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: tavilyKey, query, include_answer: true, max_results: 5 })
      });
      const data = await resp.json();
      return res.json({ ok: true, answer: data.answer, results: data.results || [] });
    } catch (e) {}
  }

  res.json({
    ok: true,
    answer: `Live search summary for: "${query}"`,
    results: [{ title: query, url: `https://duckduckgo.com/?q=${encodeURIComponent(query)}`, content: 'Configure TAVILY_API_KEY in API Connections for deep live web citations.' }]
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

app.get('/api/files/download/:filename', requireAuth, (req, res) => {
  const filePath = path.join(UPLOADS_DIR, path.basename(req.params.filename));
  if (!fs.existsSync(filePath)) return res.status(404).send('File not found');
  res.sendFile(filePath);
});

app.delete('/api/files/:id', requireAuth, (req, res) => {
  const ws = loadWorkspaceData();
  ws.files = (ws.files || []).filter(f => f.id !== req.params.id);
  saveWorkspaceData(ws);
  res.json({ ok: true });
});

app.get('/api/workspace', requireAuth, (req, res) => {
  const ws = loadWorkspaceData();
  res.json({ ok: true, agents: ws.agents, projects: ws.projects, knowledge: ws.knowledge });
});

app.post('/api/agents', requireAuth, (req, res) => {
  const { name, instructions } = req.body;
  const ws = loadWorkspaceData();
  const agent = { id: 'agent_' + crypto.randomBytes(4).toString('hex'), name, instructions };
  ws.agents.push(agent);
  saveWorkspaceData(ws);
  res.json({ ok: true, agent });
});

app.post('/api/projects', requireAuth, (req, res) => {
  const { name, instructions } = req.body;
  const ws = loadWorkspaceData();
  const proj = { id: 'proj_' + crypto.randomBytes(4).toString('hex'), name, instructions };
  ws.projects.push(proj);
  saveWorkspaceData(ws);
  res.json({ ok: true, project: proj });
});

app.post('/api/knowledge', requireAuth, (req, res) => {
  const { title, content } = req.body;
  const ws = loadWorkspaceData();
  const doc = { id: 'kb_' + crypto.randomBytes(4).toString('hex'), title, content };
  ws.knowledge.push(doc);
  saveWorkspaceData(ws);
  res.json({ ok: true, doc });
});

app.post('/api/chat', requireAuth, async (req, res) => {
  const { messages = [], model = 'openrouter/auto', attachments = [], projectId = null } = req.body;
  const ws = loadWorkspaceData();

  // Build context from Project, Knowledge Base, and Attachments
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

  // 1. Custom Provider Routing (custom:provId:modelId)
  if (model.startsWith('custom:')) {
    const parts = model.split(':');
    const provId = parts[1];
    const actualModel = parts.slice(2).join(':');
    const prov = (ws.customProviders || []).find(p => p.id === provId);
    if (!prov) return res.status(404).json({ error: 'Custom provider not found.' });

    try {
      const resp = await fetch(`${prov.endpoint}/chat/completions`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${prov.apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: actualModel, messages: finalMessages })
      });
      const data = await resp.json();
      return res.json({ ok: true, reply: data?.choices?.[0]?.message?.content || 'No response from custom provider.' });
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }
  }

  // 2. KIE.ai Model Routing (kie:modelId)
  if (model.startsWith('kie:')) {
    if (req.user.role !== 'owner' && req.user.tier !== 'pro') {
      return res.status(403).json({ error: 'Pro Subscription required to use KIE.ai models.' });
    }
    const kieModel = model.replace(/^kie:/, '');
    const kieKey = process.env.KIE_API_KEY;
    if (kieKey) {
      try {
        const resp = await fetch('https://api.kie.ai/v1/chat/completions', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${kieKey}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ model: kieModel, messages: finalMessages })
        });
        const data = await resp.json();
        if (data?.choices?.[0]?.message?.content) {
          return res.json({ ok: true, reply: data.choices[0].message.content });
        }
      } catch (e) {}
    }
    // Fallback to OpenRouter if KIE chat endpoint falls back
  }

  // 3. OpenRouter Routing
  const apiKey = process.env.OPENROUTER_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'OPENROUTER_API_KEY missing in .env or API Connections' });

  const targetModel = model.startsWith('kie:') ? 'openrouter/auto' : model;
  try {
    const resp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'HTTP-Referer': 'http://localhost:3000',
        'X-Title': 'ORBIT AI Private OS'
      },
      body: JSON.stringify({ model: targetModel, messages: finalMessages })
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
