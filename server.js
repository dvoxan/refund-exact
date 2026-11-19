const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const { calculateRefund } = require('./refund');

const CLIENT_ID = process.env.SHOPIFY_API_KEY;
const CLIENT_SECRET = process.env.SHOPIFY_API_SECRET;
const API_VERSION = process.env.SHOPIFY_API_VERSION || '2026-10';
const PORT = process.env.PORT || 3000;
const TOKEN_FILE = process.env.TOKEN_FILE || path.join(__dirname, 'tokens.json');

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error('Missing SHOPIFY_API_KEY or SHOPIFY_API_SECRET');
}

// ---- tiny token store (shop -> offline access token) ----
let tokens = {};
try { tokens = JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8')); } catch (e) { tokens = {}; }
function saveTokens() {
  try { fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokens)); } catch (e) { /* ephemeral disk is ok: we re-exchange */ }
}

const app = express();

// Webhooks need the raw body for HMAC verification.
app.post('/webhooks', express.raw({ type: '*/*' }), (req, res) => {
  const hmac = req.get('X-Shopify-Hmac-Sha256') || '';
  const digest = crypto.createHmac('sha256', CLIENT_SECRET || '').update(req.body).digest('base64');
  const a = Buffer.from(hmac);
  const b = Buffer.from(digest);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).send('Invalid HMAC');
  const topic = req.get('X-Shopify-Topic');
  const shop = req.get('X-Shopify-Shop-Domain');
  if (topic === 'app/uninstalled' || topic === 'shop/redact') {
    delete tokens[shop];
    saveTokens();
  }
  // customers/data_request and customers/redact: this app stores no customer data.
  res.status(200).send('ok');
});

app.use(express.json());

app.use((req, res, next) => {
  const shop = req.query.shop;
  const valid = typeof shop === 'string' && /^[a-z0-9][a-z0-9-]*\.myshopify\.com$/i.test(shop);
  res.set('Content-Security-Policy', valid
    ? 'frame-ancestors https://' + shop + ' https://admin.shopify.com;'
    : 'frame-ancestors https://admin.shopify.com https://*.myshopify.com;');
  next();
});

app.get('/healthz', (req, res) => res.send('ok'));

app.get('/', (req, res) => {
  const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8')
    .replace(/__SHOPIFY_API_KEY__/g, CLIENT_ID || '');
  res.type('html').send(html);
});

// ---- auth: verify session token, exchange for an access token ----
function verifySession(req) {
  const h = req.get('Authorization') || '';
  const token = h.replace(/^Bearer /, '');
  const payload = jwt.verify(token, CLIENT_SECRET, { algorithms: ['HS256'], audience: CLIENT_ID });
  const shop = new URL(payload.dest).hostname;
  return { shop, idToken: token };
}

async function getAccessToken(shop, idToken) {
  if (tokens[shop]) return tokens[shop];
  const r = await fetch('https://' + shop + '/admin/oauth/access_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: idToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      requested_token_type: 'urn:shopify:params:oauth:token-type:offline-access-token',
    }),
  });
  if (!r.ok) throw new Error('Token exchange failed (' + r.status + ')');
  const data = await r.json();
  tokens[shop] = data.access_token;
  saveTokens();
  return data.access_token;
}

async function adminGraphql(shop, accessToken, query, variables) {
  const r = await fetch('https://' + shop + '/admin/api/' + API_VERSION + '/graphql.json', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Shopify-Access-Token': accessToken },
    body: JSON.stringify({ query, variables }),
  });
  if (r.status === 401) { const e = new Error('unauthorized'); e.code = 401; throw e; }
  const data = await r.json();
  if (data.errors) throw new Error(JSON.stringify(data.errors));
  return data.data;
}

const ORDER_QUERY = `
query($q: String!) {
  orders(first: 1, query: $q) {
    nodes {
      id
      name
      currencyCode
      taxesIncluded
      displayFinancialStatus
      lineItems(first: 100) {
        nodes {
          id
          title
          variantTitle
          quantity
          refundableQuantity
          originalTotalSet { shopMoney { amount } }
          discountedTotalSet { shopMoney { amount } }
          taxLines { priceSet { shopMoney { amount } } }
        }
      }
    }
  }
}`;

async function loadOrder(req, orderName) {
  const { shop, idToken } = verifySession(req);
  let accessToken = await getAccessToken(shop, idToken);
  const name = String(orderName || '').trim().replace(/^#/, '');
  if (!/^[A-Za-z0-9-]+$/.test(name)) throw Object.assign(new Error('Enter an order number like 1001'), { code: 400 });
  let data;
  try {
    data = await adminGraphql(shop, accessToken, ORDER_QUERY, { q: 'name:#' + name });
  } catch (e) {
    if (e.code !== 401) throw e;
    delete tokens[shop];
    accessToken = await getAccessToken(shop, idToken);
    data = await adminGraphql(shop, accessToken, ORDER_QUERY, { q: 'name:#' + name });
  }
  const node = data.orders.nodes[0];
  if (!node) throw Object.assign(new Error('Order #' + name + ' not found. Orders older than 60 days need extra approval from Shopify.'), { code: 404 });
  return {
    id: node.id,
    name: node.name,
    currency: node.currencyCode,
    status: node.displayFinancialStatus,
    taxesIncluded: node.taxesIncluded,
    lineItems: node.lineItems.nodes.map((li) => ({
      id: li.id,
      title: li.title,
      variantTitle: li.variantTitle,
      quantity: li.quantity,
      refundableQuantity: li.refundableQuantity,
      originalTotal: li.originalTotalSet.shopMoney.amount,
      discountedTotal: li.discountedTotalSet.shopMoney.amount,
      taxTotal: li.taxLines.reduce((s, t) => s + Number(t.priceSet.shopMoney.amount), 0),
    })),
  };
}

function sendError(res, e) {
  const status = e.name === 'JsonWebTokenError' || e.name === 'TokenExpiredError' ? 401 : e.code || 500;
  res.status(typeof status === 'number' ? status : 500).json({ error: e.message || 'Something went wrong' });
}

app.get('/api/order', async (req, res) => {
  try {
    res.json(await loadOrder(req, req.query.name));
  } catch (e) { sendError(res, e); }
});

app.post('/api/calc', async (req, res) => {
  try {
    const order = await loadOrder(req, req.body.name);
    const result = calculateRefund(order, req.body.picks || []);
    res.json({ currency: order.currency, ...result });
  } catch (e) { sendError(res, e); }
});

app.listen(PORT, () => console.log('Refund Exact listening on ' + PORT));
