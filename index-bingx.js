const express = require('express');
const { createHmac } = require('crypto');
const app = express();
app.use(express.json());

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-bingx-key, x-bingx-secret');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const BASE_URL = 'https://open-api.bingx.com';

app.all('/', async (req, res) => {
  const endpoint = req.query.endpoint;
  if (!endpoint || !endpoint.startsWith('/openApi/')) {
    return res.json({ code: -1, msg: 'Endpoint non valido — deve iniziare con /openApi/' });
  }

  const method = req.method === 'POST' ? 'POST' : req.method === 'DELETE' ? 'DELETE' : 'GET';
  const apiKey = req.headers['x-bingx-key']    || '';
  const secret = req.headers['x-bingx-secret'] || '';

  // ── Chiamate pubbliche (no auth) ──
  if (!apiKey || !secret) {
    const params = { ...req.query };
    delete params.endpoint;
    const queryStr = Object.keys(params).length
      ? new URLSearchParams(params).toString()
      : '';
    const fullUrl = `${BASE_URL}${endpoint}${queryStr ? '?' + queryStr : ''}`;
    try {
      const response = await fetch(fullUrl, {
        method,
        headers: { 'Content-Type': 'application/json' },
        ...(method === 'POST' ? { body: '{}' } : {}),
      });
      const data = await response.json();
      return res.json(data);
    } catch (e) {
      return res.json({ code: -1, msg: e.message });
    }
  }

  // ── Chiamate autenticate ──
  const ts = String(Date.now());

  const qParams = { ...req.query };
  delete qParams.endpoint;
  const bodyParams = (method === 'POST' && req.body && Object.keys(req.body).length) ? req.body : {};
  paramsToSign = { ...qParams, ...bodyParams, timestamp: ts };

  const signPayload = Object.keys(paramsToSign)
    .map(k => `${k}=${paramsToSign[k]}`)
    .join('&');

  const signature = createHmac('sha256', secret)
    .update(signPayload)
    .digest('hex');

  const signedPayload = signPayload + '&signature=' + signature;

  // BingX: GET/DELETE → params in query string
  //        POST       → params nel body come x-www-form-urlencoded
  const isPost = method === 'POST';
  const fullUrl = isPost
    ? `${BASE_URL}${endpoint}`
    : `${BASE_URL}${endpoint}?${signedPayload}`;

  try {
    const fetchOpts = {
      method,
      headers: {
        'X-BX-APIKEY': apiKey,
        'Content-Type': isPost ? 'application/x-www-form-urlencoded' : 'application/json',
      },
      ...(isPost ? { body: signedPayload } : {}),
    };
    const response = await fetch(fullUrl, fetchOpts);
    const text = await response.text();
    console.log(`[BingX PROXY] ${method} ${endpoint} → ${text.slice(0, 400)}`);
    if (!text || !text.trim()) {
      return res.json({ code: 0, msg: 'ok' });
    }
    let data;
    try { data = JSON.parse(text); }
    catch(e) { return res.json({ code: -1, msg: 'BingX non-JSON: ' + text.slice(0, 200) }); }
    res.json(data);
  } catch (e) {
    res.json({ code: -1, msg: e.message });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('BingX proxy running'));
