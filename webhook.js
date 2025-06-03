const crypto = require('crypto');

const CHANNEL_SECRET = process.env.LINE_CHANNEL_SECRET;
const CHANNEL_ACCESS_TOKEN = process.env.LINE_CHANNEL_ACCESS_TOKEN;

function verifySignature(req) {
  const signature = req.headers['x-line-signature'];
  const body = req.rawBody;
  const hash = crypto.createHmac('SHA256', CHANNEL_SECRET).update(body).digest('base64');
  return signature === hash;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }

  // Vercel 需要先讀原始 Buffer 以驗證簽章
  const buf = await new Promise((resolve) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
  });
  req.rawBody = buf;

  // 驗證簽章
  if (!verifySignature(req)) {
    return res.status(401).send('Invalid signature');
  }

  console.log('Received webhook:', req.body);

  // 你可以在這裡處理事件

  return res.status(200).send('OK');
}
