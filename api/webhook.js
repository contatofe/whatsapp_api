import crypto from 'node:crypto';

// ---------- GET: verificação (mesma lógica de antes, novo formato) ----------
export function GET(request) {
  const url = new URL(request.url);
  const mode = url.searchParams.get('hub.mode');
  const token = url.searchParams.get('hub.verify_token');
  const challenge = url.searchParams.get('hub.challenge');

  if (mode === 'subscribe' && token === process.env.VERIFY_TOKEN) {
    console.log('WEBHOOK VERIFIED');
    return new Response(challenge, { status: 200 });
  }
  return new Response('Forbidden', { status: 403 });
}

// ---------- Confere a assinatura ----------
function isValidSignature(rawBody, header) {
  if (!header || !header.startsWith('sha256=')) return false;

  const expected = crypto
    .createHmac('sha256', process.env.APP_SECRET)
    .update(rawBody)
    .digest('hex');

  const received = header.slice('sha256='.length);

  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(received, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------- POST: eventos ----------
export async function POST(request) {
  const rawBody = Buffer.from(await request.arrayBuffer()); // corpo cru, byte a byte
  const signature = request.headers.get('x-hub-signature-256');

  if (!isValidSignature(rawBody, signature)) {
    console.warn('Assinatura inválida, requisição rejeitada');
    return new Response('Invalid signature', { status: 401 });
  }

  const body = JSON.parse(rawBody.toString('utf8'));
  console.log(JSON.stringify(body, null, 2));
  return new Response(null, { status: 200 });
}