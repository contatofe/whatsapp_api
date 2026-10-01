import crypto from 'node:crypto';
import { waitUntil } from '@vercel/functions';
import { neon } from '@neondatabase/serverless';

const sql = neon(process.env.DATABASE_URL);

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
  const rawBody = Buffer.from(await request.arrayBuffer());
  const signature = request.headers.get('x-hub-signature-256');

  if (!isValidSignature(rawBody, signature)) {
    console.warn('Assinatura inválida, requisição rejeitada');
    return new Response('Invalid signature', { status: 401 });
  }

  const body = JSON.parse(rawBody.toString('utf8'));

  // Agenda o processamento para depois da resposta
  waitUntil(processEvent(body));

  // Responde na hora
  console.log('200 enviado para a Meta');
  return new Response(null, { status: 200 });
}

// Tenta gravar o ID. Retorna true se for novo, false se já existia.
async function isNewMessage(wamid) {
  const rows = await sql`
    INSERT INTO processed_messages (wamid)
    VALUES (${wamid})
    ON CONFLICT (wamid) DO NOTHING
    RETURNING wamid
  `;
  return rows.length > 0;
}

async function processEvent(body) {
  try {
    for (const entry of body.entry ?? []) {
      for (const change of entry.changes ?? []) {
        const messages = change.value?.messages ?? [];

        for (const msg of messages) {
          if (!(await isNewMessage(msg.id))) {
            console.log('Duplicata ignorada:', msg.id);
            continue;
          }

          console.log('Nova mensagem:', msg.id, 'tipo:', msg.type);
          // Fase 3: decidir e enviar a resposta aqui
        }
      }
    }
  } catch (err) {
    console.error('Erro ao processar evento:', err);
  }
}