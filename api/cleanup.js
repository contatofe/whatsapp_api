import { neon } from '@neondatabase/serverless';

const sql = neon(process.env.DATABASE_URL);

export async function GET(request) {
  // Só a Vercel Cron pode chamar esta rota
  if (request.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) {
    return new Response('Unauthorized', { status: 401 });
  }

  const events = await sql`
    DELETE FROM webhook_events
    WHERE received_at < now() - interval '30 days'
    RETURNING id
  `;

  const ids = await sql`
    DELETE FROM processed_messages
    WHERE received_at < now() - interval '30 days'
    RETURNING wamid
  `;

  console.log(`Limpeza: ${events.length} eventos e ${ids.length} IDs removidos`);
  return Response.json({ events: events.length, ids: ids.length });
}