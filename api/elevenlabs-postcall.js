// ElevenLabs post-call webhook receiver
// Verifies HMAC, fires a Slack notification with the conversation_id so the
// Chief of Staff agent picks it up and fetches the full transcript via the
// ElevenLabs API on demand. Returns 200.
import crypto from 'node:crypto';

export const config = { api: { bodyParser: false } };

async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks);
}

function verifySignature(rawBody, header, secret) {
  if (!header || !secret) return false;
  const parts = Object.fromEntries(
    header.split(',').map((p) => p.trim().split('='))
  );
  const t = parts.t;
  const sig = parts.v0;
  if (!t || !sig) return false;
  const payload = `${t}.${rawBody.toString('utf8')}`;
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    return false;
  }
}

async function postSlack(url, text, blocks) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, blocks }),
  });
  if (!res.ok) throw new Error(`slack post failed ${res.status}`);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });
  const raw = await readRawBody(req);
  const sig = req.headers['elevenlabs-signature'];
  const secret = process.env.ELEVENLABS_WEBHOOK_SECRET;

  if (!verifySignature(raw, sig, secret)) {
    return res.status(401).json({ error: 'invalid signature' });
  }

  let payload;
  try {
    payload = JSON.parse(raw.toString('utf8'));
  } catch {
    return res.status(400).json({ error: 'invalid json' });
  }

  const type = payload?.type || 'unknown';
  const data = payload?.data || {};
  const convId = data.conversation_id || 'unknown';
  const agentId = data.agent_id || 'unknown';
  const status = data.status || '';
  const durSecs = data?.metadata?.call_duration_secs || '';
  const summary = data?.analysis?.transcript_summary || '';

  const slackUrl = process.env.SLACK_WEBHOOK_URL;
  if (slackUrl) {
    try {
      await postSlack(
        slackUrl,
        `Voice agent call complete (${type}) — ${convId}`,
        [
          {
            type: 'section',
            text: {
              type: 'mrkdwn',
              text: `*Voice agent call complete*\n*Type:* \`${type}\`\n*Agent:* \`${agentId}\`\n*Conversation:* \`${convId}\`\n*Status:* ${status}\n*Duration:* ${durSecs}s`,
            },
          },
          summary && {
            type: 'section',
            text: { type: 'mrkdwn', text: `*Summary:*\n${summary.slice(0, 1500)}` },
          },
        ].filter(Boolean)
      );
    } catch (err) {
      console.error('slack notify failed', err);
    }
  }

  return res.status(200).json({ ok: true, conversation_id: convId, type });
}
