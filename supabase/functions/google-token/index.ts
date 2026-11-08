// Fonction serveur Supabase « google-token » — CRM Meyaclo
// Garde pour chaque membre une autorisation Google durable (refresh token) et fournit
// au CRM un accès Google Agenda toujours valide, sans que l'utilisateur ait à se reconnecter.
// Secrets nécessaires (Edge Functions → Secrets) : GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
import { createClient } from 'npm:@supabase/supabase-js@2';

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};
const json = (o: unknown, s = 200) =>
  new Response(JSON.stringify(o), { status: s, headers: { ...cors, 'Content-Type': 'application/json' } });

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  try {
    const admin = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!);
    const jwt = (req.headers.get('Authorization') || '').replace('Bearer ', '');
    const { data: { user }, error } = await admin.auth.getUser(jwt);
    if (error || !user) return json({ error: 'non_connecte' });

    const { action, code } = await req.json().catch(() => ({}));
    const CID = Deno.env.get('GOOGLE_CLIENT_ID'), SEC = Deno.env.get('GOOGLE_CLIENT_SECRET');
    if (!CID || !SEC) return json({ error: 'secrets_google_manquants' });

    const tokenReq = async (params: Record<string, string>) => {
      const r = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: CID, client_secret: SEC, ...params }),
      });
      return { ok: r.ok, j: await r.json() };
    };
    const { data: row } = await admin.from('google_tokens').select('refresh_token').eq('user_id', user.id).maybeSingle();

    // 1re connexion : échange du code contre une autorisation durable
    if (action === 'exchange') {
      const { ok, j } = await tokenReq({ code, grant_type: 'authorization_code', redirect_uri: 'postmessage' });
      if (!ok) return json({ error: j.error_description || j.error });
      const rt = j.refresh_token || row?.refresh_token;
      if (!rt) {
        // Google n'a pas fourni d'autorisation durable (accès déjà accordé auparavant) : on la révoque pour pouvoir la redemander
        await fetch('https://oauth2.googleapis.com/revoke?token=' + j.access_token, { method: 'POST' });
        return json({ error: 'retry' });
      }
      await admin.from('google_tokens').upsert({ user_id: user.id, email: user.email, refresh_token: rt, updated_at: new Date().toISOString() });
      return json({ access_token: j.access_token, expires_in: j.expires_in });
    }

    // Déconnexion
    if (action === 'revoke') {
      if (row) await fetch('https://oauth2.googleapis.com/revoke?token=' + row.refresh_token, { method: 'POST' });
      await admin.from('google_tokens').delete().eq('user_id', user.id);
      return json({ ok: true });
    }

    // Par défaut : fournir un accès Google à jour
    if (!row) return json({ error: 'aucun_jeton' });
    const { ok, j } = await tokenReq({ refresh_token: row.refresh_token, grant_type: 'refresh_token' });
    if (!ok) {
      if (j.error === 'invalid_grant') await admin.from('google_tokens').delete().eq('user_id', user.id);
      return json({ error: j.error || 'refresh_impossible' });
    }
    return json({ access_token: j.access_token, expires_in: j.expires_in });
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
