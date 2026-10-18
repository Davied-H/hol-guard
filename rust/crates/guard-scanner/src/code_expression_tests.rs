use crate::scan_text;
use guard_rules::MAX_SCAN_BYTES;

fn flagged(text: &str) -> bool {
    scan_text(text, true, true, MAX_SCAN_BYTES, None)
        .matches
        .iter()
        .any(|matched| matched.classifier == "credential-assignment")
}

#[test]
fn click_tracking_redirect_route_is_not_a_credential() {
    let route = "\
import { NextResponse } from 'next/server';
import { z } from 'zod';

const querySchema = z.object({
  token: z.string().min(1),
  target: z.string().url(),
});

export async function GET(request: Request) {
  const query = new URL(request.url).searchParams;
  const parsed = querySchema.safeParse({
    token: query.get('token') ?? '',
    target: query.get('target') ?? '',
  });
  if (!parsed.success) {
    return NextResponse.redirect(new URL('/', request.url));
  }
  const token = parsed.data.token;
  await recordClick({ token: token.slice(0, 8), target: parsed.data.target });
  return NextResponse.redirect(parsed.data.target);
}
";
    assert!(!flagged(route));
}

#[test]
fn reminder_worker_that_builds_unsubscribe_links_is_not_a_credential() {
    let worker = "\
type CreateUnsubscribeToken = (params: { userId: string; scope: 'weekly-reminder' }) => Promise<string>;

const isCreateUnsubscribeToken = (value: unknown): value is CreateUnsubscribeToken =>
  typeof value === 'function';

export async function sendReminders(users: User[]) {
  const createUnsubscribeToken = await loadCreateUnsubscribeToken();
  for (const user of users) {
    const unsubscribeToken = await createUnsubscribeToken({
      userId: user.id,
      scope: 'weekly-reminder',
    });
    const unsubscribeUrl = `${baseUrl}/unsubscribe?token=${encodeURIComponent(unsubscribeToken)}`;
    const confirmUrl = `${baseUrl}/confirm?token=${unsubscribeToken}&scope=reminder`;
    await send(user.email, renderReminder({ unsubscribeUrl, confirmUrl }));
  }
}
";
    assert!(!flagged(worker));
}

#[test]
fn reminder_worker_with_multiline_function_type_is_not_a_credential() {
    let worker = "\
type CreateUnsubscribeToken = (params: {
  userId: string;
  scope: 'weekly-reminder';
}) => Promise<string>;
";
    assert!(!flagged(worker));
}

#[test]
fn signing_helper_that_names_environment_secrets_is_not_a_credential() {
    let helper = "\
import { createHmac, timingSafeEqual } from 'crypto';

export function signDeliveryToken(payload: string): string {
  const secret = process.env.DELIVERY_TOKEN_SECRET ?? '';
  const payloadB64 = Buffer.from(payload).toString('base64url');
  const signature = createHmac('sha256', secret).update(payload).digest('base64url');
  const token = `${payloadB64}.${signature}`;
  return token;
}

export function verifyDeliveryToken(token: string, expected: string): boolean {
  if (token === expected) {
    return true;
  }
  if (token == null) {
    logger.warn('Delivery token HMAC verification failed', { token: token.slice(0, 20) });
  }
  return timingSafeEqual(Buffer.from(token), Buffer.from(expected));
}
";
    assert!(!flagged(helper));
}

#[test]
fn token_handling_in_other_styles_is_not_a_credential() {
    for text in [
        "const token = crypto.randomBytes(32).toString('hex');",
        "const token = await signToken(user.id);",
        "const apiKey = await getApiKey();",
        "const token = req.query.token as string;",
        "const apiKey = req.headers['x-api-key'] as string;",
        "const token = authHeader?.split(' ')[1];",
        "const token = authHeader.replace('Bearer ', '');",
        "const emailToken = jwt.sign({ sub: user.id }, secret);",
        "const token = sign({ id }, secret, { expiresIn: '1h' });",
        "const password = await bcrypt.hash(input, 10);",
        "const auth = { token: await getToken(), user };",
        "href: `${base}/confirm?token=${tok}`,",
        "export const config = { secret: process.env.SECRET!, token: undefined };",
        "tokens.map(token => token.trim())",
        "if (!token || token === expected) {",
        "token = secrets.token_urlsafe(32)",
        "token := generateToken(user)",
        "let token = Uuid::new_v4().to_string();",
    ] {
        assert!(!flagged(text), "{text:?}");
    }
}

#[test]
fn literal_secrets_beside_code_are_still_credentials() {
    let live = ["sk-", "live-abcdefghijklmnop1234"].concat();
    let sample = ["a1b2c3d4", "e5f6g7h8i9j0"].concat();
    let long = ["abcdef123456", "abcdef123456"].concat();
    for text in [
        "const token = process.env.TOKEN || 'dev-token-123';".to_string(),
        "const secret = process.env.SECRET ?? 'fallbackSecretValue1';".to_string(),
        "const token = prefix + 'hunter2';".to_string(),
        format!("const token = getKey() + '{long}';"),
        format!("const secret = await vault.read('{long}');"),
        format!("const apiKey = loadKey('{live}');"),
        format!("const token = login(user, '{sample}');"),
        "const token = login(user, 'correct-horse-battery-staple');".to_string(),
        format!("const token = `{live}${{suffix}}`;"),
        "const token = `abcdefghijklmnop1234567890`;".to_string(),
        "const password = `correct horse battery staple`;".to_string(),
        "if (password === 'hunter2production') {".to_string(),
        "if (password == 123456) {".to_string(),
        "password=$(echo hunter2)".to_string(),
        "secret = hunter2 || fallback".to_string(),
        "password = hunter2".to_string(),
        "password: foo.bar.baz".to_string(),
        "const secret = 'x' as string;".to_string(),
        "token: abcdef0123456789abcdef".to_string(),
    ] {
        assert!(flagged(&text), "{text:?}");
    }
}
