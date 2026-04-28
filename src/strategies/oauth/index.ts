import { randomBytes } from 'node:crypto';
import type {
  BaseUser,
  ResolvedAuthConfig,
  OAuthProfile,
  OAuthAccount,
  TokenPair,
  Session,
} from '../../types/index.js';
import { generateCodeVerifier, generateCodeChallenge } from '../../crypto/pkce.js';
import { safeCompare } from '../../crypto/tokens.js';
import { Errors } from '../../errors.js';
import { emitAudit } from '../../audit.js';
import { createSession } from '../../session.js';

// ─── Provider presets ─────────────────────────────────────────────────────────

export interface OAuthProviderConfig {
  clientId: string;
  clientSecret: string;
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl?: string;
  scopes: string[];
  /** Override to customize how the provider's user object maps to OAuthProfile. */
  mapProfile?: (raw: Record<string, unknown>) => OAuthProfile;
}

export const PROVIDERS: Record<string, Omit<OAuthProviderConfig, 'clientId' | 'clientSecret'>> = {
  google: {
    authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://www.googleapis.com/oauth2/v3/userinfo',
    scopes: ['openid', 'email', 'profile'],
    mapProfile: (raw) => ({
      provider: 'google',
      providerUserId: String(raw['sub']),
      email: raw['email'] as string | null,
      emailVerified: raw['email_verified'] as boolean | undefined,
      displayName: raw['name'] as string | null,
      avatarUrl: raw['picture'] as string | null,
      raw,
    }),
  },
  github: {
    authorizationUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    userInfoUrl: 'https://api.github.com/user',
    scopes: ['read:user', 'user:email'],
    mapProfile: (raw) => ({
      provider: 'github',
      providerUserId: String(raw['id']),
      email: raw['email'] as string | null,
      emailVerified: raw['email'] != null,
      displayName: raw['name'] as string | null,
      avatarUrl: raw['avatar_url'] as string | null,
      raw,
    }),
  },
  discord: {
    authorizationUrl: 'https://discord.com/api/oauth2/authorize',
    tokenUrl: 'https://discord.com/api/oauth2/token',
    userInfoUrl: 'https://discord.com/api/users/@me',
    scopes: ['identify', 'email'],
    mapProfile: (raw) => ({
      provider: 'discord',
      providerUserId: String(raw['id']),
      email: raw['email'] as string | null,
      emailVerified: raw['verified'] as boolean | undefined,
      displayName: raw['username'] as string | null,
      avatarUrl: raw['avatar']
        ? `https://cdn.discordapp.com/avatars/${raw['id']}/${raw['avatar']}.png`
        : null,
      raw,
    }),
  },
  microsoft: {
    authorizationUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
    userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
    scopes: ['openid', 'email', 'profile'],
    mapProfile: (raw) => ({
      provider: 'microsoft',
      providerUserId: String(raw['id']),
      email: raw['mail'] as string | null ?? raw['userPrincipalName'] as string | null,
      emailVerified: true,
      displayName: raw['displayName'] as string | null,
      avatarUrl: null,
      raw,
    }),
  },
};

// ─── Authorization URL ────────────────────────────────────────────────────────

export interface AuthorizationUrlResult {
  url: string;
  state: string;
  codeVerifier: string;
}

/**
 * Generate an OAuth2 authorization URL with PKCE (S256) and state parameter.
 *
 * @param provider - Provider config (use PROVIDERS preset or custom)
 * @param redirectUri - Your callback URL
 * @returns URL to redirect the user to, plus state + verifier to store in session
 */
export function buildAuthorizationUrl(
  provider: OAuthProviderConfig,
  redirectUri: string,
): AuthorizationUrlResult {
  const state = randomBytes(16).toString('hex');
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);

  const params = new URLSearchParams({
    client_id: provider.clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: provider.scopes.join(' '),
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  return {
    url: `${provider.authorizationUrl}?${params.toString()}`,
    state,
    codeVerifier,
  };
}

// ─── Callback handling ────────────────────────────────────────────────────────

export interface OAuthCallbackInput {
  code: string;
  state: string;
  /** The state value stored when the authorization URL was generated. */
  storedState: string;
  /** The code verifier stored when the authorization URL was generated. */
  codeVerifier: string;
  redirectUri: string;
}

export interface OAuthCallbackResult<TUser extends BaseUser> {
  user: TUser;
  session: Session;
  tokens: TokenPair;
  profile: OAuthProfile;
  isNewUser: boolean;
}

/**
 * Handle the OAuth2 callback.
 *
 * Flow:
 * 1. Validate state (CSRF protection)
 * 2. Exchange code for tokens (with PKCE verifier)
 * 3. Fetch user profile
 * 4. Call findOrCreateUser hook — app controls the linking policy
 * 5. Create session
 */
export async function handleOAuthCallback<TUser extends BaseUser>(
  provider: OAuthProviderConfig,
  input: OAuthCallbackInput,
  config: ResolvedAuthConfig<TUser>,
  findOrCreateUser: (profile: OAuthProfile) => Promise<{ user: TUser; isNewUser: boolean }>,
  meta: { ip?: string | null; userAgent?: string | null } = {},
): Promise<OAuthCallbackResult<TUser>> {
  // Validate state — constant-time comparison
  if (!safeCompare(input.state, input.storedState)) {
    throw Errors.oauthStateMismatch();
  }

  // Exchange code for tokens
  const tokenResponse = await exchangeCode(provider, input);
  const accessToken = tokenResponse['access_token'] as string | undefined;
  if (!accessToken) throw Errors.oauthCodeInvalid();

  // Fetch user profile
  let profile: OAuthProfile;
  if (provider.userInfoUrl) {
    const userInfoRes = await fetch(provider.userInfoUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!userInfoRes.ok) throw Errors.oauthCodeInvalid();
    const raw = await userInfoRes.json() as Record<string, unknown>;
    profile = provider.mapProfile ? provider.mapProfile(raw) : defaultMapProfile(provider, raw);
  } else {
    throw Errors.invalidConfig('userInfoUrl is required for OAuth providers');
  }

  const { user, isNewUser } = await findOrCreateUser(profile);

  const { session, tokens } = await createSession(user, config, meta);

  await emitAudit(isNewUser ? 'user.registered' : 'user.login', {
    userId: user.id,
    sessionId: session.id,
    ip: meta.ip ?? null,
    userAgent: meta.userAgent ?? null,
    metadata: { provider: profile.provider, method: 'oauth' },
  });

  return { user, session, tokens, profile, isNewUser };
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

async function exchangeCode(
  provider: OAuthProviderConfig,
  input: OAuthCallbackInput,
): Promise<Record<string, unknown>> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: input.code,
    redirect_uri: input.redirectUri,
    client_id: provider.clientId,
    client_secret: provider.clientSecret,
    code_verifier: input.codeVerifier,
  });

  const res = await fetch(provider.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: body.toString(),
  });

  if (!res.ok) throw Errors.oauthCodeInvalid();
  return res.json() as Promise<Record<string, unknown>>;
}

function defaultMapProfile(
  provider: OAuthProviderConfig,
  raw: Record<string, unknown>,
): OAuthProfile {
  return {
    provider: provider.authorizationUrl,
    providerUserId: String(raw['id'] ?? raw['sub'] ?? ''),
    email: raw['email'] as string | null,
    emailVerified: false,
    displayName: raw['name'] as string | null,
    avatarUrl: null,
    raw,
  };
}
