/**
 * WebAuthn / Passkeys strategy.
 * Wraps @simplewebauthn/server — we do NOT reimplement WebAuthn primitives.
 *
 * SECURITY: All cryptographic verification is delegated to @simplewebauthn/server,
 * which is a well-audited library. We only handle storage and session creation.
 */
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type GenerateRegistrationOptionsOpts,
  type VerifyRegistrationResponseOpts,
  type GenerateAuthenticationOptionsOpts,
  type VerifyAuthenticationResponseOpts,
} from '@simplewebauthn/server';
import type {
  AuthenticationResponseJSON,
  AuthenticatorDevice,
  AuthenticatorTransportFuture,
  RegistrationResponseJSON,
} from '@simplewebauthn/types';
import type { BaseUser, ResolvedAuthConfig, TokenPair, Session } from '../../types/index.js';
import { Errors } from '../../errors.js';
import { emitAudit } from '../../audit.js';
import { createSession } from '../../session.js';

// ─── Registration ─────────────────────────────────────────────────────────────

export interface WebAuthnRegistrationOptionsInput {
  rpName: string;
  rpId: string;
  origin: string;
}

/**
 * Generate WebAuthn registration options.
 * Store the challenge server-side (in session or token store) before returning.
 */
export async function getRegistrationOptions<TUser extends BaseUser>(
  user: TUser,
  input: WebAuthnRegistrationOptionsInput,
  config: ResolvedAuthConfig<TUser>,
): Promise<{ options: Awaited<ReturnType<typeof generateRegistrationOptions>>; challenge: string }> {
  if (!config.adapters.credential) throw Errors.adapterNotConfigured('credential');

  const existingCredentials = await config.adapters.credential.findByUserId(user.id);

  const opts: GenerateRegistrationOptionsOpts = {
    rpName: input.rpName,
    rpID: input.rpId,
    userID: new TextEncoder().encode(user.id),
    userName: user.email,
    userDisplayName: user.email,
    attestationType: 'none',
    excludeCredentials: existingCredentials.map((c) => ({
      id: c.credentialId,
      ...(c.transports ? { transports: c.transports as AuthenticatorTransportFuture[] } : {}),
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
  };

  const options = await generateRegistrationOptions(opts);
  return { options, challenge: options.challenge };
}

export interface WebAuthnRegistrationVerifyInput {
  response: RegistrationResponseJSON;
  expectedChallenge: string;
  rpId: string;
  origin: string;
}

/**
 * Verify a WebAuthn registration response and store the credential.
 */
export async function verifyRegistration<TUser extends BaseUser>(
  user: TUser,
  input: WebAuthnRegistrationVerifyInput,
  config: ResolvedAuthConfig<TUser>,
): Promise<void> {
  if (!config.adapters.credential) throw Errors.adapterNotConfigured('credential');

  const opts: VerifyRegistrationResponseOpts = {
    response: input.response,
    expectedChallenge: input.expectedChallenge,
    expectedOrigin: input.origin,
    expectedRPID: input.rpId,
    requireUserVerification: true,
  };

  const { verified, registrationInfo } = await verifyRegistrationResponse(opts);

  if (!verified || !registrationInfo) {
    throw Errors.webAuthnChallengeFailed();
  }

  const { credentialID, credentialPublicKey, counter, credentialDeviceType, credentialBackedUp } =
    registrationInfo;

  await config.adapters.credential.save({
    userId: user.id,
    credentialId: credentialID,
    publicKey: credentialPublicKey,
    counter,
    deviceType: credentialDeviceType,
    backedUp: credentialBackedUp,
    ...(input.response.response.transports
      ? { transports: input.response.response.transports as string[] }
      : {}),
  });
}

// ─── Authentication ───────────────────────────────────────────────────────────

export interface WebAuthnAuthOptionsInput {
  rpId: string;
  /** Optional — for username-less (resident key) flows, omit this. */
  userId?: string;
}

/**
 * Generate WebAuthn authentication options.
 */
export async function getAuthenticationOptions<TUser extends BaseUser>(
  input: WebAuthnAuthOptionsInput,
  config: ResolvedAuthConfig<TUser>,
): Promise<{ options: Awaited<ReturnType<typeof generateAuthenticationOptions>>; challenge: string }> {
  if (!config.adapters.credential) throw Errors.adapterNotConfigured('credential');

  const allowCredentials = input.userId
    ? (await config.adapters.credential.findByUserId(input.userId)).map((c) => ({
        id: c.credentialId,
        ...(c.transports ? { transports: c.transports as AuthenticatorTransportFuture[] } : {}),
      }))
    : [];

  const opts: GenerateAuthenticationOptionsOpts = {
    rpID: input.rpId,
    allowCredentials,
    userVerification: 'preferred',
  };

  const options = await generateAuthenticationOptions(opts);
  return { options, challenge: options.challenge };
}

export interface WebAuthnAuthVerifyInput {
  response: AuthenticationResponseJSON;
  expectedChallenge: string;
  rpId: string;
  origin: string;
}

export interface WebAuthnAuthResult<TUser extends BaseUser> {
  user: TUser;
  session: Session;
  tokens: TokenPair;
}

/**
 * Verify a WebAuthn authentication response and create a session.
 */
export async function verifyAuthentication<TUser extends BaseUser>(
  input: WebAuthnAuthVerifyInput,
  config: ResolvedAuthConfig<TUser>,
  meta: { ip?: string | null; userAgent?: string | null } = {},
): Promise<WebAuthnAuthResult<TUser>> {
  if (!config.adapters.credential) throw Errors.adapterNotConfigured('credential');

  const credentialId = input.response.id;
  const credential = await config.adapters.credential.findById(credentialId);

  if (!credential) throw Errors.webAuthnCredentialNotFound();

  const authenticator: AuthenticatorDevice = {
    credentialID: credential.credentialId,
    credentialPublicKey: credential.publicKey,
    counter: credential.counter,
    ...(credential.transports
      ? { transports: credential.transports as AuthenticatorTransportFuture[] }
      : {}),
  };

  const opts: VerifyAuthenticationResponseOpts = {
    response: input.response,
    expectedChallenge: input.expectedChallenge,
    expectedOrigin: input.origin,
    expectedRPID: input.rpId,
    requireUserVerification: true,
    authenticator,
  };

  const { verified, authenticationInfo } = await verifyAuthenticationResponse(opts);

  if (!verified) throw Errors.webAuthnChallengeFailed();

  // Update counter to prevent replay attacks
  await config.adapters.credential.update(credential.credentialId, {
    counter: authenticationInfo.newCounter,
    lastUsedAt: new Date(),
  });

  const user = await config.adapters.user.findById(credential.userId);
  if (!user) throw Errors.userNotFound();

  const { session, tokens } = await createSession(user, config, {
    ...meta,
    mfaVerified: true, // WebAuthn counts as MFA
  });

  await emitAudit('user.login', {
    userId: user.id,
    sessionId: session.id,
    ip: meta.ip ?? null,
    userAgent: meta.userAgent ?? null,
    metadata: { method: 'webauthn' },
  });

  return { user, session, tokens };
}
