import { z } from 'zod';
import { ConfigManager } from '@/modules/config/ipc/manager';
import { AuthServer } from '@/modules/cloud-account/ipc/authServer';
import { EnvHttpProxyAgent, ProxyAgent } from 'undici';
import {
  buildUserAgent,
  FALLBACK_VERSION,
  resolveLocalInstalledVersion,
} from '@/modules/proxy-gateway/server/common/utils/request-user-agent';
import { isEmpty, isNumber, isString, isUndefined } from 'lodash-es';
import { v4 } from 'uuid';
import { logger } from '@/shared/logging/logger';
import {
  type OAuthClientDescriptor,
  OAuthClientRegistryService,
} from './OAuthClientRegistryService';
import { GOOGLE_OAUTH_SCOPE } from '../oauthScopes';

// --- Constants & Config ---
const URLS = {
  TOKEN: 'https://oauth2.googleapis.com/token',
  USER_INFO: 'https://www.googleapis.com/oauth2/v2/userinfo',
  AUTH: 'https://accounts.google.com/o/oauth2/v2/auth',
  LOAD_PROJECT: 'https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist',
  SANDBOX_LOAD_PROJECT:
    'https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:loadCodeAssist',
  DAILY_LOAD_PROJECT: 'https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist',
  FETCH_CREDITS: 'https://cloudcode-pa.googleapis.com/v1internal:fetchCredits',
};

const QUOTA_API_ENDPOINTS = [
  'https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:fetchAvailableModels',
  'https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels',
  'https://cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels',
];

const QUOTA_SUMMARY_ENDPOINTS = [
  'https://daily-cloudcode-pa.sandbox.googleapis.com/v1internal:retrieveUserQuotaSummary',
  'https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary',
  'https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary',
];

// Request timeout in milliseconds (30 seconds)
const REQUEST_TIMEOUT_MS = 30000;
const OAUTH_CLIENT_ERROR_CODES = new Set([
  'invalid_client',
  'unauthorized_client',
  'deleted_client',
]);
const INVALID_GRANT_RETRY_DELAY_MS = 500;

const OAuthErrorResponseSchema = z.object({
  error: z.string().optional(),
  error_description: z.string().optional(),
});

function parseOAuthErrorResponse(
  errorText: string,
): z.infer<typeof OAuthErrorResponseSchema> | null {
  try {
    const parsed = OAuthErrorResponseSchema.safeParse(JSON.parse(errorText));
    return parsed.success ? parsed.data : null;
  } catch {
    // Some OAuth endpoints or intermediaries can return plain-text errors.
    return null;
  }
}

export function extractOAuthErrorCode(errorText: string): string | null {
  const parsed = parseOAuthErrorResponse(errorText);
  if (parsed?.error) {
    return parsed.error.trim().toLowerCase();
  }

  const text = errorText.toLowerCase();
  for (const code of OAUTH_CLIENT_ERROR_CODES) {
    if (text.includes(code)) {
      return code;
    }
  }

  return null;
}

function extractOAuthErrorDescription(errorText: string): string | undefined {
  const parsed = parseOAuthErrorResponse(errorText);
  if (parsed?.error_description) {
    const normalized = Array.from(parsed.error_description, (character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint <= 0x1f || codePoint === 0x7f ? ' ' : character;
    })
      .join('')
      .trim();
    return normalized === '' ? undefined : normalized.slice(0, 200);
  }
  return undefined;
}

export class OAuthTokenRefreshError extends Error {
  constructor(
    readonly code: string | null,
    readonly status: number,
    readonly clientKey: string,
    readonly description?: string,
  ) {
    super(`Token refresh failed for OAuth client [${clientKey}]: ${code ?? `HTTP ${status}`}`);
    this.name = 'OAuthTokenRefreshError';
  }
}

export function isClientMismatchError(errorText: string): boolean {
  const errorCode = extractOAuthErrorCode(errorText);
  return errorCode !== null && OAUTH_CLIENT_ERROR_CODES.has(errorCode);
}

/**
 * Creates an AbortSignal that times out after the specified duration.
 */
function createTimeoutSignal(ms: number, externalSignal?: AbortSignal): AbortSignal {
  const timeoutSignal = AbortSignal.timeout(ms);
  return externalSignal ? AbortSignal.any([timeoutSignal, externalSignal]) : timeoutSignal;
}

function waitForAbortableDelay(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) {
    return Promise.reject(signal.reason ?? new DOMException('Aborted', 'AbortError'));
  }

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      signal?.removeEventListener('abort', handleAbort);
      resolve();
    }, ms);
    const handleAbort = () => {
      clearTimeout(timeout);
      reject(signal?.reason ?? new DOMException('Aborted', 'AbortError'));
    };
    signal?.addEventListener('abort', handleAbort, { once: true });
  });
}

// --- Types ---

const TokenResponseSchema = z.object({
  access_token: z.string().min(1),
  expires_in: z.number(),
  token_type: z.string().min(1),
  refresh_token: z.string().optional(),
  id_token: z.string().optional(),
  scope: z.string().optional(),
  oauth_client_key: z.string().optional(),
});

export type TokenResponse = z.infer<typeof TokenResponseSchema>;

export type { OAuthClientDescriptor };

export interface UserInfo {
  id: string;
  email: string;
  verified_email: boolean;
  name: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
}

export class GoogleUserInfoHttpError extends Error {
  constructor(readonly status: number) {
    super(`Failed to fetch user info: HTTP ${status}`);
    this.name = 'GoogleUserInfoHttpError';
  }
}

export const UserInfoSchema = z.object({
  id: z.string(),
  email: z.string(),
  verified_email: z.boolean().optional().default(false),
  name: z.string().optional(),
  given_name: z.string().optional(),
  family_name: z.string().optional(),
  picture: z.string().optional(),
});

export interface QuotaData {
  models: Record<string, ModelQuotaInfo>;
  model_forwarding_rules?: Record<string, string>;
  subscription_tier?: string;
  is_forbidden?: boolean;
  ai_credits?: { credits: number; expiryDate: string };
  quota_groups?: QuotaGroup[];
}

export interface ModelQuotaInfo {
  percentage: number;
  resetTime: string;
  display_name?: string;
  supports_images?: boolean;
  supports_thinking?: boolean;
  thinking_budget?: number;
  recommended?: boolean;
  max_tokens?: number;
  max_output_tokens?: number;
  supported_mime_types?: Record<string, boolean>;
}

export interface QuotaBucket {
  bucket_id: string;
  window: string;
  remaining_fraction: number;
  reset_time: string;
  display_name?: string;
  description?: string;
}

export interface QuotaGroup {
  display_name: string;
  description?: string;
  buckets: QuotaBucket[];
}

// Internal schemas define the trust boundary for Google API responses.
const AvailableCreditRawSchema = z.object({
  creditType: z.string().optional(),
  creditAmount: z.union([z.string(), z.number()]).optional(),
  minimumCreditAmountForUsage: z.union([z.string(), z.number()]).optional(),
});

const TierRawSchema = z.object({
  is_default: z.boolean().optional(),
  id: z.string().optional(),
  quotaTier: z.string().optional(),
  name: z.string().optional(),
  slug: z.string().optional(),
  availableCredits: z.array(AvailableCreditRawSchema).optional(),
});

const LoadProjectResponseSchema = z.object({
  cloudaicompanionProject: z.string().optional(),
  currentTier: TierRawSchema.optional(),
  paidTier: TierRawSchema.optional(),
  allowedTiers: z.array(TierRawSchema).optional(),
  ineligibleTiers: z.array(z.object({ reasonCode: z.string().optional() })).optional(),
});

const ModelInfoRawSchema = z.object({
  quotaInfo: z
    .object({
      remainingFraction: z.number().optional(),
      resetTime: z.string().optional(),
    })
    .optional(),
  displayName: z.string().optional(),
  supportsImages: z.boolean().optional(),
  supportsThinking: z.boolean().optional(),
  thinkingBudget: z.number().optional(),
  recommended: z.boolean().optional(),
  maxTokens: z.number().optional(),
  maxOutputTokens: z.number().optional(),
  supportedMimeTypes: z.record(z.string(), z.boolean()).optional(),
});

const FetchModelsResponseSchema = z.object({
  models: z.record(z.string(), ModelInfoRawSchema).optional(),
  deprecatedModelIds: z
    .record(z.string(), z.object({ newModelId: z.string().optional() }))
    .optional(),
});

const QuotaSummaryResponseSchema = z.object({
  groups: z
    .array(
      z.object({
        displayName: z.string().optional(),
        description: z.string().optional(),
        buckets: z
          .array(
            z.object({
              bucketId: z.string().optional(),
              window: z.string().optional(),
              remainingFraction: z.number().optional(),
              resetTime: z.string().optional(),
              displayName: z.string().optional(),
              description: z.string().optional(),
            }),
          )
          .optional(),
      }),
    )
    .optional(),
});

type ModelInfoRaw = z.infer<typeof ModelInfoRawSchema>;
type LoadProjectResponse = z.infer<typeof LoadProjectResponseSchema>;
type FetchModelsResponse = z.infer<typeof FetchModelsResponseSchema>;
type QuotaSummaryResponse = z.infer<typeof QuotaSummaryResponseSchema>;

interface ProjectContext {
  projectId?: string;
  subscriptionTier?: string;
}

function parseTokenResponse(payload: unknown, oauthClientKey: string): TokenResponse {
  const parsed = TokenResponseSchema.safeParse(payload);
  if (!parsed.success) {
    throw new Error('Received malformed OAuth token response from Google APIs');
  }

  return {
    ...parsed.data,
    oauth_client_key: oauthClientKey,
  };
}

function parseLoadProjectResponse(payload: unknown): LoadProjectResponse {
  const parsed = LoadProjectResponseSchema.safeParse(payload);
  if (!parsed.success) {
    throw new Error('Received malformed project context response from Google APIs');
  }
  return parsed.data;
}

function parseFetchModelsResponse(payload: unknown): FetchModelsResponse {
  const parsed = FetchModelsResponseSchema.safeParse(payload);
  if (!parsed.success) {
    throw new Error('Received malformed quota response from Google APIs');
  }
  return parsed.data;
}

function parseQuotaSummaryResponse(payload: unknown): QuotaSummaryResponse {
  const parsed = QuotaSummaryResponseSchema.safeParse(payload);
  if (!parsed.success) {
    throw new Error('Received malformed quota summary response from Google APIs');
  }
  return parsed.data;
}

function isHttp429Error(error: unknown): boolean {
  return error instanceof Error && error.message.startsWith('HTTP 429');
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function buildInternalApiHeaders(accessToken: string): Record<string, string> {
  const discoveryVersion = resolveLocalInstalledVersion() ?? FALLBACK_VERSION;
  return {
    Authorization: `Bearer ${accessToken}`,
    'User-Agent': buildUserAgent(discoveryVersion),
    'Content-Type': 'application/json',
  };
}

function resolveSubscriptionTier(payload: LoadProjectResponse): string | undefined {
  const paidTier = payload.paidTier;
  if (isString(paidTier?.name) && !isEmpty(paidTier.name.trim())) {
    return paidTier.name;
  }
  if (isString(paidTier?.id) && !isEmpty(paidTier.id.trim())) {
    return paidTier.id;
  }

  const ineligible = Array.isArray(payload.ineligibleTiers) && payload.ineligibleTiers.length > 0;
  if (!ineligible) {
    const currentTier = payload.currentTier;
    if (isString(currentTier?.name) && !isEmpty(currentTier.name.trim())) {
      return currentTier.name;
    }
    if (isString(currentTier?.id) && !isEmpty(currentTier.id.trim())) {
      return currentTier.id;
    }
  }

  if (Array.isArray(payload.allowedTiers)) {
    const preferredAllowedTier =
      payload.allowedTiers.find((tier) => tier.is_default === true) ?? payload.allowedTiers[0];
    if (isString(preferredAllowedTier?.name) && !isEmpty(preferredAllowedTier.name.trim())) {
      return ineligible ? `${preferredAllowedTier.name} (Restricted)` : preferredAllowedTier.name;
    }
    if (isString(preferredAllowedTier?.id) && !isEmpty(preferredAllowedTier.id.trim())) {
      return ineligible ? `${preferredAllowedTier.id} (Restricted)` : preferredAllowedTier.id;
    }
  }

  return undefined;
}

function isTrackedModel(modelName: string): boolean {
  return /^(gemini|claude|gpt|image|imagen)/i.test(modelName);
}

function toModelQuotaInfo(modelName: string, info: ModelInfoRaw): ModelQuotaInfo | null {
  if (!isTrackedModel(modelName) || !info.quotaInfo) {
    return null;
  }

  const fraction = info.quotaInfo.remainingFraction ?? 0;
  return {
    percentage: Math.floor(fraction * 100),
    resetTime: info.quotaInfo.resetTime || '',
    display_name: info.displayName,
    supports_images: info.supportsImages,
    supports_thinking: info.supportsThinking,
    thinking_budget: info.thinkingBudget,
    recommended: info.recommended,
    max_tokens: info.maxTokens,
    max_output_tokens: info.maxOutputTokens,
    supported_mime_types: info.supportedMimeTypes,
  };
}

function toModelForwardingRules(
  deprecatedModelIds: FetchModelsResponse['deprecatedModelIds'],
): Record<string, string> | undefined {
  if (!deprecatedModelIds || Object.keys(deprecatedModelIds).length === 0) {
    return undefined;
  }

  const forwardingRules: Record<string, string> = {};
  for (const [oldModelId, deprecatedInfo] of Object.entries(deprecatedModelIds)) {
    if (isString(deprecatedInfo.newModelId) && deprecatedInfo.newModelId !== '') {
      forwardingRules[oldModelId] = deprecatedInfo.newModelId;
    }
  }

  return Object.keys(forwardingRules).length > 0 ? forwardingRules : undefined;
}

function toQuotaGroups(data: QuotaSummaryResponse): QuotaGroup[] | undefined {
  if (!Array.isArray(data.groups) || data.groups.length === 0) {
    return undefined;
  }

  const groups = data.groups.map((group) => ({
    display_name: group.displayName || '',
    description: group.description,
    buckets: Array.isArray(group.buckets)
      ? group.buckets.map((bucket) => ({
          bucket_id: bucket.bucketId || '',
          window: bucket.window || '',
          remaining_fraction: bucket.remainingFraction ?? 0,
          reset_time: bucket.resetTime || '',
          display_name: bucket.displayName,
          description: bucket.description,
        }))
      : [],
  }));

  return groups;
}

function parseCreditAmount(value: string | number | undefined): number {
  if (isNumber(value)) {
    return value;
  }

  if (isString(value)) {
    const parsed = Number.parseInt(value, 10);
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }

  return 0;
}

function toAiCredits(
  payload: Partial<{
    credits: unknown;
    remainingCredits: unknown;
    expiryDate: unknown;
    expirationDate: unknown;
  }>,
): { credits: number; expiryDate: string } | null {
  const creditsValue =
    isNumber(payload.credits) || isString(payload.credits)
      ? payload.credits
      : isNumber(payload.remainingCredits) || isString(payload.remainingCredits)
        ? payload.remainingCredits
        : undefined;

  if (isUndefined(creditsValue)) {
    return null;
  }

  const expiryDate = isString(payload.expiryDate)
    ? payload.expiryDate
    : isString(payload.expirationDate)
      ? payload.expirationDate
      : '';

  return {
    credits: parseCreditAmount(creditsValue),
    expiryDate,
  };
}

function extractAiCreditsFromProjectContext(
  payload: LoadProjectResponse,
): { credits: number; expiryDate: string } | null {
  const availableCredit = payload.paidTier?.availableCredits?.[0];
  if (!availableCredit) {
    return null;
  }

  return {
    credits: parseCreditAmount(availableCredit.creditAmount),
    expiryDate: '',
  };
}

// --- Service Implementation ---

export class GoogleAPIService {
  static listOAuthClients(): OAuthClientDescriptor[] {
    return OAuthClientRegistryService.listOAuthClients();
  }

  static getActiveOAuthClientKey(): string {
    return OAuthClientRegistryService.getActiveOAuthClientKey();
  }

  static setActiveOAuthClientKey(clientKey: string): void {
    OAuthClientRegistryService.setActiveOAuthClientKey(clientKey);
  }

  static normalizeRefreshedOAuthClientKey(
    currentToken: { oauth_client_key?: string; project_id?: string },
    refreshedClientKey?: string,
  ): string | undefined {
    return OAuthClientRegistryService.normalizeRefreshedOAuthClientKey(
      currentToken,
      refreshedClientKey,
    );
  }

  private static getFetchOptions(proxyUrl?: string) {
    const proxyTraceEnabled = process.env.DEBUG_PROXY_TRACE === '1';

    if (proxyUrl && proxyUrl.length > 0) {
      if (proxyTraceEnabled) {
        logger.info('[GoogleAPIService] Proxy source: account proxy_url');
      }
      return {
        dispatcher: new ProxyAgent(proxyUrl),
      };
    }
    try {
      const config = ConfigManager.loadConfig();
      if (config.proxy?.upstream_proxy?.enabled) {
        if (!config.proxy.upstream_proxy.url) {
          throw new Error('Upstream proxy is enabled but URL is not configured');
        }
        if (proxyTraceEnabled) {
          logger.info('[GoogleAPIService] Proxy source: config.proxy.upstream_proxy.url');
        }
        return {
          dispatcher: new ProxyAgent(config.proxy.upstream_proxy.url),
        };
      }
    } catch (e) {
      logger.error('[GoogleAPIService] Proxy configuration error', e);
      throw e;
    }

    const httpProxy = process.env.http_proxy?.trim() || process.env.HTTP_PROXY?.trim();
    const httpsProxy = process.env.https_proxy?.trim() || process.env.HTTPS_PROXY?.trim();
    const noProxy = process.env.no_proxy?.trim() || process.env.NO_PROXY?.trim();
    const electronProxyServer = process.env.ELECTRON_PROXY_SERVER?.trim();

    if (httpProxy || httpsProxy) {
      if (proxyTraceEnabled) {
        logger.info(
          `[GoogleAPIService] Proxy source: HTTP(S)_PROXY env (http: ${httpProxy ?? 'none'}, https: ${httpsProxy ?? 'none'})`,
        );
      }
      return {
        dispatcher: new EnvHttpProxyAgent({
          httpProxy,
          httpsProxy,
          noProxy,
        }),
      };
    }

    if (electronProxyServer) {
      if (proxyTraceEnabled) {
        logger.info(
          `[GoogleAPIService] Proxy source: ELECTRON_PROXY_SERVER env (${electronProxyServer})`,
        );
      }
      return {
        dispatcher: new ProxyAgent(electronProxyServer),
      };
    }

    if (proxyTraceEnabled) {
      logger.info('[GoogleAPIService] Proxy source: none');
    }

    return {};
  }

  /**
   * Generates the OAuth2 authorization URL.
   */
  static getAuthUrl(oauthClientKey?: string): string {
    const oauthClient = OAuthClientRegistryService.selectAuthClient(oauthClientKey);
    const redirectUri = AuthServer.getRedirectUri();

    const params = new URLSearchParams({
      access_type: 'offline',
      scope: GOOGLE_OAUTH_SCOPE,
      prompt: 'consent',
      response_type: 'code',
      client_id: oauthClient.client_id,
      redirect_uri: redirectUri,
      include_granted_scopes: 'true',
      state: v4(),
    });

    return `${URLS.AUTH}?${params.toString()}`;
  }

  /**
   * Exchanges an authorization code for tokens.
   */
  static async exchangeCode(
    code: string,
    proxyUrl?: string,
    preferredClientKey?: string,
  ): Promise<TokenResponse> {
    const redirectUri = AuthServer.getRedirectUri();
    const candidates = OAuthClientRegistryService.getCandidateClients(preferredClientKey);
    if (candidates.length === 0) {
      throw new Error('No OAuth clients configured');
    }

    const attemptErrors: string[] = [];

    for (const client of candidates) {
      const params = new URLSearchParams({
        client_id: client.client_id,
        client_secret: client.client_secret,
        code,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      });

      logger.info(
        `[GoogleAPIService] Attempting token exchange with client=${client.key}, endpoint=${URLS.TOKEN}`,
      );
      const fetchOpts = this.getFetchOptions(proxyUrl);
      logger.info(
        `[GoogleAPIService] Fetch options: ${JSON.stringify(fetchOpts ? { hasDispatcher: !!fetchOpts.dispatcher } : {})}`,
      );

      const response = await fetch(URLS.TOKEN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params,
        signal: createTimeoutSignal(REQUEST_TIMEOUT_MS),
        ...fetchOpts,
      }).catch((err: unknown) => {
        logger.error(`[GoogleAPIService] Fetch error for client=${client.key}:`, err);
        if (err instanceof Error && err.name === 'AbortError') {
          throw new Error(
            'Token exchange timed out. Please check your network connection and try again.',
          );
        }
        throw err;
      });

      logger.info(
        `[GoogleAPIService] Fetch response received for client=${client.key}: ok=${response.ok}, status=${response.status}`,
      );

      if (response.ok) {
        return parseTokenResponse(await response.json(), client.key);
      }

      const text = await response.text();
      attemptErrors.push(`${client.key} => ${text}`);
      if (isClientMismatchError(text)) {
        logger.warn(
          `[GoogleAPIService] Token exchange failed for OAuth client '${client.key}', trying next client`,
        );
        continue;
      }

      throw new Error(`Token exchange failed for client [${client.key}]: ${text}`);
    }

    throw new Error(`Token exchange failed for all OAuth clients: ${attemptErrors.join(' | ')}`);
  }

  /**
   * Refreshes an access token using a refresh token.
   */
  static async refreshAccessToken(
    refreshToken: string,
    proxyUrl?: string,
    preferredClientKey?: string,
    requestSignal?: AbortSignal,
  ): Promise<TokenResponse> {
    const candidates = OAuthClientRegistryService.getCandidateClients(preferredClientKey);
    if (candidates.length === 0) {
      throw new Error('No OAuth clients configured');
    }

    const attemptErrors: string[] = [];

    for (const client of candidates) {
      const params = new URLSearchParams({
        client_id: client.client_id,
        client_secret: client.client_secret,
        refresh_token: refreshToken,
        grant_type: 'refresh_token',
      });

      for (let attempt = 0; attempt < 2; attempt += 1) {
        const response = await fetch(URLS.TOKEN, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: params,
          signal: createTimeoutSignal(REQUEST_TIMEOUT_MS, requestSignal),
          ...this.getFetchOptions(proxyUrl),
        }).catch((err: unknown) => {
          if (err instanceof Error && err.name === 'AbortError') {
            throw new Error(
              'Token refresh timed out. Please check your network connection and try again.',
            );
          }
          throw err;
        });

        if (response.ok) {
          return parseTokenResponse(await response.json(), client.key);
        }

        const text = await response.text();
        const errorCode = extractOAuthErrorCode(text);
        attemptErrors.push(`${client.key} => ${errorCode ?? `HTTP ${response.status}`}`);
        if (errorCode === 'invalid_grant' && attempt === 0) {
          await waitForAbortableDelay(INVALID_GRANT_RETRY_DELAY_MS, requestSignal);
          continue;
        }
        if (isClientMismatchError(text)) {
          logger.warn(
            `[GoogleAPIService] Token refresh failed for OAuth client '${client.key}', trying next client`,
          );
          break;
        }

        throw new OAuthTokenRefreshError(
          errorCode,
          response.status,
          client.key,
          extractOAuthErrorDescription(text),
        );
      }
    }

    throw new Error(`Token refresh failed for all OAuth clients: ${attemptErrors.join(' | ')}`);
  }

  /**
   * Fetches user profile information.
   */
  static async getUserInfo(
    accessToken: string,
    proxyUrl?: string,
    requestSignal?: AbortSignal,
  ): Promise<UserInfo> {
    const response = await fetch(URLS.USER_INFO, {
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: createTimeoutSignal(REQUEST_TIMEOUT_MS, requestSignal),
      ...this.getFetchOptions(proxyUrl),
    }).catch((err: unknown) => {
      if (err instanceof Error) {
        if (err.name === 'AbortError') {
          throw new Error(
            'User info request timed out. Please check your network connection and try again.',
          );
        }
      }
      throw err;
    });

    if (!response.ok) {
      throw new GoogleUserInfoHttpError(response.status);
    }

    const data = await response.json();
    try {
      const parsed = UserInfoSchema.parse(data);

      return {
        ...parsed,
        // Google may omit profile claims such as family_name for accounts with limited profile data.
        name: parsed.name ?? parsed.email,
      };
    } catch (err) {
      logger.error('[GoogleAPIService] Malformed user info response:', err);
      throw new Error('Received malformed user info from Google APIs');
    }
  }

  public static async fetchProjectContext(
    accessToken: string,
    proxyUrl?: string,
  ): Promise<ProjectContext> {
    const body = {
      metadata: { ideType: 'ANTIGRAVITY' },
    };

    let projectId: string | undefined;
    let subscriptionTier: string | undefined;
    let lastError: unknown;
    const endpoints = [URLS.LOAD_PROJECT, URLS.SANDBOX_LOAD_PROJECT];

    for (const endpoint of endpoints) {
      try {
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: buildInternalApiHeaders(accessToken),
          body: JSON.stringify(body),
          signal: createTimeoutSignal(REQUEST_TIMEOUT_MS),
          ...this.getFetchOptions(proxyUrl),
        });

        if (response.ok) {
          const data = parseLoadProjectResponse(await response.json());
          if (isString(data.cloudaicompanionProject)) {
            projectId = data.cloudaicompanionProject;
          }
          subscriptionTier = resolveSubscriptionTier(data);
          break;
        } else {
          lastError = new Error(`HTTP ${response.status}: ${await response.text()}`);
          if (endpoint === URLS.LOAD_PROJECT && response.status === 429) {
            logger.warn(
              '[GoogleAPIService] Prod loadCodeAssist returned 429, falling back to sandbox endpoint',
            );
            continue;
          }
        }
      } catch (error) {
        lastError = error;
        logger.warn(`[GoogleAPIService] Failed to fetch project ID from ${endpoint} `, error);
        await sleep(500);
      }

      if (projectId || subscriptionTier) {
        break;
      }

      if (endpoint !== URLS.LOAD_PROJECT || !isHttp429Error(lastError)) {
        break;
      }
    }

    if (!projectId && !subscriptionTier) {
      throw lastError || new Error('Failed to fetch project context after multiple attempts.');
    }

    return {
      projectId,
      subscriptionTier,
    };
  }

  public static async fetchProjectId(
    accessToken: string,
    proxyUrl?: string,
  ): Promise<string | null> {
    const context = await this.fetchProjectContext(accessToken, proxyUrl);
    return context.projectId ?? null;
  }

  static async fetchAICredits(
    accessToken: string,
    proxyUrl?: string,
  ): Promise<{ credits: number; expiryDate: string } | null> {
    try {
      const fetchOptions = this.getFetchOptions(proxyUrl);
      const discoveryVersion = resolveLocalInstalledVersion() ?? FALLBACK_VERSION;
      const fallbackResponse = await fetch(URLS.DAILY_LOAD_PROJECT, {
        method: 'POST',
        headers: buildInternalApiHeaders(accessToken),
        body: JSON.stringify({
          metadata: {
            ide_type: 'ANTIGRAVITY',
            ide_version: discoveryVersion,
            ide_name: 'antigravity',
          },
        }),
        signal: createTimeoutSignal(REQUEST_TIMEOUT_MS),
        ...fetchOptions,
      });

      if (!fallbackResponse.ok) {
        if (fallbackResponse.status === 401) {
          throw new Error('UNAUTHORIZED');
        }
        return null;
      }

      const fallbackData = parseLoadProjectResponse(await fallbackResponse.json());
      return extractAiCreditsFromProjectContext(fallbackData);
    } catch (error) {
      if (error instanceof Error && error.message === 'UNAUTHORIZED') {
        throw error;
      }
      return null;
    }
  }

  private static toQuotaData(
    data: FetchModelsResponse,
    subscriptionTier: string | undefined,
  ): QuotaData {
    const result: QuotaData = {
      models: {},
      subscription_tier: subscriptionTier,
      is_forbidden: false,
    };

    for (const [modelName, modelInfoRaw] of Object.entries(data.models || {})) {
      const modelQuota = toModelQuotaInfo(modelName, modelInfoRaw);
      if (modelQuota) {
        result.models[modelName] = modelQuota;
      }
    }

    const modelForwardingRules = toModelForwardingRules(data.deprecatedModelIds);
    if (modelForwardingRules) {
      result.model_forwarding_rules = modelForwardingRules;
    }

    return result;
  }

  private static shouldFallbackQuotaEndpoint(status: number): boolean {
    return status === 429 || status >= 500;
  }

  private static isPermanentQuotaHttp4xx(errorMsg: string): boolean {
    return /^HTTP 4\d{2}\b/.test(errorMsg) && !errorMsg.startsWith('HTTP 429');
  }

  /**
   * Core logic: Fetches detailed model quota information.
   */
  static async fetchQuota(accessToken: string, proxyUrl?: string): Promise<QuotaData> {
    let projectContext: ProjectContext = {};
    try {
      projectContext = await this.fetchProjectContext(accessToken, proxyUrl);
    } catch (error) {
      logger.warn(
        '[GoogleAPIService] Project context unavailable; continuing quota lookup without project',
        error instanceof Error ? error.message : String(error),
      );
    }

    const { projectId, subscriptionTier } = projectContext;

    const payload: Record<string, unknown> = projectId ? { project: projectId } : {};
    let lastError: Error | null = null;
    const fetchOptions = this.getFetchOptions(proxyUrl);

    for (let endpointIndex = 0; endpointIndex < QUOTA_API_ENDPOINTS.length; endpointIndex++) {
      const endpoint = QUOTA_API_ENDPOINTS[endpointIndex];
      const hasNextEndpoint = endpointIndex + 1 < QUOTA_API_ENDPOINTS.length;
      let currentPayload = { ...payload };
      let retriedWithoutProject = false;

      while (true) {
        try {
          const response = await fetch(endpoint, {
            method: 'POST',
            headers: buildInternalApiHeaders(accessToken),
            body: JSON.stringify(currentPayload),
            signal: createTimeoutSignal(REQUEST_TIMEOUT_MS),
            ...fetchOptions,
          });

          if (!response.ok) {
            const status = response.status;

            if (status === 403) {
              if ('project' in currentPayload && !retriedWithoutProject) {
                logger.warn(
                  '[GoogleAPIService] Quota API returned 403 with project ID, retrying without project ID',
                );
                currentPayload = {};
                retriedWithoutProject = true;
                continue;
              }

              throw new Error('FORBIDDEN');
            }
            if (status === 401) {
              throw new Error('UNAUTHORIZED');
            }

            const text = await response.text();
            const errorMsg = `HTTP ${status} - ${text}`;
            if (hasNextEndpoint && this.shouldFallbackQuotaEndpoint(status)) {
              logger.warn(
                `[GoogleAPIService] Quota API ${endpoint} returned ${status}, falling back to next endpoint`,
              );
              lastError = new Error(errorMsg);

              await sleep(1000);
              break;
            }

            throw new Error(errorMsg);
          }

          const data = parseFetchModelsResponse(await response.json());
          const result = this.toQuotaData(data, subscriptionTier);
          const quotaGroups = await this.fetchQuotaSummary(accessToken, projectId, fetchOptions);
          if (quotaGroups) {
            result.quota_groups = quotaGroups;
          }

          if (endpointIndex > 0) {
            logger.info(
              `[GoogleAPIService] Quota API fallback succeeded at endpoint #${endpointIndex + 1}`,
            );
          }

          return result;
        } catch (error: unknown) {
          const errorMsg = error instanceof Error ? error.message : String(error);
          lastError = error instanceof Error ? error : new Error(String(error));

          // Abort retries for auth errors
          if (errorMsg === 'FORBIDDEN' || errorMsg === 'UNAUTHORIZED') {
            throw error;
          }

          if (hasNextEndpoint && !this.isPermanentQuotaHttp4xx(errorMsg)) {
            logger.warn(
              `[GoogleAPIService] Quota API request failed at ${endpoint}: ${errorMsg}. Falling back to next endpoint`,
            );
            await sleep(1000);
            break;
          }

          throw lastError;
        }
      }
    }

    throw lastError || new Error('Quota check failed');
  }

  private static async fetchQuotaSummary(
    accessToken: string,
    projectId: string | undefined,
    fetchOptions: ReturnType<typeof GoogleAPIService.getFetchOptions>,
  ): Promise<QuotaGroup[] | undefined> {
    const payload: Record<string, unknown> = projectId ? { project: projectId } : {};

    for (const endpoint of QUOTA_SUMMARY_ENDPOINTS) {
      let currentPayload = { ...payload };
      let retriedWithoutProject = false;

      while (true) {
        try {
          const response = await fetch(endpoint, {
            method: 'POST',
            headers: buildInternalApiHeaders(accessToken),
            body: JSON.stringify(currentPayload),
            signal: createTimeoutSignal(REQUEST_TIMEOUT_MS),
            ...fetchOptions,
          });

          if (!response.ok) {
            logger.warn(
              `[GoogleAPIService] Quota summary API ${endpoint} returned ${response.status}`,
            );
            if (response.status === 403 && 'project' in currentPayload && !retriedWithoutProject) {
              logger.warn(
                '[GoogleAPIService] Quota summary returned 403 with project ID, retrying without project ID',
              );
              currentPayload = {};
              retriedWithoutProject = true;
              continue;
            }
            if (response.status >= 400 && response.status < 500 && response.status !== 429) {
              return undefined;
            }
            break;
          }

          return toQuotaGroups(parseQuotaSummaryResponse(await response.json()));
        } catch (error) {
          logger.warn(`[GoogleAPIService] Quota summary API request failed at ${endpoint}`, error);
          break;
        }
      }
    }

    return undefined;
  }
}
