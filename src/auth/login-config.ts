import { CliError } from "../core/errors.js";
import { ApiClient, decodeData } from "../http/client.js";
import { ApiError } from "../http/errors.js";

export interface LoginConfig {
  clientId: string;
  requestId: string;
}

interface LoginConfigResponse {
  client_id?: unknown;
  authorization_endpoint?: unknown;
  token_endpoint?: unknown;
  revocation_endpoint?: unknown;
  scopes?: unknown;
  code_challenge_method?: unknown;
  redirect_uri_pattern?: unknown;
}

export async function discoverLoginConfig(client: ApiClient): Promise<LoginConfig> {
  let response: Awaited<ReturnType<ApiClient["do"]>>;
  try {
    response = await client.do({
      method: "GET",
      path: "/api/v3/agent-identity/auth/config"
    });
  } catch (error) {
    if (error instanceof ApiError) {
      throw new CliError({
        code: error.code === "AGENT_CLI_LOGIN_NOT_CONFIGURED"
          ? error.code
          : "LOGIN_CONFIGURATION_UNAVAILABLE",
        message: error.message,
        requestId: error.requestId,
        exitCode: 7,
        retryable: error.status === 429 || error.status >= 500,
        cause: error
      });
    }
    throw new CliError({
      code: "LOGIN_CONFIGURATION_UNAVAILABLE",
      message: "GenAuth login configuration is unavailable",
      exitCode: 7,
      retryable: true,
      cause: error
    });
  }

  const data = decodeData<LoginConfigResponse>(response.data);
  const clientId = text(data.client_id);
  const scopes = Array.isArray(data.scopes) ? data.scopes.map(text) : [];
  const valid =
    /^[A-Za-z0-9._~-]{1,256}$/u.test(clientId) &&
    text(data.authorization_endpoint) === "/oidc/auth" &&
    text(data.token_endpoint) === "/oidc/token" &&
    text(data.revocation_endpoint) === "/oidc/token/revocation" &&
    text(data.code_challenge_method) === "S256" &&
    text(data.redirect_uri_pattern) === "http://127.0.0.1:*/callback" &&
    scopes.includes("openid") &&
    scopes.includes("offline_access");
  if (!valid) {
    throw new CliError({
      code: "LOGIN_CONFIGURATION_INVALID",
      message: "GenAuth returned an incompatible Agent CLI login configuration",
      requestId: response.requestId,
      exitCode: 7
    });
  }
  return { clientId, requestId: response.requestId };
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}
