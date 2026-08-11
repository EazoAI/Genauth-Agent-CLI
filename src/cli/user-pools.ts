import { decodeData } from "../http/client.js";

export interface ManageableUserPool {
  id: string;
  name?: string;
  domain?: string;
  role?: string;
}

export function decodeManageableUserPools(value: unknown): ManageableUserPool[] {
  const data = decodeData<{ list?: Array<Record<string, unknown>> }>(value);
  return (data.list ?? []).flatMap(item => {
    const id = text(item.id);
    if (id === "") return [];
    const name = text(item.name);
    const domain = text(item.domain);
    const role = text(item.role);
    return [{
      id,
      ...(name === "" ? {} : { name }),
      ...(domain === "" ? {} : { domain }),
      ...(role === "" ? {} : { role })
    }];
  });
}

export function userPoolLabel(pool: ManageableUserPool): string {
  if (pool.name !== undefined && pool.domain !== undefined) {
    return `${pool.name} [${pool.domain}] (${pool.id})`;
  }
  const label = pool.name ?? pool.domain;
  return label === undefined ? pool.id : `${label} (${pool.id})`;
}

export function selectedUserPoolFields(
  userPoolId: string,
  pool: ManageableUserPool | undefined
): Record<string, string> {
  return {
    selected_user_pool_id: userPoolId,
    ...(pool?.name === undefined ? {} : { selected_user_pool_name: pool.name }),
    ...(pool?.domain === undefined ? {} : { selected_user_pool_domain: pool.domain })
  };
}

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}
