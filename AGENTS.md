# GenAuth Agent Identity CLI Instructions

- The CLI may call only GenAuth public HTTPS endpoints. Do not add direct Agent
  Identity private service calls.
- Keep secrets and full access tokens out of profile files, logs, error output,
  and default JSON output. Use the operating-system keyring.
- Preserve stable JSON `kind`, `error.code`, `request_id`, remediation, warning,
  and exit-code behavior for Skills and automation.
- Administrator and member flows must remain bound to an explicitly selected
  user pool. Members cannot impersonate another user or request silent grants.
- Destructive and security-sensitive operations require explicit confirmation.
- Run `make verify` and `make test-race` before release.
