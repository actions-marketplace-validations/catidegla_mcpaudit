/**
 * OWASP MCP Top 10 (beta), the categories every rule maps to.
 *
 * https://owasp.org/www-project-mcp-top-10/
 *
 * Findings carry a category id so output can be grouped the way a security
 * team already thinks, and so the SARIF report says something more useful than
 * the name of whichever rule happened to fire.
 */

export const OWASP_MCP = {
  MCP01: {
    id: 'MCP01:2025',
    title: 'Token Mismanagement and Secret Exposure',
    summary: 'Hard-coded credentials, long-lived tokens, and secrets reachable through configuration or logs.',
  },
  MCP02: {
    id: 'MCP02:2025',
    title: 'Privilege Escalation via Scope Creep',
    summary: 'Loosely defined permissions that grant an agent more capability than the task needs.',
  },
  MCP03: {
    id: 'MCP03:2025',
    title: 'Tool Poisoning',
    summary: 'Instructions hidden in tool metadata that redirect the model, including descriptions that change after approval.',
  },
  MCP04: {
    id: 'MCP04:2025',
    title: 'Software Supply Chain Attacks and Dependency Tampering',
    summary: 'Unpinned or untrusted sources that can alter server behaviour between runs.',
  },
  MCP05: {
    id: 'MCP05:2025',
    title: 'Command Injection and Execution',
    summary: 'Tool arguments reaching a shell, an eval, or a filesystem path without validation.',
  },
  MCP06: {
    id: 'MCP06:2025',
    title: 'Intent Flow Subversion',
    summary: 'Context that steers the agent away from what the user actually asked for.',
  },
  MCP07: {
    id: 'MCP07:2025',
    title: 'Insufficient Authentication and Authorization',
    summary: 'Servers and transports that do not verify who is calling.',
  },
  MCP08: {
    id: 'MCP08:2025',
    title: 'Lack of Audit and Telemetry',
    summary: 'No record of which tools ran with which arguments, so incidents cannot be reconstructed.',
  },
  MCP09: {
    id: 'MCP09:2025',
    title: 'Shadow MCP Servers',
    summary: 'Servers running outside governance, often with default credentials and permissive settings.',
  },
  MCP10: {
    id: 'MCP10:2025',
    title: 'Context Injection and Over-Sharing',
    summary: 'Data from one task, user, or agent leaking into another through inadequately scoped context.',
  },
};

export function owasp(key) {
  const entry = OWASP_MCP[key];
  if (!entry) throw new Error(`Unknown OWASP MCP category: ${key}`);
  return entry;
}
