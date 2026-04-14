export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export interface FindingView {
  id: string;
  title: string;
  severity: FindingSeverity;
  description: string;
  remediation?: string;
  resourceType?: string;
  cisControl?: string;
  owasp?: string;
}

function normalizeSeverity(value: unknown): FindingSeverity {
  if (typeof value !== 'string') return 'UNKNOWN';

  const normalized = value.toUpperCase();
  if (
    normalized === 'CRITICAL' ||
    normalized === 'HIGH' ||
    normalized === 'MEDIUM' ||
    normalized === 'LOW'
  ) {
    return normalized;
  }

  return 'UNKNOWN';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

export function extractFindings(data: unknown): FindingView[] {
  if (!isRecord(data)) return [];

  let rawFindings: unknown[] = [];

  if (Array.isArray(data.findings)) {
    rawFindings = data.findings;
  } else if (
    isRecord(data.nodes) &&
    Array.isArray((data.nodes as Record<string, unknown>).Finding)
  ) {
    rawFindings = (data.nodes as Record<string, unknown>).Finding as unknown[];
  }

  return rawFindings
    .filter(isRecord)
    .map((finding, index) => {
      const type = typeof finding.type === 'string' ? finding.type : `Finding ${index + 1}`;
      const severity = normalizeSeverity(finding.severity);
      const description =
        typeof finding.description === 'string' && finding.description.trim()
          ? finding.description
          : 'No description provided.';
      const remediation =
        typeof finding.remediation === 'string' && finding.remediation.trim()
          ? finding.remediation
          : undefined;
      const resourceType =
        typeof finding.resource_type === 'string' ? finding.resource_type : undefined;
      const cisControl =
        typeof finding.cis_control === 'string' ? finding.cis_control : undefined;
      const owasp = typeof finding.owasp === 'string' ? finding.owasp : undefined;
      const id =
        typeof finding.finding_id === 'string'
          ? finding.finding_id
          : `finding-${index + 1}`;

      return {
        id,
        title: type.replace(/_/g, ' '),
        severity,
        description,
        remediation,
        resourceType,
        cisControl,
        owasp,
      };
    });
}

export function countFindings(data: unknown): number {
  return extractFindings(data).length;
}
