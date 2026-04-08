export function countFindings(data: unknown): number {
  if (
    data &&
    typeof data === 'object' &&
    'nodes' in data &&
    data.nodes &&
    typeof data.nodes === 'object' &&
    'Finding' in data.nodes &&
    Array.isArray(data.nodes.Finding)
  ) {
    return data.nodes.Finding.length;
  }

  if (
    data &&
    typeof data === 'object' &&
    'findings' in data &&
    Array.isArray(data.findings)
  ) {
    return data.findings.length;
  }

  return 0;
}
