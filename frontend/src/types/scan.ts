export type ResourceType = 'ec2' | 'iam' | 's3' | 'lambda';

export interface ScanResult {
  resource: ResourceType;
  data?: any;
  error?: string;
  status: 'success' | 'error';
}

export interface ResourceToggle {
  id: ResourceType;
  label: string;
  enabled: boolean;
}
