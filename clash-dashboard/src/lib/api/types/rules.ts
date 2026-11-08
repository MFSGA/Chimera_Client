export interface Rule {
  type: string;
  payload: string;
  proxy: string;
  size?: number;
}
export interface RuleProvider {
  name: string;
  type: string;
  vehicleType: string;
  updatedAt?: string;
  behavior?: string;
  format?: string;
  ruleCount?: number;
}
