export interface TrafficData {
  up: number;
  down: number;
  upTotal: number;
  downTotal: number;
}
export interface LogEntry {
  type: string;
  payload: string;
}
