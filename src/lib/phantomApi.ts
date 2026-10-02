import { apiRequest, apiUrl } from './api';

export type ScanProfile='quick'|'standard'|'deep'|'trust';
export type AssessmentCredential={id:string;name:string;kind:'basic'|'bearer'|'api_key';username?:string|null;header_name?:string|null};
export type Scan={id:string;target:string;host:string;profile:string;modules:string[];status:string;created_at:string|null;started_at:string|null;completed_at:string|null;error?:string|null;attempt?:number;worker_id?:string|null;lease_expires_at?:string|null;cancel_requested_at?:string|null;cancelled_at?:string|null;credential_id?:string|null};
export type FindingEvent={id:string;module:string;title:string;severity:string;confidence:number};
export type ScanEvent={event:'connected'|'scan.created'|'scan.started'|'scan.completed'|'scan.cancel_requested'|'scan.cancelled';scan_id:string;status?:string}|{event:'scan.failed';scan_id:string;error:string}|{event:'module.started'|'module.completed';scan_id:string;module:string;index:number;total:number;finding_count?:number}|{event:'finding.created';scan_id:string;finding:FindingEvent};

export function createScan(target:string,profile:ScanProfile='standard',credentialId?:string){
  return apiRequest<Scan>('/api/v1/scans',{method:'POST',body:JSON.stringify({target,profile,credential_id:credentialId||null})});
}
export function listAvailableCredentials(){
  return apiRequest<AssessmentCredential[]>('/api/v1/workspaces/current/credentials/available');
}
export function getScan(scanId:string){
  return apiRequest<Scan&{findings:FindingEvent[]}>(`/api/v1/scans/${encodeURIComponent(scanId)}`);
}
export function listScans(){
  return apiRequest<Scan[]>('/api/v1/scans');
}
export function cancelScan(scanId:string){
  return apiRequest<Scan>(`/api/v1/scans/${encodeURIComponent(scanId)}/cancel`,{method:'POST'});
}
export async function scanSocket(scanId:string):Promise<WebSocket>{
  const ticket=await apiRequest<{ticket:string}>(`/api/v1/events/ws-ticket?scan_id=${encodeURIComponent(scanId)}`,{method:'POST'});
  if(!ticket?.ticket) throw new Error('WebSocket ticket was not returned by the API.');
  const base=new URL(apiUrl('/'));
  base.protocol=base.protocol==='https:'?'wss:':'ws:';
  base.pathname=`/ws/scans/${encodeURIComponent(scanId)}`;
  base.search=`?ticket=${encodeURIComponent(ticket.ticket)}`;
  return new WebSocket(base.toString());
}
