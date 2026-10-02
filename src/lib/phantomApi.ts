import { authHeaders } from './auth';
const API_BASE=(import.meta.env.VITE_PHANTOM_API_URL??(import.meta.env.PROD?'':'http://localhost:8000')).replace(/\/$/,'');
export type AssessmentCredential={id:string;name:string;kind:'basic'|'bearer'|'api_key'|'cookie';username?:string|null;header_name?:string|null;created_at:string|null;last_used_at:string|null};
export type ScanProfile='quick'|'standard'|'deep'|'trust';
export type Scan={id:string;target:string;host:string;profile:string;modules:string[];status:string;credential_id?:string|null;comparison_credential_id?:string|null;created_at:string|null;started_at:string|null;completed_at:string|null;error?:string|null;attempt?:number;worker_id?:string|null;lease_expires_at?:string|null;cancel_requested_at?:string|null;cancelled_at?:string|null};
export type FindingEvent={id:string;module:string;title:string;severity:string;confidence:number};
export type ScanEvent={event:'connected'|'scan.created'|'scan.started'|'scan.completed'|'scan.cancel_requested'|'scan.cancelled';scan_id:string;status?:string}|{event:'scan.failed'|'module.failed';scan_id:string;error:string;module?:string;index?:number;total?:number;status?:string}|{event:'module.started'|'module.completed';scan_id:string;module:string;index:number;total:number;finding_count?:number}|{event:'finding.created';scan_id:string;finding:FindingEvent};
async function request<T>(path:string,init?:RequestInit):Promise<T>{
 const response=await fetch(`${API_BASE}${path}`,{...init,headers:{'Content-Type':'application/json',...authHeaders(),...(init?.headers??{})}});
 const payload=await response.json().catch(()=>null) as {data?:T;error?:{message?:string}}|T|null;
 if(!response.ok){
   const error=payload && typeof payload==='object' && 'error' in payload ? (payload as {error?:{message?:string}}).error?.message : null;
   throw new Error(error || `PHANTOM API request failed (${response.status})`);
 }
 if(payload && typeof payload==='object' && 'data' in payload) return (payload as {data:T}).data;
 return payload as T;
}
export function listScans(){return request<Scan[]>('/api/v1/scans')}\nexport function createScan(target:string,profile:ScanProfile='standard',credentialId?:string,comparisonCredentialId?:string){return request<Scan>('/api/v1/scans',{method:'POST',body:JSON.stringify({target,profile,...(credentialId?{credential_id:credentialId}:{}),...(comparisonCredentialId?{comparison_credential_id:comparisonCredentialId}:{})})})}
export function getScan(scanId:string){return request<Scan&{findings:FindingEvent[]}>(`/api/v1/scans/${encodeURIComponent(scanId)}`)}
export function cancelScan(scanId:string){return request<Scan>(`/api/v1/scans/${encodeURIComponent(scanId)}/cancel`,{method:'POST'})}
export async function scanSocket(scanId:string):Promise<WebSocket>{const ticket=await request<{ticket:string}>(`/api/v1/events/ws-ticket?scan_id=${encodeURIComponent(scanId)}`,{method:'POST'});const base=new URL(API_BASE || window.location.origin);base.protocol=base.protocol==='https:'?'wss:':'ws:';base.pathname=`/ws/scans/${encodeURIComponent(scanId)}`;base.search=`?ticket=${encodeURIComponent(ticket.ticket)}`;return new WebSocket(base.toString())}
export function listCredentials(){return request<AssessmentCredential[]>('/api/v1/workspaces/current/credentials')}
export function createCredential(payload:{name:string;kind:'basic'|'bearer'|'api_key'|'cookie';username?:string;header_name?:string;secret:string}){return request<AssessmentCredential>('/api/v1/workspaces/current/credentials',{method:'POST',body:JSON.stringify(payload)})}
export function deleteCredential(id:string){return request<{deleted:boolean}>(`/api/v1/workspaces/current/credentials/${encodeURIComponent(id)}`,{method:'DELETE'})}
