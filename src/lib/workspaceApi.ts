import { authHeaders } from './auth';
const API=(import.meta.env.VITE_PHANTOM_API_URL??'http://localhost:8000').replace(/\/$/,'');
export async function getWorkspace(){const r=await fetch(`${API}/api/v1/workspaces/current`,{headers:authHeaders()});if(!r.ok)throw new Error(await r.text());return r.json();}
export async function getDashboardSummary(){const r=await fetch(`${API}/api/v1/dashboard/summary`,{headers:authHeaders()});if(!r.ok)throw new Error(await r.text());return r.json();}
export async function getMembers(){const r=await fetch(`${API}/api/v1/workspaces/current/members`,{headers:authHeaders()});if(!r.ok)throw new Error(await r.text());return r.json();}
export async function addMember(email:string,name:string,role:string){const r=await fetch(`${API}/api/v1/workspaces/current/members`,{method:'POST',headers:{'Content-Type':'application/json',...authHeaders()},body:JSON.stringify({email,name,role})});if(!r.ok)throw new Error(await r.text());return r.json();}
