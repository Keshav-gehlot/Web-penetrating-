import { apiRequest } from './api';

export async function getWorkspace(){
  return apiRequest('/api/v1/workspaces/current');
}
export async function getDashboardSummary(){
  return apiRequest('/api/v1/dashboard/summary');
}
export async function getMembers(){
  return apiRequest('/api/v1/workspaces/current/members');
}
export async function addMember(email:string,name:string,role:string){
  return apiRequest('/api/v1/workspaces/current/members',{
    method:'POST',
    body:JSON.stringify({email,name,role}),
  });
}
