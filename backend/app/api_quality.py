from __future__ import annotations
import json,time
from collections import defaultdict,deque
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

def envelope(data,request_id:str):return {"data":data,"error":None,"request_id":request_id}
def api_error(code:str,message:str,request_id:str,details=None):
 out={"data":None,"error":{"code":code,"message":message},"request_id":request_id}
 if details is not None:out["error"]["details"]=details
 return out

class APIEnvelopeMiddleware(BaseHTTPMiddleware):
 async def dispatch(self,request:Request,call_next)->Response:
  response=await call_next(request)
  if not request.url.path.startswith("/api/v1/"):return response
  ctype=response.headers.get("content-type","")
  if "application/json" not in ctype:return response
  body=b""
  async for chunk in response.body_iterator:body+=chunk
  try:payload=json.loads(body)
  except Exception:return Response(body,status_code=response.status_code,headers=dict(response.headers),media_type=ctype)
  rid=getattr(request.state,"request_id",response.headers.get("X-Request-ID",""))
  if response.status_code>=400:
   detail=payload.get("detail",payload) if isinstance(payload,dict) else payload
   if isinstance(detail,dict) and "code" in detail:
    err=api_error(str(detail["code"]),str(detail.get("message",detail["code"])),rid,detail.get("details"))
   else:
    code={400:"BAD_REQUEST",401:"UNAUTHORIZED",403:"FORBIDDEN",404:"NOT_FOUND",409:"CONFLICT",422:"VALIDATION_ERROR",429:"RATE_LIMITED"}.get(response.status_code,"API_ERROR")
    err=api_error(code,str(detail) if isinstance(detail,str) else "Request failed",rid,detail if not isinstance(detail,str) else None)
   body=json.dumps(err).encode()
  elif not(isinstance(payload,dict) and set(("data","error","request_id")).issubset(payload)):
   body=json.dumps(envelope(payload,rid),default=str).encode()
  headers=dict(response.headers);headers.pop("content-length",None)
  return Response(body,status_code=response.status_code,headers=headers,media_type="application/json")

class RateLimitMiddleware(BaseHTTPMiddleware):
 def __init__(self,app,requests_per_minute:int=300):
  super().__init__(app);self.limit=max(10,requests_per_minute);self.hits=defaultdict(deque)
 async def dispatch(self,request:Request,call_next):
  if not request.url.path.startswith("/api/v1/"):return await call_next(request)
  key=request.client.host if request.client else "unknown";now=time.monotonic();q=self.hits[key]
  while q and q[0]<now-60:q.popleft()
  if len(q)>=self.limit:
   rid=getattr(request.state,"request_id","")
   return JSONResponse(api_error("RATE_LIMITED","Too many requests",rid),429,headers={"Retry-After":"60"})
  q.append(now);return await call_next(request)
