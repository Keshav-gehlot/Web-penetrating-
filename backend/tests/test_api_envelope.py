from fastapi import FastAPI,HTTPException
from fastapi.testclient import TestClient
from app.api_quality import APIEnvelopeMiddleware

def test_success_response_has_standard_envelope():
 app=FastAPI();app.add_middleware(APIEnvelopeMiddleware)
 @app.get("/api/v1/example")
 async def example():return {"value":1}
 body=TestClient(app).get("/api/v1/example").json()
 assert body["data"]=={"value":1}
 assert body["error"] is None
 assert "request_id" in body

def test_not_found_has_structured_error():
 app=FastAPI();app.add_middleware(APIEnvelopeMiddleware)
 @app.get("/api/v1/example")
 async def example():raise HTTPException(status_code=404,detail="Missing")
 response=TestClient(app).get("/api/v1/example")
 assert response.status_code==404
 assert response.json()["error"]["code"]=="NOT_FOUND"
