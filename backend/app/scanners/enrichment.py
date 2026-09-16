from urllib.parse import urlparse
import httpx

UA = "PHANTOM/2.0 authorized-security-assessment"
TIMEOUT = 8.0

async def cve_lookup(target: str) -> dict:
    host = urlparse(target).hostname or target
    async with httpx.AsyncClient(timeout=TIMEOUT, headers={"User-Agent": UA}) as client:
        # Use visible server metadata as a keyword seed. We do not invent a product/version.
        response = await client.get(target)
        server = response.headers.get("server") or response.headers.get("x-powered-by")
        if not server:
            return {"module":"cve_lookup","query":None,"matches":[],"findings":[],"note":"No software fingerprint was exposed by the target."}
        nvd = await client.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"keywordSearch":server.split("/")[0],"resultsPerPage":10})
        matches=[]
        if nvd.status_code == 200:
            data=nvd.json()
            for item in data.get("vulnerabilities",[]):
                cve=item.get("cve",{})
                matches.append({"id":cve.get("id"),"published":cve.get("published"),"lastModified":cve.get("lastModified"),"description":next((d.get("value") for d in cve.get("descriptions",[]) if d.get("lang")=="en"),None)})
        return {"module":"cve_lookup","host":host,"query":server,"matches":matches,"findings":[],"source":"NVD"}

async def whois_lookup(target: str) -> dict:
    host=urlparse(target).hostname or target
    async with httpx.AsyncClient(timeout=TIMEOUT, headers={"User-Agent":UA}) as client:
        response=await client.get(f"https://rdap.org/domain/{host}")
        if response.status_code != 200:
            return {"module":"whois_lookup","host":host,"source":"RDAP","status":response.status_code,"data":{},"findings":[]}
        data=response.json()
        return {"module":"whois_lookup","host":host,"source":"RDAP","status":200,"data":{
            "ldhName":data.get("ldhName"),"handle":data.get("handle"),"status":data.get("status"),
            "events":data.get("events",[]),"nameservers":[n.get("ldhName") for n in data.get("nameservers",[]) if n.get("ldhName")]
        },"findings":[]}
