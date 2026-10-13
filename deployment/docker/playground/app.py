# XFSC verification local browser/NATS test client
import asyncio
import base64
import html
import json
import os
import uuid
from urllib.parse import urlencode, urlsplit, parse_qs
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import nats
from aiohttp import web

NATS_URL = os.getenv('NATS_URL', 'nats://nats:4222')
VERIFIER = os.getenv('VERIFICATION_URL', 'http://verification:8080')
PUBLIC = os.getenv('PUBLIC_VERIFICATION_URL', 'http://localhost:8086')
AUTH_SUBJECT = os.getenv('NATS_AUTHORIZATION_SUBJECT', 'presentation.authorisation')
PRES_SUBJECT = os.getenv('NATS_PRESENTATION_SUBJECT', 'request')

DEFAULT_DCQL = json.dumps({"credentials": [{"id": "identity", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:example:identity"]}}]}, indent=2)

async def connection():
    return await nats.connect(NATS_URL, connect_timeout=3)

async def nats_request(subject, event_type, payload):
    # CloudEvent structured JSON request/reply; framing must be checked with cloudeventprovider.
    nc = await connection()
    try:
        evt = {'specversion':'1.0', 'id':str(uuid.uuid4()), 'source':'/xfsc/local-playground',
               'type':event_type, 'subject':subject, 'datacontenttype':'application/json', 'data':payload}
        msg = await nc.request(subject, json.dumps(evt).encode(), timeout=12)
        raw = msg.data.decode(errors='replace')
        try: return json.loads(raw)
        except ValueError: return {'raw':raw}
    finally:
        await nc.drain()

async def nats_publish(subject, event_type, payload):
    nc = await connection()
    try:
        evt = {'specversion':'1.0','id':str(uuid.uuid4()),'source':'/xfsc/local-playground',
               'type':event_type,'subject':subject,'datacontenttype':'application/json','data':payload}
        await nc.publish(subject, json.dumps(evt).encode())
        await nc.flush()
        return evt
    finally:
        await nc.drain()

def page(message='', status=200):
    body = f'''<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>XFSC Verification Playground</title>
<style>body{{font:15px system-ui;max-width:1000px;margin:2rem auto;padding:0 1rem;background:#f8fafc;color:#172033}}section{{background:white;padding:1.3rem;margin:1rem 0;border-radius:12px;border:1px solid #ddd}}input,textarea,select{{box-sizing:border-box;width:100%;padding:.6rem;margin:.25rem 0 .7rem;border:1px solid #bbc;border-radius:6px}}textarea{{min-height:115px;font-family:monospace}}button{{padding:.7rem 1.1rem;background:#164a9c;color:white;border:0;border-radius:6px;cursor:pointer}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#edf2fa;padding:1rem;border-radius:6px}}small{{color:#555}}</style>
<h1>XFSC Verification Playground</h1><p>Lokale Entwicklungsoberfläche: Authorization-Redirect, Authorization per NATS, Presentation-Request per NATS und Request-Object im Browser.</p>
{('<section><h2>Antwort</h2><pre>'+html.escape(message)+'</pre></section>') if message else ''}
<section><h2>1 · Authorization-Link per Redirect</h2><form method="post" action="/authorization-redirect">
<label>OID4VP Authorization-URI (mit client_id und request_uri)</label><textarea name="uri" placeholder="openid4vp://authorize?client_id=...&request_uri=..."></textarea>
<label>Tenant-ID</label><input name="tenant" value="demo"><label>Group-ID</label><input name="group" value="demo"><label>Request-ID</label><input name="request_id" value="demo-request"><button>Über Verifier weiterleiten</button></form><small>Browser-Redirect wird über /authorize des Verification Service durchgeführt; request_uri muss aus dem Container erreichbar sein. Externe Wallet-URI-Schemes werden in eine HTTP-URL umgesetzt.</small></section>
<section><h2>2 · Authorization-Link per NATS</h2><form method="post" action="/authorization-nats">
<label>client_id</label><input name="client_id" value="redirect_uri:http://localhost:8090/callback"><label>request_uri</label><input name="request_uri" placeholder="http://.../request.jwt"><label>Tenant / Group / Request</label><input name="tenant" value="demo"><input name="group" value="demo"><input name="request_id" value="demo-request"><button>NATS-Event senden</button></form><small>Publiziert den Typ verifier.presentation.authorization.remote auf dem Authorization-Subject; die Antwort ist asynchron auf dem Authorization-Reply-Subject.</small></section>
<section><h2>3 · Presentation-URI über NATS erzeugen</h2><form method="post" action="/presentation-nats">
<label>client_id</label><input name="client_id" value="redirect_uri:http://localhost:8090/callback"><label>tenant_uri (Host)</label><input name="tenant_uri" value="localhost:8086"><label>target_uri (Host)</label><input name="target_uri" value="localhost:8086/presentation"><label>requestobject_uri (Host)</label><input name="requestobject_uri" value="localhost:8086/presentation/proof"><label>Tenant / Group / Request</label><input name="tenant" value="demo"><input name="group" value="demo"><input name="request_id" value="demo-request"><label>DCQL Query</label><textarea name="dcql">{html.escape(DEFAULT_DCQL)}</textarea><button>NATS Request/Reply senden</button></form><small>Eventtyp verifier.presentation.authorization, Subject request. Die URI wird aus der Antwort angezeigt.</small></section>
<section><h2>4 · Presentation-URI / Request-Object im Browser abfragen</h2><form method="get" action="/inspect"><label>Presentation-URI oder HTTP Request-Object URL</label><textarea name="uri" placeholder="http://localhost:8086/presentation/proof/.../request-object/request.jwt"></textarea><label>Tenant / Group</label><input name="tenant" value="demo"><input name="group" value="demo"><button>Abfragen</button></form><small>Request-Object Abruf sendet die benötigten Tenant/Group-Header; bei Authorization-Links wird request_uri aufgelöst.</small></section>
<section><h2>5 · DCQL per HTTP erzeugen</h2><form method="post" action="/presentation-http"><label>client_id</label><input name="client_id" value="redirect_uri:http://localhost:8090/callback"><label>Tenant / Group / Request</label><input name="tenant" value="demo"><input name="group" value="demo"><input name="request_id" value="demo-request"><label>DCQL Query</label><textarea name="dcql">{html.escape(DEFAULT_DCQL)}</textarea><button>GET /presentation/request aufrufen</button></form></section></html>'''
    return web.Response(text=body,content_type='text/html',status=status)

def fields(request): return request.post()

def headers(f):
    return {'x-tenantId': f.get('tenant','demo'), 'x-groupId':f.get('group','demo'),
            'x-requestId':f.get('request_id','demo-request'), 'x-client-id':f.get('client_id','')}

def fetch(url, hs):
    # Deliberately restricted to verifier service: do not create an open proxy.
    parsed=urlsplit(url)
    if parsed.scheme not in ('http','https') or parsed.hostname not in ('localhost','127.0.0.1','verification'):
        raise ValueError('Only localhost/verification URLs can be fetched from playground')
    local=VERIFIER + parsed.path + ('?'+parsed.query if parsed.query else '')
    req=Request(local, headers=hs)
    try:
        with urlopen(req, timeout=12) as r: return r.status, r.read().decode(errors='replace')
    except HTTPError as e: return e.code, e.read().decode(errors='replace')

async def index(request): return page()

async def auth_redirect(request):
    f=await fields(request)
    uri=f.get('uri','').strip()
    parsed=urlsplit(uri)
    qs=parse_qs(parsed.query)
    if not qs.get('client_id') or not qs.get('request_uri'): return page('client_id und request_uri fehlen',400)
    dest=PUBLIC+'/presentation/authorize?'+urlencode({'client_id':qs['client_id'][0], 'request_uri':qs['request_uri'][0]})
    # Browser navigation cannot attach custom tenant headers; route through our HTTP forwarder.
    dest='/authorize-forward?'+urlencode({'uri':dest,'tenant':f.get('tenant','demo'),'group':f.get('group','demo'),'request_id':f.get('request_id','demo-request')})
    raise web.HTTPFound(dest)

async def authorize_forward(request):
    f=request.query
    url=f.get('uri','')
    try:
        status,body=await asyncio.to_thread(fetch,url,headers(f))
        return page(f'HTTP {status}\n{body}')
    except Exception as e: return page(str(e),502)

async def auth_nats(request):
    f=await fields(request)
    payload={'tenantId':f.get('tenant','demo'),'groupId':f.get('group','demo'),'requestId':f.get('request_id','demo-request'),
             'clientId':f.get('client_id',''),'request_uri':f.get('request_uri',''),'ttl':3600}
    try: return page(json.dumps(await nats_publish(AUTH_SUBJECT,'verifier.presentation.authorization.remote',payload),indent=2)+'\nAntwort-Subject: presentation.authorisation.reply')
    except Exception as e: return page(str(e),502)

async def pres_nats(request):
    f=await fields(request)
    try:
        dcql=json.loads(f.get('dcql','{}'))
        payload={'tenantId':f.get('tenant','demo'),'groupId':f.get('group','demo'),'requestId':f.get('request_id','demo-request'),
                 'client_id':f.get('client_id',''),'ttl':3600,'tenant_uri':f.get('tenant_uri',''),
                 'target_uri':f.get('target_uri',''),'requestobject_uri':f.get('requestobject_uri',''), 'dcql_query':dcql}
        result=await nats_request(PRES_SUBJECT,'verifier.presentation.authorization',payload)
        return page(json.dumps(result,indent=2))
    except Exception as e: return page(str(e),502)

async def inspect(request):
    f=request.query
    uri=f.get('uri','').strip()
    parsed=urlsplit(uri)
    qs=parse_qs(parsed.query)
    target=qs.get('request_uri',[uri])[0]
    try:
        status,body=await asyncio.to_thread(fetch,target,headers(f))
        return page(f'HTTP {status}\n{body}')
    except Exception as e: return page(str(e),502)

async def pres_http(request):
    f=await fields(request)
    try:
        query=base64.urlsafe_b64encode(json.dumps(json.loads(f.get('dcql','{}'))).encode()).rstrip(b'=').decode()
        url=PUBLIC+'/presentation/request?'+urlencode({'requestId':f.get('request_id','demo-request'),'dcqlQuery':query})
        status,body=await asyncio.to_thread(fetch,url,headers(f))
        return page(f'HTTP {status}\n{body}')
    except Exception as e: return page(str(e),502)

async def callback(request):
    return page('Callback query:\n'+json.dumps(dict(request.query),indent=2))

app=web.Application(client_max_size=2*1024*1024)
app.router.add_get('/',index)
app.router.add_post('/authorization-redirect',auth_redirect)
app.router.add_get('/authorize-forward',authorize_forward)
app.router.add_post('/authorization-nats',auth_nats)
app.router.add_post('/presentation-nats',pres_nats)
app.router.add_get('/inspect',inspect)
app.router.add_post('/presentation-http',pres_http)
app.router.add_get('/callback',callback)
web.run_app(app,host='0.0.0.0',port=8090)
