#!/usr/bin/env python3
"""Development-only presentation policy fixture server. Never expose publicly."""
import json, os, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
ROOT=Path(__file__).resolve().parent/'policies'
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  u=urlsplit(self.path); m=re.fullmatch(r'/v1/presentation-policies/([A-Za-z0-9_-]+)',u.path)
  if u.path == '/health': return self.send_json(200, {'status':'ok'})
  if not m: return self.send_json(404,{'error':'not found'})
  q=parse_qs(u.query)
  if not q.get('tenantId',[''])[0] or not q.get('groupId',[''])[0]:return self.send_json(400,{'error':'tenantId/groupId required'})
  file=ROOT/(m.group(1)+'.json')
  if not file.is_file():return self.send_json(404,{'error':'policy not found'})
  return self.send_json(200,json.loads(file.read_text()))
 def send_json(self,status,data):
  b=json.dumps(data).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
ThreadingHTTPServer((os.getenv('HOST','0.0.0.0'),int(os.getenv('PORT','8080'))),Handler).serve_forever()
