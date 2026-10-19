"""Dynamic Auto API. Python 3.12+, no third-party dependencies. Run behind HTTPS."""
import os, json, sqlite3, hashlib, secrets, time, base64, re, io
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote
ROOT=Path(__file__).resolve().parent.parent
DATA=Path(os.environ.get('DATA_DIR', str(ROOT/'data'))); DATA.mkdir(parents=True,exist_ok=True)
UPLOAD=DATA/'uploads'; UPLOAD.mkdir(exist_ok=True)
ORIGINS=[x.strip().rstrip('/') for x in os.environ.get('ALLOWED_ORIGINS','http://localhost:8000,http://127.0.0.1:8000').split(',')]
DEV=os.environ.get('DEV_MODE')=='1'
def db():
 c=sqlite3.connect(DATA/'dynamic.sqlite'); c.row_factory=sqlite3.Row; return c
def init():
 with db() as c:
  c.executescript('CREATE TABLE IF NOT EXISTS cars(id TEXT PRIMARY KEY, body TEXT NOT NULL); CREATE TABLE IF NOT EXISTS inquiries(id TEXT PRIMARY KEY, body TEXT NOT NULL); CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, expires REAL); CREATE TABLE IF NOT EXISTS limits(key TEXT PRIMARY KEY, start REAL, count INTEGER); CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY, body TEXT);')
def limited(key, maximum, window):
 now=time.time()
 with db() as c:
  c.execute('BEGIN IMMEDIATE'); c.execute('DELETE FROM limits WHERE start<?',(now-86400,)); r=c.execute('SELECT * FROM limits WHERE key=?',(key,)).fetchone()
  if not r or now-r['start']>window: c.execute('INSERT OR REPLACE INTO limits VALUES(?,?,?)',(key,now,1)); return False
  if r['count']>=maximum:return True
  c.execute('UPDATE limits SET count=count+1 WHERE key=?',(key,)); return False
def settings():
 with db() as c:r=c.execute('SELECT body FROM settings WHERE id=1').fetchone()
 return json.loads(r[0]) if r else {'phone':'','email':'','address':'','hours':'By appointment','instagram':'dynamicauto1'}
def cars(admin=False):
 with db() as c:rows=[json.loads(r[0]) for r in c.execute('SELECT body FROM cars ORDER BY rowid DESC')]
 return rows if admin else [x for x in rows if x['status']!='draft']
def clean_car(d):
 out={k:str(d.get(k,'')).strip()[:n] for k,n in {'make':80,'model':100,'trim':100,'body':40,'transmission':60,'fuel':40,'drivetrain':30,'engine':100,'exterior':60,'interior':60,'vin':17,'stock':40,'description':6000,'features':2000}.items()}
 if not out['make'] or not out['model']:raise ValueError('Make and model are required.')
 for k,lo,hi in [('year',1886,2100),('price',0,100000000),('mileage',0,10000000),('horsepower',0,10000),('topSpeed',0,1000)]:
  v=d.get(k); out[k]=None if v in ('',None) else float(v)
  if out[k] is not None and (not lo<=out[k]<=hi or out[k]!=out[k]):raise ValueError('Invalid '+k)
 if out['year'] is None or out['mileage'] is None:raise ValueError('Year and mileage are required.')
 out['status']=d.get('status','draft')
 if out['status'] not in ['draft','available','pending','sold']:raise ValueError('Invalid status')
 out['images']=d.get('images',[])[:24]
 if any(not re.fullmatch(r'/uploads/[a-f0-9]{32}\.(jpg|png|webp)',str(x)) for x in out['images']):raise ValueError('Upload photos using the uploader.')
 if out['status']!='draft' and not out['images']:raise ValueError('Add at least one photo before publishing.')
 return out
class Handler(BaseHTTPRequestHandler):
 def log_message(self,fmt,*args): pass
 def response_headers(self,status=200,kind='application/json'):
  self.send_response(status); self.send_header('Content-Type',kind); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Cache-Control','no-store')
  origin=self.headers.get('Origin','')
  if origin in ORIGINS:self.send_header('Access-Control-Allow-Origin',origin); self.send_header('Vary','Origin')
  self.send_header('Access-Control-Allow-Headers','Content-Type, Authorization'); self.send_header('Access-Control-Allow-Methods','GET, POST, PUT, DELETE, OPTIONS'); self.end_headers()
 def send(self,data,status=200):self.response_headers(status); self.wfile.write(json.dumps(data).encode())
 def read(self):
  n=int(self.headers.get('Content-Length','0'))
  if n>18000000:raise ValueError('Request too large (maximum 12 MB photo).')
  if 'application/json' not in self.headers.get('Content-Type',''):raise ValueError('JSON required')
  return json.loads(self.rfile.read(n))
 def authorized(self):
  token=self.headers.get('Authorization','').removeprefix('Bearer ')
  with db() as c:r=c.execute('SELECT expires FROM sessions WHERE token=?',(hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
  return bool(r and r[0]>time.time())
 def do_OPTIONS(self):self.response_headers(204)
 def do_GET(self):self.route('GET')
 def do_POST(self):self.route('POST')
 def do_PUT(self):self.route('PUT')
 def do_DELETE(self):self.route('DELETE')
 def route(self,method):
  try:self.dispatch(method)
  except (ValueError,KeyError,TypeError) as e:self.send({'error':str(e)},400)
  except Exception:self.send({'error':'Server error. Please try again.'},500)
 def dispatch(self,method):
  p=urlparse(self.path).path
  if method not in ['GET','OPTIONS'] and self.headers.get('Origin') and self.headers['Origin'] not in ORIGINS:return self.send({'error':'Origin not allowed'},403)
  if p=='/api/health':return self.send({'ok':True})
  if p=='/api/login' and method=='POST':
   if limited('login:'+self.client_address[0],10,900):return self.send({'error':'Too many attempts. Try again in 15 minutes.'},429)
   d=self.read(); expected=os.environ.get('OWNER_PASSWORD_HASH',''); salt=os.environ.get('OWNER_PASSWORD_SALT','')
   supplied=hashlib.pbkdf2_hmac('sha256',str(d.get('password','')).encode(),salt.encode(),600000).hex()
   if not expected or not secrets.compare_digest(str(d.get('username','')),os.environ.get('OWNER_USERNAME','owner')) or not secrets.compare_digest(supplied,expected):return self.send({'error':'Incorrect username or password.'},401)
   token=secrets.token_urlsafe(48)
   with db() as c:
    c.execute('DELETE FROM sessions WHERE expires<?',(time.time(),)); c.execute('INSERT INTO sessions VALUES(?,?)',(hashlib.sha256(token.encode()).hexdigest(),time.time()+28800))
   return self.send({'token':token})
  if p=='/api/settings' and method=='GET':return self.send(settings())
  if p=='/api/cars' and method=='GET':return self.send(cars())
  if p.startswith('/api/cars/') and method=='GET':
   car=next((x for x in cars() if x['id']==p.split('/')[-1]),None)
   return self.send(car if car else {'error':'Vehicle not found'},200 if car else 404)
  if p=='/api/inquiries' and method=='POST':
   if limited('inquiry:'+self.client_address[0],8,3600):return self.send({'error':'Please contact us on Instagram for further help.'},429)
   d=self.read()
   if d.get('website'):return self.send({'ok':True})
   out={k:str(d.get(k,'')).strip()[:n] for k,n in {'name':100,'email':254,'phone':50,'message':3000,'vehicle':100}.items()}
   if not out['name'] or not out['message'] or not (out['phone'] or re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',out['email'])):raise ValueError('Add your name, message, and a valid email or phone number.')
   if out['vehicle'] and not any(x['id']==out['vehicle'] for x in cars()):raise ValueError('Vehicle is no longer listed.')
   out.update(id=secrets.token_hex(12),created=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),status='new')
   with db() as c:c.execute('INSERT INTO inquiries VALUES(?,?)',(out['id'],json.dumps(out)))
   return self.send({'ok':True,'reference':out['id']},201)
  if p.startswith('/api/'):
   if not self.authorized():return self.send({'error':'Please sign in again.'},401)
   if p=='/api/logout':
    with db() as c:c.execute('DELETE FROM sessions WHERE token=?',(hashlib.sha256(self.headers.get('Authorization','').removeprefix('Bearer ').encode()).hexdigest(),))
    return self.send({'ok':True})
   if p=='/api/admin/cars' and method=='GET':return self.send(cars(True))
   if p=='/api/admin/inquiries' and method=='GET':
    with db() as c:return self.send([json.loads(x[0]) for x in c.execute('SELECT body FROM inquiries ORDER BY rowid DESC')])
   if p.startswith('/api/admin/inquiries/') and method=='PUT':
    ident=p.split('/')[-1]; status=self.read().get('status')
    if status not in ['new','contacted','closed']:raise ValueError('Invalid inquiry status')
    with db() as c:
     r=c.execute('SELECT body FROM inquiries WHERE id=?',(ident,)).fetchone()
     if not r:return self.send({'error':'Not found'},404)
     d=json.loads(r[0]); d['status']=status; c.execute('UPDATE inquiries SET body=? WHERE id=?',(json.dumps(d),ident))
    return self.send({'ok':True})
   if p=='/api/settings' and method=='PUT':
    d=self.read(); out={k:str(d.get(k,'')).strip()[:500] for k in ['phone','email','address','hours']}; out['instagram']='dynamicauto1'
    with db() as c:c.execute('INSERT OR REPLACE INTO settings VALUES(1,?)',(json.dumps(out),))
    return self.send(out)
   if p=='/api/upload' and method=='POST':
    raw=base64.b64decode(self.read()['data'],validate=True)
    if len(raw)>12000000:raise ValueError('Photo exceeds 12 MB.')
    ext='jpg' if raw.startswith(b'\xff\xd8\xff') else 'png' if raw.startswith(b'\x89PNG\r\n\x1a\n') else 'webp' if raw[:4]==b'RIFF' and raw[8:12]==b'WEBP' else None
    if not ext:raise ValueError('Use JPG, PNG or WebP. Convert iPhone HEIC photos first.')
    name=secrets.token_hex(16)+'.'+ext; (UPLOAD/name).write_bytes(raw); return self.send({'url':'/uploads/'+name},201)
   if p=='/api/admin/cars' and method=='POST':
    d=clean_car(self.read()); d.update(id=secrets.token_hex(12),updated=time.time())
    with db() as c:c.execute('INSERT INTO cars VALUES(?,?)',(d['id'],json.dumps(d)))
    return self.send(d,201)
   if p.startswith('/api/admin/cars/') and method in ['PUT','DELETE']:
    ident=p.split('/')[-1]
    with db() as c:
     if not c.execute('SELECT 1 FROM cars WHERE id=?',(ident,)).fetchone():return self.send({'error':'Not found'},404)
     if method=='DELETE':c.execute('DELETE FROM cars WHERE id=?',(ident,)); return self.send({'ok':True})
     d=clean_car(self.read()); d.update(id=ident,updated=time.time()); c.execute('UPDATE cars SET body=? WHERE id=?',(json.dumps(d),ident))
    return self.send(d)
   return self.send({'error':'Not found'},404)
  if method!='GET':return self.send({'error':'Not found'},404)
  if p.startswith('/uploads/'):
   f=UPLOAD/Path(p).name
   if not re.fullmatch(r'[a-f0-9]{32}\.(jpg|png|webp)',f.name) or not f.is_file():return self.send({'error':'Not found'},404)
   self.response_headers(200,{'jpg':'image/jpeg','png':'image/png','webp':'image/webp'}[f.suffix[1:]]); return self.wfile.write(f.read_bytes())
  # Serve only public frontend files, never source, database, or configuration.
  relative=unquote(p).lstrip('/') or 'index.html'
  if relative not in ['index.html','inventory.html','vehicle.html','contact.html','about.html','admin.html','privacy.html','config.js','robots.txt'] and not relative.startswith('assets/'):return self.send({'error':'Not found'},404)
  f=(ROOT/relative).resolve()
  if not f.is_relative_to(ROOT) or not f.is_file():return self.send({'error':'Not found'},404)
  import mimetypes
  self.response_headers(200,mimetypes.guess_type(f)[0] or 'application/octet-stream'); self.wfile.write(f.read_bytes())
if __name__=='__main__':
 init(); ThreadingHTTPServer(('0.0.0.0',int(os.environ.get('PORT','8000'))),Handler).serve_forever()
