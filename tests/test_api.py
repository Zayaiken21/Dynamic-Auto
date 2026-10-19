import unittest,subprocess,tempfile,os,sys,time,json,urllib.request,urllib.error,hashlib,socket,base64
from pathlib import Path
urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))
class API(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory(); sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close();cls.base=f'http://127.0.0.1:{port}';cls.token=''
  env=dict(os.environ,DATA_DIR=cls.tmp.name,PORT=str(port),OWNER_USERNAME='test-owner',OWNER_PASSWORD_SALT='test-salt',OWNER_PASSWORD_HASH=hashlib.pbkdf2_hmac('sha256',b'correct-long-password',b'test-salt',600000).hex(),ALLOWED_ORIGINS='https://frontend.example')
  cls.proc=subprocess.Popen([sys.executable,str(Path(__file__).resolve().parents[1]/'backend/server.py')],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
  for _ in range(15):
   try:urllib.request.urlopen(cls.base+'/api/health',timeout=1).close();break
   except OSError:time.sleep(.1)
  else:
   cls.proc.terminate();cls.proc.wait();raise RuntimeError('Server did not start')
 @classmethod
 def tearDownClass(cls):cls.proc.terminate();cls.proc.wait();cls.proc.stderr.close();cls.tmp.cleanup()
 def req(self,path,method='GET',data=None,auth=False,origin=None,raw=False):
  headers={'Content-Type':'application/json'}
  if auth:headers['Authorization']='Bearer '+self.token
  if origin:headers['Origin']=origin
  req=urllib.request.Request(self.base+path,data=json.dumps(data).encode() if data is not None else None,headers=headers,method=method)
  try:r=urllib.request.urlopen(req,timeout=5)
  except urllib.error.HTTPError as e:r=e
  with r:
   value=r.read();return r.status,value if raw else json.loads(value)
 def test_full_workflow(self):
  self.assertEqual(self.req('/api/admin/cars')[0],401)
  self.assertEqual(self.req('/api/login','POST',{'username':'test-owner','password':'wrong'})[0],401)
  code,r=self.req('/api/login','POST',{'username':'test-owner','password':'correct-long-password'});self.assertEqual(code,200);self.token=r['token']
  self.assertEqual(self.req('/api/admin/cars','POST',{},True,origin='https://evil.example')[0],403)
  self.assertEqual(self.req('/api/upload','POST',{'data':base64.b64encode(b'<svg/>').decode()},True)[0],400)
  raw=base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aP1sAAAAASUVORK5CYII=')
  code,r=self.req('/api/upload','POST',{'data':base64.b64encode(raw).decode()},True);self.assertEqual(code,201)
  photo=r['url'];d={'year':2020,'make':'Toyota','model':'Camry','price':19000,'mileage':50000,'status':'draft','images':[photo],'description':'Real test car','features':'Camera'}
  code,r=self.req('/api/admin/cars','POST',d,True);self.assertEqual(code,201);ident=r['id']
  self.assertEqual(self.req('/api/cars')[1],[]);self.assertEqual(self.req('/api/cars/'+ident)[0],404)
  d['status']='available';self.assertEqual(self.req('/api/admin/cars/'+ident,'PUT',d,True)[0],200)
  self.assertEqual(len(self.req('/api/cars')[1]),1)
  bad={**d,'price':-3};self.assertEqual(self.req('/api/admin/cars/'+ident,'PUT',bad,True)[0],400)
  bad={**d,'images':['https://malicious.invalid/test.svg']};self.assertEqual(self.req('/api/admin/cars/'+ident,'PUT',bad,True)[0],400)
  self.assertEqual(self.req('/api/inquiries','POST',{'name':'Buyer','message':'Hello'})[0],400)
  code,r=self.req('/api/inquiries','POST',{'name':'Buyer','email':'buyer@example.com','message':'Can I see it?','vehicle':ident});self.assertEqual(code,201)
  leads=self.req('/api/admin/inquiries',auth=True)[1];self.assertEqual(len(leads),1)
  self.assertEqual(self.req('/api/admin/inquiries/'+leads[0]['id'],'PUT',{'status':'contacted'},True)[0],200)
  self.assertEqual(self.req('/api/settings','PUT',{'phone':'212-555-0100','email':'test@example.com','address':'Test address','hours':'By appointment'},True)[0],200)
  self.assertEqual(self.req('/api/settings')[1]['instagram'],'dynamicauto1')
  self.assertEqual(self.req(photo,raw=True)[1],raw)
  for private in ['/backend/server.py','/data/dynamic.sqlite','/.env','/assets/../../backend/server.py']:
   self.assertEqual(self.req(private)[0],404)
  self.assertEqual(self.req('/api/admin/cars/'+ident,'DELETE',auth=True)[0],200)
  self.assertEqual(self.req('/api/cars')[1],[])
  self.assertEqual(self.req('/api/logout','POST',{},True)[0],200)
  self.assertEqual(self.req('/api/admin/cars',auth=True)[0],401)
 def test_frontend_routes(self):
  for name in ['index','inventory','vehicle','contact','about','privacy','admin']:
   code,html=self.req('/'+name+'.html',raw=True);self.assertEqual(code,200);self.assertIn(b'Dynamic All Star Auto Sales LLC',html)
if __name__=='__main__':unittest.main()
