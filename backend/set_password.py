import getpass,hashlib,secrets
password=getpass.getpass('New owner password (12+ characters): ')
if len(password)<12:raise SystemExit('Use at least 12 characters.')
salt=secrets.token_hex(32)
print('Set these private backend environment variables (never add to GitHub):')
print('OWNER_PASSWORD_SALT='+salt)
print('OWNER_PASSWORD_HASH='+hashlib.pbkdf2_hmac('sha256',password.encode(),salt.encode(),600000).hex())
