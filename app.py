from flask import Flask, request, jsonify, session, send_from_directory, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3, os, re, secrets, hashlib, smtplib, mimetypes, json, urllib.request, urllib.error, shutil
from email.message import EmailMessage
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")
DB_PATH = Path(os.getenv('DB_PATH', ROOT / 'dual_auth_voting.sqlite3'))
UPLOADS = ROOT / 'uploads'
UPLOADS.mkdir(exist_ok=True)
NID_STORAGE = ROOT / 'private_nid_storage'
NID_STORAGE.mkdir(mode=0o700, exist_ok=True)
app = Flask(__name__, static_folder=None)
app.secret_key = os.getenv('SECRET_KEY', 'CHANGE-ME-before-deployment-' + secrets.token_hex(16))
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', MAX_CONTENT_LENGTH=12*1024*1024)
ADMIN_TOKEN = os.getenv('ADMIN_TOKEN', '').strip()
OTP_DEV_MODE = os.getenv('OTP_DEV_MODE', '1') == '1'

SCHEMA = '''
CREATE TABLE IF NOT EXISTS voters(id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, guardian_name TEXT NOT NULL, nid TEXT NOT NULL UNIQUE, division TEXT NOT NULL, district TEXT NOT NULL, upazila TEXT NOT NULL, ward TEXT NOT NULL, email TEXT NOT NULL UNIQUE, primary_phone TEXT NOT NULL DEFAULT '', secondary_phone TEXT NOT NULL DEFAULT '', password_hash TEXT NOT NULL, duress_password_hash TEXT NOT NULL, otp_verified_at TEXT, face_descriptor TEXT, face_enrolled_at TEXT, face_image_path TEXT, face_status TEXT NOT NULL DEFAULT 'pending', face_reviewed_at TEXT, face_verified_at TEXT, fingerprint_registered INTEGER NOT NULL DEFAULT 0, biometric_verified_at TEXT, is_registered INTEGER NOT NULL DEFAULT 1, has_voted INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS nid_documents(id INTEGER PRIMARY KEY AUTOINCREMENT, voter_id INTEGER NOT NULL UNIQUE, front_path TEXT NOT NULL, back_path TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')), rejection_reason TEXT, reviewed_by TEXT, reviewed_at TEXT, uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(voter_id) REFERENCES voters(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS otp_codes(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT NOT NULL,otp_hash TEXT NOT NULL,purpose TEXT NOT NULL DEFAULT 'registration',expires_at TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,verified_at TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS candidates(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,party TEXT NOT NULL,symbol TEXT,position TEXT NOT NULL DEFAULT 'Member',division TEXT,district TEXT,upazila TEXT,ward TEXT,photo TEXT,status TEXT NOT NULL DEFAULT 'active',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS votes(id INTEGER PRIMARY KEY AUTOINCREMENT,voter_id INTEGER NOT NULL UNIQUE,candidate_id INTEGER NOT NULL,division TEXT NOT NULL,district TEXT NOT NULL,upazila TEXT NOT NULL,ward TEXT NOT NULL,cast_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(voter_id) REFERENCES voters(id), FOREIGN KEY(candidate_id) REFERENCES candidates(id));
CREATE TABLE IF NOT EXISTS election_control(id INTEGER PRIMARY KEY AUTOINCREMENT,election_name TEXT NOT NULL DEFAULT 'National Digital Election',is_running INTEGER NOT NULL DEFAULT 0,start_time TEXT,end_time TEXT,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS notices(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,message TEXT,file_path TEXT,created_by TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,voter_id INTEGER,action TEXT NOT NULL,ip_address TEXT,user_agent TEXT,details TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
'''

class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc, tb):
        try:
            return super().__exit__(exc_type, exc, tb)
        finally:
            self.close()

def db():
    conn=sqlite3.connect(DB_PATH, timeout=15, factory=ClosingConnection)
    conn.row_factory=sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

def init_db():
    with db() as c:
        c.executescript(SCHEMA)
        existing = {r['name'] for r in c.execute('PRAGMA table_info(voters)').fetchall()}
        for col in ('primary_phone','secondary_phone'):
            if col not in existing: c.execute(f"ALTER TABLE voters ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
        for col, definition in [('face_descriptor','TEXT'),('face_image_path','TEXT'),('face_status',"TEXT NOT NULL DEFAULT 'pending'"),('face_reviewed_at','TEXT'),('face_verified_at','TEXT'),('fingerprint_registered','INTEGER NOT NULL DEFAULT 0')]:
            if col not in existing: c.execute(f'ALTER TABLE voters ADD COLUMN {col} {definition}')
        if not c.execute('SELECT id FROM election_control LIMIT 1').fetchone():
            c.execute("INSERT INTO election_control(election_name,is_running) VALUES('National Digital Election',0)")
        c.commit()
init_db()

def out(data, status=200): return jsonify(data), status
def fail(message,status=400,**kw): return out({'success':False,'message':message,**kw},status)
def value(key, default=''):
    # Accept form submissions (existing frontend) and JSON API clients consistently.
    if key in request.form:
        return request.form.get(key, default)
    if key in request.args:
        return request.args.get(key, default)
    payload = request.get_json(silent=True)
    if isinstance(payload, dict) and key in payload:
        return payload.get(key, default)
    return default
def body():
    if request.is_json: return request.get_json(silent=True) or {}
    return request.form

def csrf_token():
    if 'csrf_token' not in session: session['csrf_token']=secrets.token_urlsafe(32)
    return session['csrf_token']
def check_csrf():
    got=request.headers.get('X-CSRF-Token') or request.form.get('csrf_token') or (request.get_json(silent=True) or {}).get('csrf_token')
    return bool(got and secrets.compare_digest(str(got), str(session.get('csrf_token',''))))
def csrf_required(fn):
    @wraps(fn)
    def wrap(*a,**kw):
        if not check_csrf(): return fail('Security token expired. Refresh the page and try again.',403)
        return fn(*a,**kw)
    return wrap
def admin_required(fn):
    @wraps(fn)
    def wrap(*a,**kw):
        if session.get('role')!='admin': return fail('Admin login required.',401)
        return fn(*a,**kw)
    return wrap
def voter_required(fn):
    @wraps(fn)
    def wrap(*a,**kw):
        if not session.get('voter_id'): return fail('Please log in first.',401)
        return fn(*a,**kw)
    return wrap
def audit(conn, action, voter_id=None, details=''):
    conn.execute('INSERT INTO audit_logs(voter_id,action,ip_address,user_agent,details) VALUES(?,?,?,?,?)',(voter_id,action,request.remote_addr,request.headers.get('User-Agent','')[:500],str(details)))
_DIGIT_TRANSLATION = str.maketrans({
    **{chr(0x09E6 + i): str(i) for i in range(10)},
    **{chr(0x0660 + i): str(i) for i in range(10)},
    **{chr(0x06F0 + i): str(i) for i in range(10)},
})
def normalize_digits(value):
    value = str(value or "").translate(_DIGIT_TRANSLATION)
    return value.replace(" ", "").replace("-", "")
def valid_nid(nid): return nid.isascii() and nid.isdigit() and len(nid) in (10,13,17)

def validate_nid_image(upload):
    if not upload or not upload.filename:
        return None, 'Upload both the front and back NID images.'
    ext = Path(secure_filename(upload.filename)).suffix.lower()
    if ext not in {'.jpg', '.jpeg', '.png', '.webp'}:
        return None, 'NID images must be JPG, PNG or WEBP.'
    upload.stream.seek(0, os.SEEK_END)
    size = upload.stream.tell()
    upload.stream.seek(0)
    if size < 16 or size > 5 * 1024 * 1024:
        return None, 'Each NID image must be between 16 bytes and 5 MB.'
    header = upload.stream.read(16)
    upload.stream.seek(0)
    is_jpeg = header.startswith(b'\xff\xd8\xff')
    is_png = header.startswith(b'\x89PNG\r\n\x1a\n')
    is_webp = len(header) >= 12 and header[:4] == b'RIFF' and header[8:12] == b'WEBP'
    if not ((ext in {'.jpg','.jpeg'} and is_jpeg) or (ext == '.png' and is_png) or (ext == '.webp' and is_webp)):
        return None, 'The uploaded file content does not match a supported image format.'
    return ext, None
def mail_otp(email, otp, minutes):
    host=os.getenv('SMTP_HOST'); user=os.getenv('SMTP_USER'); password=os.getenv('SMTP_PASS')
    if not (host and user and password):
        if OTP_DEV_MODE:
            print(f'\n[DEV OTP] {email}: {otp} (expires in {minutes} minutes)\n', flush=True)
            return True
        return False
    msg=EmailMessage(); msg['Subject']='Dual Auth Vote - Registration OTP'; msg['From']=os.getenv('SMTP_FROM',user); msg['To']=email
    msg.set_content(f'Your registration OTP is {otp}. It expires in {minutes} minutes. Do not share it.')
    try:
        port=int(os.getenv('SMTP_PORT','465'))
        if os.getenv('SMTP_SECURE','ssl').lower()=='tls':
            with smtplib.SMTP(host,port,timeout=15) as s: s.starttls(); s.login(user,password); s.send_message(msg)
        else:
            with smtplib.SMTP_SSL(host,port,timeout=15) as s: s.login(user,password); s.send_message(msg)
        return True
    except Exception as e:
        app.logger.exception('SMTP send failed'); return False

@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options']='nosniff'; resp.headers['X-Frame-Options']='DENY'; resp.headers['Referrer-Policy']='strict-origin-when-cross-origin'; resp.headers['Cache-Control']='no-store'
    return resp

@app.get('/')
def home():
    return send_from_directory(ROOT,'index.html')

@app.get('/services.html')
def services_page():
    # The page is stored in services/services.html, while existing navigation
    # links use the legacy root URL /services.html. Keep both paths working.
    return send_from_directory(ROOT / 'services', 'services.html')
@app.get('/<path:path>')
def static_files(path):
    # Existing frontend pages/assets are served by Flask; PHP endpoint URLs are handled below.
    if path.startswith('api/') and path.endswith('.php'): return fail('API endpoint is not implemented.',404)
    root = ROOT.resolve()
    target = (root / path).resolve()
    allowed_suffixes = {'.html','.css','.js','.png','.jpg','.jpeg','.webp','.gif','.svg','.ico','.woff','.woff2','.ttf','.pdf'}
    if (not target.is_relative_to(root) or not target.is_file()
            or any(part.startswith('.') for part in target.relative_to(root).parts)
            or target.suffix.lower() not in allowed_suffixes
            or target.relative_to(root).as_posix().startswith('uploads/private/')):
        return fail('Page or file not found.',404)
    return send_from_directory(root,target.relative_to(root).as_posix())

@app.route('/api/csrf.php', methods=['GET'])
def csrf(): return out({'success':True,'csrf_token':csrf_token()})

@app.route('/api/send-otp.php', methods=['POST'])
@csrf_required
def send_otp():
    email=value('email').strip().lower()
    if '@' not in email or len(email)>190: return fail('Enter a valid email address.',422)
    with db() as c:
        recent=c.execute("SELECT COUNT(*) n FROM otp_codes WHERE email=? AND purpose='registration' AND created_at >= datetime('now','-10 minutes')",(email,)).fetchone()['n']
        if recent>=3: return fail('Too many OTP requests. Please try again later.',429)
        if c.execute('SELECT id FROM voters WHERE email=?',(email,)).fetchone(): return fail('This email is already registered.',409)
        otp=f'{secrets.randbelow(1000000):06d}'; minutes=max(1,min(30,int(os.getenv('OTP_EXPIRES_MINUTES','10'))))
        c.execute("UPDATE otp_codes SET expires_at=datetime('now') WHERE email=? AND purpose='registration' AND verified_at IS NULL",(email,))
        c.execute("INSERT INTO otp_codes(email,otp_hash,purpose,expires_at) VALUES(?,?,'registration',datetime('now',?))",(email,generate_password_hash(otp),f'+{minutes} minutes'))
        c.commit()
    if not mail_otp(email,otp,minutes):
        with db() as c: c.execute("DELETE FROM otp_codes WHERE email=? AND purpose='registration' AND verified_at IS NULL",(email,)); c.commit()
        return fail('Could not send OTP email. Configure SMTP in .env.',503)
    result={'success':True,'message':'OTP sent successfully. Please check your email.'}
    if OTP_DEV_MODE and not (os.getenv('SMTP_HOST') and os.getenv('SMTP_USER') and os.getenv('SMTP_PASS')): result['dev_mode']=True; result['message']='Development OTP generated. Check the terminal running Flask.'
    return out(result)

@app.route('/api/verify-otp.php', methods=['POST'])
@csrf_required
def verify_otp():
    email=value('email').strip().lower(); otp=value('otp').strip()
    with db() as c:
        r=c.execute("SELECT * FROM otp_codes WHERE email=? AND purpose='registration' AND verified_at IS NULL ORDER BY id DESC LIMIT 1",(email,)).fetchone()
        if not r: return fail('OTP not found or already used.',400)
        if datetime.fromisoformat(r['expires_at']) < datetime.now(timezone.utc).replace(tzinfo=None): return fail('OTP has expired. Request a new OTP.',400)
        if r['attempts']>=5: return fail('Too many OTP attempts. Request a new OTP.',429)
        if not check_password_hash(r['otp_hash'],otp): c.execute('UPDATE otp_codes SET attempts=attempts+1 WHERE id=?',(r['id'],)); c.commit(); return fail('Incorrect OTP.',400)
        c.execute("UPDATE otp_codes SET verified_at=datetime('now') WHERE id=?",(r['id'],)); c.commit()
    return out({'success':True,'message':'OTP verified successfully.'})

@app.route('/api/registration.php', methods=['POST'])
@csrf_required
def registration():
    d=body(); full=d.get('fullName','').strip(); guardian=d.get('guardianName','').strip(); nid=normalize_digits(d.get('nid','')); division=d.get('division','').strip(); district=d.get('district','').strip(); upazila=d.get('upazila','').strip(); ward=d.get('ward','').strip(); email=d.get('email','').strip().lower(); primary_phone=str(d.get('primaryPhone', d.get('primary_phone',''))).strip(); secondary_phone=str(d.get('secondaryPhone', d.get('secondary_phone',''))).strip(); otp=str(d.get('otp','')).strip(); pw=str(d.get('password','')); dpw=str(d.get('duressPassword',''))
    # Return a precise validation error instead of the old generic message.
    if not full: return fail('Full name is required.',422)
    if not guardian: return fail("Father's/Husband's name is required.",422)
    if not valid_nid(nid): return fail('NID must contain exactly 10, 13 or 17 digits.',422)
    if division in ('', 'Select Division'): return fail('Please select a division.',422)
    if district in ('', 'Select District'): return fail('Please select a district.',422)
    if upazila in ('', 'Select Upazila'): return fail('Please select an upazila.',422)
    if not ward or ward == 'Select Ward': return fail('Please select a ward.',422)
    if not re.fullmatch(r'[+0-9() -]{7,20}', primary_phone): return fail('Enter a valid primary phone number (7–20 digits/phone symbols).',422)
    if not re.fullmatch(r'[+0-9() -]{7,20}', secondary_phone): return fail('Enter a valid secondary phone number (7–20 digits/phone symbols).',422)
    if primary_phone == secondary_phone: return fail('Primary and secondary phone numbers must be different.',422)
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email): return fail('Enter a valid email address.',422)
    if not re.fullmatch(r'\d{6}', otp): return fail('OTP must contain exactly 6 English digits.',422)
    if not re.fullmatch(r'\d{8}', pw): return fail('Primary PIN must contain exactly 8 English digits.',422)
    if not re.fullmatch(r'\d{8}', dpw): return fail('Duress PIN must contain exactly 8 English digits.',422)
    if pw == dpw: return fail('Primary PIN and Duress PIN must be different.',422)
    front = request.files.get('nid_front')
    back = request.files.get('nid_back')
    front_ext, front_error = validate_nid_image(front)
    back_ext, back_error = validate_nid_image(back)
    if front_error or back_error:
        return fail(front_error or back_error or 'Please upload both NID images.', 422)
    with db() as c:
        r=c.execute("SELECT * FROM otp_codes WHERE email=? AND purpose='registration' ORDER BY id DESC LIMIT 1",(email,)).fetchone()
        if not r: return fail('Please request an OTP first.',400)
        if datetime.fromisoformat(r['expires_at'])<datetime.now(timezone.utc).replace(tzinfo=None): return fail('OTP has expired.',400)
        if r['attempts']>=5: return fail('Too many OTP attempts.',429)
        if not check_password_hash(r['otp_hash'],otp): c.execute('UPDATE otp_codes SET attempts=attempts+1 WHERE id=?',(r['id'],)); c.commit(); return fail('Incorrect OTP.',400)
        if c.execute('SELECT id FROM voters WHERE nid=? OR email=?',(nid,email)).fetchone(): return fail('NID or email is already registered.',409)
        try:
            cur=c.execute('INSERT INTO voters(full_name,guardian_name,nid,division,district,upazila,ward,email,primary_phone,secondary_phone,password_hash,duress_password_hash,otp_verified_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)',(full,guardian,nid,division,district,upazila,ward,email,primary_phone,secondary_phone,generate_password_hash(pw),generate_password_hash(dpw)))
            voter_id = cur.lastrowid
            folder = NID_STORAGE / secrets.token_hex(16)
            folder.mkdir(mode=0o700, parents=True, exist_ok=False)
            front_name = 'front' + front_ext
            back_name = 'back' + back_ext
            try:
                front.save(folder / front_name)
                back.save(folder / back_name)
                c.execute('INSERT INTO nid_documents(voter_id,front_path,back_path,status) VALUES(?,?,?,?)',
                          (voter_id, str((folder/front_name).resolve()), str((folder/back_name).resolve()), 'pending'))
                c.execute("UPDATE otp_codes SET purpose='registration_used',verified_at=COALESCE(verified_at,CURRENT_TIMESTAMP) WHERE id=?",(r['id'],))
                c.commit()
            except Exception:
                c.rollback()
                shutil.rmtree(folder, ignore_errors=True)
                raise
            audit(c, 'nid_documents_submitted', voter_id, 'NID images submitted for administrator review')
            c.commit()
            return out({'success':True,'message':'Registration completed. NID images are saved securely and await administrator review.','voter_id':voter_id,'nid_verification_status':'pending'},201)
        except sqlite3.IntegrityError: return fail('NID or email is already registered.',409)

@app.route('/api/login.php', methods=['POST'])
@csrf_required
def login():
    nid=normalize_digits(value('nid')); pw=value('password')
    if not valid_nid(nid) or len(pw)!=8 or not pw.isdigit(): return fail('Invalid credentials.',422)
    with db() as c:
        v=c.execute('SELECT * FROM voters WHERE nid=? AND is_registered=1',(nid,)).fetchone()
        if not v or not (check_password_hash(v['password_hash'],pw) or check_password_hash(v['duress_password_hash'],pw)): return fail('Invalid NID or password.',401)
        duress=check_password_hash(v['duress_password_hash'],pw) and not check_password_hash(v['password_hash'],pw)
        session.clear(); session['csrf_token']=secrets.token_urlsafe(32); session.update(voter_id=v['id'],role='voter',duress_mode=duress,face_verified=False)
        audit(c,'duress_login' if duress else 'login_success',v['id']); c.commit()
        return out({'success':True,'message':'Login successful.','duress_mode':duress,'voter':{k:v[k] for k in ['id','full_name','nid','division','district','upazila','ward','has_voted','face_status']}})

@app.route('/api/logout.php', methods=['POST','GET'])
def logout(): session.clear(); return out({'success':True,'message':'Logged out.'})
@app.route('/api/me.php', methods=['GET'])
def me():
    if session.get('role')=='admin': return out({'success':True,'role':'admin'})
    if not session.get('voter_id'): return fail('Not logged in.',401)
    with db() as c:
        v=c.execute('SELECT id,full_name,nid,division,district,upazila,ward,has_voted FROM voters WHERE id=?',(session['voter_id'],)).fetchone()
        return out({'success':True,'role':'voter','voter':dict(v) if v else None,'duress_mode':bool(session.get('duress_mode'))})

@app.route('/api/admin-login.php', methods=['POST'])
@csrf_required
def admin_login():
    if not ADMIN_TOKEN or not secrets.compare_digest(str(value('token')).strip(),ADMIN_TOKEN): return fail('Invalid admin credentials.',401)
    session.clear(); session['csrf_token']=secrets.token_urlsafe(32); session['role']='admin'; return out({'success':True,'message':'Admin authentication successful.'})

@app.route('/api/candidates.php', methods=['GET','POST','DELETE'])
def candidates():
    if request.method=='GET':
        fields=['position','division','district','upazila','ward']; sql="SELECT * FROM candidates WHERE status='active'"; args=[]
        for f in fields:
            v=request.args.get(f,'').strip()
            if v: sql+=f' AND {f}=?'; args.append(v)
        with db() as c: rows=[dict(r) for r in c.execute(sql+' ORDER BY id DESC',args).fetchall()]
        return out({'success':True,'candidates':rows})
    if session.get('role')!='admin': return fail('Admin login required.',401)
    if not check_csrf(): return fail('Security token expired. Refresh the page.',403)
    if request.method=='DELETE':
        try: candidate_id=int(request.args.get('id','0'))
        except ValueError: candidate_id=0
        if candidate_id < 1: return fail('Valid candidate id is required.',422)
        with db() as c:
            row=c.execute('SELECT id FROM candidates WHERE id=?',(candidate_id,)).fetchone()
            if not row: return fail('Candidate not found.',404)
            votes=c.execute('SELECT COUNT(*) FROM votes WHERE candidate_id=?',(candidate_id,)).fetchone()[0]
            if votes: c.execute("UPDATE candidates SET status='inactive' WHERE id=?",(candidate_id,)); message='Candidate deactivated because votes are recorded.'
            else: c.execute('DELETE FROM candidates WHERE id=?',(candidate_id,)); message='Candidate deleted.'
            audit(c,'candidate_deleted' if not votes else 'candidate_deactivated',details=f'candidate_id={candidate_id}'); c.commit()
        return out({'success':True,'message':message})
    d=request.form; name=d.get('name','').strip(); party=d.get('party','').strip()
    if not name or not party: return fail('Name and party are required.',422)
    paths={}
    for field in ('photo','symbol'):
        f=request.files.get(field)
        if f and f.filename:
            ext=Path(secure_filename(f.filename)).suffix.lower()
            if ext not in ('.jpg','.jpeg','.png','.webp') or len(f.read())>2*1024*1024: return fail('Candidate images must be JPG, PNG or WEBP and 2 MB or smaller.',422)
            f.stream.seek(0); folder=UPLOADS/'candidates'; folder.mkdir(exist_ok=True); namefile=secrets.token_hex(16)+ext; f.save(folder/namefile); paths[field]='uploads/candidates/'+namefile
    with db() as c:
        cur=c.execute('INSERT INTO candidates(name,party,symbol,position,division,district,upazila,ward,photo,status) VALUES(?,?,?,?,?,?,?,?,?,?)',(name,party,paths.get('symbol',d.get('symbol','')),d.get('position','Member'),d.get('division') or None,d.get('district') or None,d.get('upazila') or None,d.get('ward') or None,paths.get('photo'),'active')); c.commit()
        return out({'success':True,'message':'Candidate added successfully.','candidate_id':cur.lastrowid},201)

@app.route('/api/election-control.php', methods=['GET','POST'])
@admin_required
def election_control():
    with db() as c:
        if request.method=='GET':
            r=c.execute('SELECT * FROM election_control ORDER BY id DESC LIMIT 1').fetchone(); return out({'success':True,'election':dict(r) if r else None})
        if not check_csrf(): return fail('Security token expired. Refresh the page.',403)
        d=body(); action=d.get('action'); name=d.get('election_name','National Digital Election')
        r=c.execute('SELECT id FROM election_control ORDER BY id DESC LIMIT 1').fetchone()
        if not r: cur=c.execute('INSERT INTO election_control(election_name,is_running) VALUES(?,0)',(name,)); eid=cur.lastrowid
        else: eid=r['id']
        if action=='start': c.execute("UPDATE election_control SET election_name=?,is_running=1,start_time=CURRENT_TIMESTAMP,end_time=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?",(name,eid))
        elif action=='stop': c.execute("UPDATE election_control SET is_running=0,end_time=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?",(eid,))
        elif action=='schedule':
            start=d.get('start_time'); end=d.get('end_time')
            if not start or not end or start>=end: return fail('Valid start_time and end_time are required.',422)
            c.execute('UPDATE election_control SET election_name=?,is_running=0,start_time=?,end_time=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',(name,start,end,eid))
        else: return fail('Invalid election action.',422)
        audit(c,'election_'+action); c.commit(); return out({'success':True,'message':'Election control updated.'})

@app.route('/api/vote.php', methods=['POST'])
@voter_required
@csrf_required
def vote():
    if session.get('duress_mode'): return fail('Voting is unavailable in duress mode.',403)
    try: cid=int(value('candidate_id','0'))
    except ValueError: cid=0
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        e=c.execute('SELECT * FROM election_control ORDER BY id DESC LIMIT 1').fetchone()
        if not e or not e['is_running']: c.rollback(); return fail('Voting is not currently open.',403)
        if e['end_time'] and e['end_time'] < datetime.now().strftime('%Y-%m-%d %H:%M:%S'): c.rollback(); return fail('Voting period has ended.',403)
        v=c.execute('SELECT * FROM voters WHERE id=?',(session['voter_id'],)).fetchone()
        if not v or v['has_voted']: c.rollback(); return fail('A vote has already been recorded for this voter.',409)
        if not session.get('face_verified') or not v['face_verified_at']: c.rollback(); return fail('Complete face verification after login before voting.',403)
        approvals=c.execute("SELECT status FROM nid_documents WHERE voter_id=?",(v['id'],)).fetchone()
        if not approvals or approvals['status']!='approved' or v['face_status']!='approved': c.rollback(); return fail('Voting is blocked until an administrator approves both NID and face registration.',403)
        if not v['face_image_path']: c.rollback(); return fail('Face registration is required before voting.',403)
        cand=c.execute("SELECT id FROM candidates WHERE id=? AND status='active' AND (division IS NULL OR division='' OR division=?) AND (district IS NULL OR district='' OR district=?) AND (upazila IS NULL OR upazila='' OR upazila=?) AND (ward IS NULL OR ward='' OR ward=?)",(cid,v['division'],v['district'],v['upazila'],v['ward'])).fetchone()
        if not cand: c.rollback(); return fail('Candidate is not available for your voting area.',403)
        try: c.execute('INSERT INTO votes(voter_id,candidate_id,division,district,upazila,ward) VALUES(?,?,?,?,?,?)',(v['id'],cid,v['division'],v['district'],v['upazila'],v['ward']))
        except sqlite3.IntegrityError: c.rollback(); return fail('A vote has already been recorded.',409)
        c.execute('UPDATE voters SET has_voted=1 WHERE id=?',(v['id'],)); receipt=hashlib.sha256(f"{v['id']}|{cid}|{e['id']}|{secrets.token_hex(16)}".encode()).hexdigest(); audit(c,'vote_cast',v['id'],f'election_id={e["id"]}'); c.commit()
        return out({'success':True,'message':'Vote submitted successfully.','receipt_hash':receipt})

@app.get('/api/vote-count.php')
def vote_count():
    division=request.args.get('division','').strip()
    district=request.args.get('district','').strip()
    upazila=request.args.get('upazila','').strip()
    ward=request.args.get('ward','').strip()
    clauses=[]; params=[]
    for col,val in [('division',division),('district',district),('upazila',upazila),('ward',ward)]:
        if val:
            clauses.append(f"v.{col}=?"); params.append(val)
    where=(' WHERE '+' AND '.join(clauses)) if clauses else ''
    with db() as c:
        stats=dict(c.execute('SELECT COUNT(*) total_votes,COUNT(*) valid_votes,0 cancelled_votes FROM votes v'+where,params).fetchone())
        stats['registered_voters']=c.execute('SELECT COUNT(*) FROM voters WHERE is_registered=1'+((' AND '+' AND '.join(x.replace('v.','') for x in clauses)) if clauses else ''),params).fetchone()[0]
        rows=[dict(r) for r in c.execute("SELECT c.id,c.name,c.party,c.symbol,COUNT(v.id) votes FROM candidates c LEFT JOIN votes v ON v.candidate_id=c.id"+((' AND '+' AND '.join(clauses)) if clauses else '')+" WHERE c.status='active' GROUP BY c.id ORDER BY votes DESC,c.id",params).fetchall()]
    return out({'success':True,'stats':stats,'total_votes':stats['total_votes'],'valid_votes':stats['valid_votes'],'candidate_count':len(rows),'candidates':rows,'results':rows})

@app.get('/api/notices.php')
def notices():
    with db() as c: rows=[dict(r) for r in c.execute('SELECT id,title,message,file_path,created_at FROM notices ORDER BY id DESC').fetchall()]
    return out({'success':True,'notices':rows})

@app.route('/api/notice-upload.php',methods=['POST'])
@admin_required
@csrf_required
def notice_upload():
    title=value('title').strip(); message=value('message').strip()
    if not title or not message: return fail('Title and message are required.',422)
    f=request.files.get('notice_file'); path=None
    if f and f.filename:
        ext=Path(secure_filename(f.filename)).suffix.lower()
        if ext not in ('.pdf','.jpg','.jpeg','.png'): return fail('Only PDF/JPG/PNG files are allowed.',422)
        folder=UPLOADS/'notices'; folder.mkdir(exist_ok=True); fn=secrets.token_hex(16)+ext; f.save(folder/fn); path='uploads/notices/'+fn
    with db() as c:
        cur=c.execute('INSERT INTO notices(title,message,file_path,created_by) VALUES(?,?,?,?)',(title,message,path,'admin')); c.commit()
    return out({'success':True,'message':'Notice uploaded successfully.','notice_id':cur.lastrowid},201)

@app.route('/api/nid_verify.php',methods=['POST'])
@csrf_required
def nid_verify():
    nid=normalize_digits(value('nid'))
    if not valid_nid(nid): return fail('NID must contain 10, 13 or 17 digits.',422,verified=False)
    with db() as c: exists=c.execute('SELECT id FROM voters WHERE nid=?',(nid,)).fetchone()
    return out({'success':True,'verified':not bool(exists),'message':'This NID is already registered.' if exists else 'NID format is valid and it is not registered yet. Official authority verification is not connected.'})

@app.post('/api/face-enrollment.php')
@voter_required
@csrf_required
def face_enrollment():
    image=request.files.get('face_image')
    if not image or not image.filename: return fail('Capture and upload a face photo.',422)
    ext, error=validate_nid_image(image)
    if error: return fail('Face photo: '+error,422)
    try:
        descriptor=json.loads(value('face_descriptor',''))
        if not isinstance(descriptor,list) or len(descriptor)!=128 or any(not isinstance(x,(int,float)) or not (-10 <= float(x) <= 10) for x in descriptor):
            raise ValueError()
        descriptor_json=json.dumps([float(x) for x in descriptor],separators=(',',':'))
    except (ValueError,TypeError,json.JSONDecodeError):
        return fail('Face model could not produce a valid face descriptor. Ensure one clear face is visible and try again.',422)
    folder=NID_STORAGE / ('face_'+secrets.token_hex(16)); folder.mkdir(mode=0o700,parents=True,exist_ok=False)
    path=folder/('face'+ext)
    try:
        image.save(path)
        with db() as c:
            c.execute("UPDATE voters SET face_image_path=?,face_descriptor=?,face_status='pending',face_enrolled_at=CURRENT_TIMESTAMP,face_reviewed_at=NULL,face_verified_at=NULL WHERE id=?",(str(path.resolve()),descriptor_json,session['voter_id']))
            audit(c,'face_enrollment_submitted',session['voter_id'],'Face photo and descriptor submitted for administrator review'); c.commit()
    except Exception:
        shutil.rmtree(folder,ignore_errors=True)
        raise
    session['face_verified']=False
    return out({'success':True,'message':'Face photo and face template submitted. Voting remains blocked until administrator approval.'},201)

@app.post('/api/face-verify.php')
@voter_required
@csrf_required
def face_verify():
    if session.get('duress_mode'): return fail('Face verification is unavailable in duress mode.',403)
    try:
        probe=json.loads(value('face_descriptor',''))
        if not isinstance(probe,list) or len(probe)!=128 or any(not isinstance(x,(int,float)) or not (-10 <= float(x) <= 10) for x in probe): raise ValueError()
    except (ValueError,TypeError,json.JSONDecodeError):
        return fail('Could not read a face. Keep one face clearly visible and try again.',422)
    with db() as c:
        v=c.execute('SELECT id,face_descriptor,face_status,face_image_path,face_verified_at FROM voters WHERE id=? AND is_registered=1',(session['voter_id'],)).fetchone()
        if not v or v['face_status']!='approved' or not v['face_image_path'] or not v['face_descriptor']:
            session['face_verified']=False
            return fail('Face registration must be submitted and approved by an administrator before verification.',403)
        try:
            enrolled=json.loads(v['face_descriptor'])
            if len(enrolled)!=128: raise ValueError()
            distance=sum((float(a)-float(b))**2 for a,b in zip(enrolled,probe))**0.5
        except (ValueError,TypeError,json.JSONDecodeError):
            return fail('Stored face template is invalid. Please contact the administrator.',500)
        # face-api.js descriptors are 128-dimensional; 0.50 is a conservative prototype threshold.
        if distance >= 0.50:
            session['face_verified']=False
            c.execute('UPDATE voters SET face_verified_at=NULL WHERE id=?',(v['id'],)); c.commit()
            audit(c,'face_verification_failed',v['id'],f'distance={distance:.4f}'); c.commit()
            return fail('Face does not match the registered face. Voting is not allowed.',403)
        c.execute('UPDATE voters SET face_verified_at=CURRENT_TIMESTAMP WHERE id=?',(v['id'],))
        audit(c,'face_verification_success',v['id'],f'distance={distance:.4f}'); c.commit()
        session['face_verified']=True
        return out({'success':True,'message':'Face matched. You may continue to the ballot.'})

@app.get('/api/admin/face-image.php')
@admin_required
def admin_face_image():
    try: voter_id=int(request.args.get('voter_id','0'))
    except ValueError: voter_id=0
    with db() as c: row=c.execute('SELECT face_image_path FROM voters WHERE id=?',(voter_id,)).fetchone()
    if not row or not row['face_image_path']: return fail('Face image not found.',404)
    target=Path(row['face_image_path']).resolve()
    try: target.relative_to(NID_STORAGE.resolve())
    except ValueError: return fail('Invalid private file reference.',403)
    if not target.is_file(): return fail('Face image unavailable.',404)
    return send_file(target,mimetype=mimetypes.guess_type(target.name)[0] or 'application/octet-stream',max_age=0)

@app.post('/api/admin/face-decision.php')
@admin_required
@csrf_required
def admin_face_decision():
    try: voter_id=int(value('voter_id','0'))
    except ValueError: voter_id=0
    decision=value('decision').strip().lower()
    if decision not in ('approved','rejected'): return fail('Choose approve or reject.',422)
    with db() as c:
        row=c.execute('SELECT id FROM voters WHERE id=? AND face_image_path IS NOT NULL',(voter_id,)).fetchone()
        if not row: return fail('Face registration not found.',404)
        c.execute('UPDATE voters SET face_status=?,face_reviewed_at=CURRENT_TIMESTAMP WHERE id=?',(decision,voter_id))
        audit(c,'face_registration_'+decision,voter_id); c.commit()
    return out({'success':True,'message':'Face registration '+decision+'.'})

@app.get('/api/admin/report.pdf')
@admin_required
def admin_report_pdf():
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.colors import HexColor
    output=BytesIO(); pdf=canvas.Canvas(output,pagesize=A4); width,height=A4; y=height-48
    pdf.setTitle('Dual-Auth Vote - Election Report')
    pdf.setFillColor(HexColor('#006A4E')); pdf.rect(0,height-70,width,70,fill=1,stroke=0)
    pdf.setFillColor(HexColor('#F42A41')); pdf.rect(0,height-75,width,5,fill=1,stroke=0)
    pdf.setFillColor(HexColor('#FFFFFF')); pdf.setFont('Helvetica-Bold',17); pdf.drawString(40,height-43,'DUAL-AUTH VOTE')
    pdf.setFillColor(HexColor('#1E40AF')); pdf.setFont('Helvetica-Bold',14); pdf.drawString(40,height-105,'ELECTION REPORT')
    y=height-130
    with db() as c:
        stats=c.execute('SELECT COUNT(*) total_votes FROM votes').fetchone()['total_votes']
        registered=c.execute('SELECT COUNT(*) FROM voters WHERE is_registered=1').fetchone()[0]
        pdf.setFont('Helvetica',10); pdf.drawString(40,y,f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'); y-=18
        pdf.drawString(40,y,f'Registered voters: {registered}    Total votes: {stats}'); y-=28
        rows=c.execute('SELECT c.name,c.party,COUNT(v.id) votes FROM candidates c LEFT JOIN votes v ON v.candidate_id=c.id GROUP BY c.id ORDER BY votes DESC,c.id').fetchall()
        pdf.setFont('Helvetica-Bold',11); pdf.drawString(40,y,'Candidate'); pdf.drawString(310,y,'Party'); pdf.drawString(500,y,'Votes'); y-=18
        pdf.setFont('Helvetica',10)
        for r in rows:
            if y<55: pdf.showPage(); y=height-48; pdf.setFont('Helvetica',10)
            pdf.drawString(40,y,str(r['name'])[:38]); pdf.drawString(310,y,str(r['party'])[:25]); pdf.drawRightString(530,y,str(r['votes'])); y-=16
        y-=10; pdf.setFont('Helvetica-Bold',11); pdf.drawString(40,y,'Vote records (private administrative report)'); y-=18; pdf.setFont('Helvetica',8)
        records=c.execute('SELECT v.id,v.nid,v.full_name,vo.candidate_id,vo.cast_at FROM votes vo JOIN voters v ON v.id=vo.voter_id ORDER BY vo.cast_at').fetchall()
        for r in records:
            if y<45: pdf.showPage(); y=height-45; pdf.setFont('Helvetica',8)
            pdf.drawString(40,y,f"Vote #{r['id']} | {r['full_name'][:24]} | NID {r['nid']} | candidate id {r['candidate_id']} | {r['cast_at']}"); y-=12
    pdf.save(); output.seek(0)
    response=send_file(output,mimetype='application/pdf',as_attachment=True,download_name='dual-auth-voting-report.pdf')
    response.headers['Cache-Control']='no-store, private'; return response

@app.get('/api/vote-receipt.pdf')
@voter_required
def voter_receipt_pdf():
    from io import BytesIO
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.colors import HexColor
    with db() as c:
        row=c.execute("""SELECT v.full_name,v.nid,v.face_image_path,v.has_voted,vo.id,vo.cast_at,
                              vo.division,vo.district,vo.upazila,vo.ward
                         FROM voters v LEFT JOIN votes vo ON vo.voter_id=v.id
                         WHERE v.id=?""",(session['voter_id'],)).fetchone()
    if not row or not row['has_voted'] or not row['id']: return fail('No recorded vote receipt is available.',404)
    output=BytesIO(); pdf=canvas.Canvas(output,pagesize=A4); pdf.setTitle('Dual-Auth Vote Receipt')
    pdf.setFillColor(HexColor('#006A4E')); pdf.rect(0,785,595,57,fill=1,stroke=0)
    pdf.setFillColor(HexColor('#F42A41')); pdf.rect(0,780,595,5,fill=1,stroke=0)
    pdf.setFillColor(HexColor('#FFFFFF')); pdf.setFont('Helvetica-Bold',17); pdf.drawString(42,808,'DUAL-AUTH VOTE')
    pdf.setFillColor(HexColor('#1E40AF')); pdf.setFont('Helvetica-Bold',15); pdf.drawString(42,744,'VOTE SUBMISSION RECEIPT')
    pdf.setStrokeColor(HexColor('#006A4E')); pdf.roundRect(35,510,525,205,12,stroke=1,fill=0)
    pdf.setFillColor(HexColor('#222222')); pdf.setFont('Helvetica-Bold',11); pdf.drawString(52,680,'Voter: '+str(row['full_name'])[:55])
    pdf.setFont('Helvetica',10); pdf.drawString(52,654,'NID (masked): '+('*' * max(0,len(str(row['nid']))-4))+str(row['nid'])[-4:])
    pdf.drawString(52,630,'Receipt reference: DAV-'+str(row['id']).zfill(8))
    pdf.drawString(52,606,'Submitted at: '+str(row['cast_at']))
    pdf.drawString(52,582,'Voting area: '+', '.join(str(row[k] or '') for k in ('upazila','district','division'))[:70])
    pdf.setFillColor(HexColor('#1E40AF')); pdf.setFont('Helvetica-Bold',10)
    pdf.drawString(52,540,'This receipt confirms submission only; it does not reveal the selected candidate.')
    image_path=Path(row['face_image_path']) if row['face_image_path'] else None
    if image_path and image_path.is_file():
        try:
            from reportlab.lib.utils import ImageReader
            pdf.drawImage(ImageReader(str(image_path)),390,565,width=130,height=125,preserveAspectRatio=True,anchor='c',mask='auto')
            pdf.setFillColor(HexColor('#006A4E')); pdf.setFont('Helvetica',8); pdf.drawCentredString(455,552,'Verification photo')
        except Exception: pass
    pdf.setFillColor(HexColor('#F42A41')); pdf.rect(35,55,525,4,fill=1,stroke=0)
    pdf.setFillColor(HexColor('#006A4E')); pdf.setFont('Helvetica',9); pdf.drawString(42,38,'Green • Red • Blue | Keep this receipt for your records.')
    pdf.save(); output.seek(0)
    return send_file(output,mimetype='application/pdf',as_attachment=True,download_name='dual-auth-vote-receipt.pdf')

@app.get('/api/admin/nid-submissions.php')
@admin_required
def admin_nid_submissions():
    with db() as c:
        rows = c.execute('''SELECT d.id, d.voter_id, d.status, d.rejection_reason, d.uploaded_at,
                                   d.reviewed_at, v.full_name, v.guardian_name, v.primary_phone, v.secondary_phone, v.nid, v.email, v.division, v.district, v.upazila, v.ward, v.face_status, v.face_image_path
                            FROM nid_documents d JOIN voters v ON v.id=d.voter_id
                            ORDER BY CASE d.status WHEN 'pending' THEN 0 ELSE 1 END, d.uploaded_at DESC''').fetchall()
    return out({'success':True,'submissions':[dict(r) for r in rows]})

@app.get('/api/admin/nid-image.php')
@admin_required
def admin_nid_image():
    try: doc_id = int(request.args.get('id', '0'))
    except ValueError: doc_id = 0
    side = request.args.get('side', 'front')
    if side not in ('front', 'back'): return fail('Invalid image side.', 422)
    with db() as c:
        row = c.execute(f'SELECT {side}_path AS path FROM nid_documents WHERE id=?', (doc_id,)).fetchone()
    if not row: return fail('NID submission not found.', 404)
    target = Path(row['path']).resolve()
    try: target.relative_to(NID_STORAGE.resolve())
    except ValueError: return fail('Invalid private file reference.', 403)
    if not target.is_file(): return fail('NID image file is unavailable.', 404)
    response = send_file(target, mimetype=mimetypes.guess_type(target.name)[0] or 'application/octet-stream', as_attachment=False, max_age=0)
    response.headers['Cache-Control'] = 'no-store, private'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.post('/api/admin/nid-decision.php')
@admin_required
@csrf_required
def admin_nid_decision():
    try: doc_id = int(value('id', '0'))
    except ValueError: doc_id = 0
    decision = value('decision').strip().lower()
    reason = value('reason').strip()[:500]
    if decision not in ('approved', 'rejected'): return fail('Choose approve or reject.', 422)
    if decision == 'rejected' and not reason: return fail('A rejection reason is required.', 422)
    with db() as c:
        row = c.execute('SELECT voter_id FROM nid_documents WHERE id=?', (doc_id,)).fetchone()
        if not row: return fail('NID submission not found.', 404)
        c.execute('UPDATE nid_documents SET status=?, rejection_reason=?, reviewed_by=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=?',
                  (decision, reason if decision == 'rejected' else None, 'admin', doc_id))
        audit(c, 'nid_document_' + decision, row['voter_id'], reason)
        c.commit()
    return out({'success':True,'message':'NID submission ' + decision + '.'})

@app.route('/api/verify-otp.php',methods=['GET'])
def otp_method(): return fail('POST method required.',405)

@app.errorhandler(413)
def too_large(_): return fail('Upload is too large. Maximum request size is 12 MB.',413)
@app.errorhandler(500)
def server_error(e): app.logger.exception('Unhandled application error'); return fail('Unexpected server error. Check the Flask terminal for details.',500)

if __name__=='__main__':
    print('Dual-Auth Vote Python backend starting. Development OTPs print in this terminal unless SMTP is configured.')
    print('Open http://127.0.0.1:8000')
    app.run(host=os.getenv('HOST','127.0.0.1'),port=int(os.getenv('PORT','8000')),debug=os.getenv('FLASK_DEBUG','0')=='1')
