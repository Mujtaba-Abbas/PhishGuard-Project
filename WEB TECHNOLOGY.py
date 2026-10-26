from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
import sqlite3, os, re, json, io, secrets, hashlib, hmac, urllib.request, urllib.error
from urllib.parse import urlparse
from datetime import datetime
from functools import wraps
from email.parser import Parser
from email.policy import default

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.secret_key = os.environ.get('PHISHGUARD_SECRET_KEY') or 'change-this-development-secret-before-deployment'
DB_PATH = os.path.join(BASE, 'phishguard.db')
GOOGLE_SAFE_BROWSING_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_KEY', '').strip()

# Passwords are salted and hashed. First run creates a demo admin account; change it before deployment.
def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 240000).hex()
    return f'{salt}${digest}'
def verify_password(password, stored):
    try:
        salt, digest = stored.split('$', 1)
        return hmac.compare_digest(hash_password(password, salt).split('$',1)[1], digest)
    except Exception: return False

def db():
    conn=sqlite3.connect(DB_PATH); conn.row_factory=sqlite3.Row; return conn
def init_db():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, scan_type TEXT NOT NULL, input_text TEXT NOT NULL, risk_score INTEGER NOT NULL, threat_level TEXT NOT NULL, indicators TEXT NOT NULL, result_json TEXT NOT NULL DEFAULT '{}', source TEXT NOT NULL DEFAULT 'Rule-based heuristic', scanned_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));
        CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, url TEXT NOT NULL, details TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'Pending', created_at TEXT NOT NULL);
        ''')
        if not c.execute("SELECT id FROM users WHERE username='admin'").fetchone():
            c.execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)', ('admin',hash_password(os.environ.get('PHISHGUARD_ADMIN_PASSWORD','ChangeMe123!')),'admin',now()))
def now(): return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
def level_for(score): return 'Safe' if score < 10 else 'Low' if score < 25 else 'Medium' if score < 50 else 'High' if score < 75 else 'Critical'
def recs(level):
    return {'Safe':['No common warning signs were detected by the configured checks. This is not proof of safety.','Verify important requests through an official channel.'],'Low':['Verify the sender and destination independently.','Avoid entering sensitive information unless you trust the destination.'],'Medium':['Do not click links until you verify the sender and destination.','Open services by typing their official address yourself.'],'High':['Do not open links or attachments from this content.','Verify through a known official channel and report suspicious content.'],'Critical':['Treat this content as highly suspicious. Do not interact with it.','Do not enter credentials, payment details, or authentication codes.','Report the content to the relevant service or security team.']}[level]
def result(score, indicators, source='Rule-based heuristic'):
    score=max(0,min(100,int(score))); level=level_for(score)
    if not indicators: indicators=[{'label':'No obvious rule-based indicators','explanation':'The configured checks did not find common warning signs. This does not guarantee safety.','points':0}]
    return {'score':score,'level':level,'indicators':indicators,'recommendations':recs(level),'source':source}
def assess_url(raw):
    text=(raw or '').strip(); candidate=text if '://' in text else 'http://'+text
    try: parsed=urlparse(candidate); host=(parsed.hostname or '').lower()
    except Exception: host=''
    score=0; ind=[]
    def flag(p,l,e):
        nonlocal score; score+=p; ind.append({'label':l,'explanation':e,'points':p})
    if not text: return result(0,[], 'Rule-based heuristic')
    if len(text)>100: flag(10,'Unusually long URL','Long URLs can make the true destination harder to recognize.')
    if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}',host): flag(25,'IP-based address','The host is an IP address rather than a conventional domain.')
    if host.count('.')>=3: flag(10,'Multiple subdomains','Several subdomain levels may disguise the actual domain.')
    if '@' in text: flag(20,'At-sign in URL','An at-sign can make text before it look like the destination when it is not.')
    if any(x in text.lower() for x in ['login','verify','update','secure','account','password','banking','confirm','wallet']): flag(10,'Sensitive-action keyword','The URL includes terms often used in account or verification lures.')
    if any(x in text for x in ['%','~','\\']): flag(5,'Unusual characters','Special characters can sometimes obscure a URL.')
    if not candidate.lower().startswith('https://'): flag(10,'HTTPS not detected','The URL does not use HTTPS. This alone does not prove phishing.')
    if host.startswith('xn--') or '.xn--' in host: flag(15,'Punycode domain','Internationalized domains can sometimes imitate familiar names.')
    if not host or '.' not in host: flag(10,'Unusual domain structure','A recognizable public domain could not be identified.')
    return result(score,ind)
def assess_email(text):
    t=(text or '').strip(); low=t.lower(); score=0; ind=[]
    def flag(p,l,e):
        nonlocal score; score+=p; ind.append({'label':l,'explanation':e,'points':p})
    if any(x in low for x in ['immediately','urgent','act now','within 24 hours','account suspended','final warning','limited time']): flag(15,'Urgent or threatening language','The message pressures the reader to act quickly.')
    if any(x in low for x in ['password','verify your account','login','sign in','bank details','credit card','social security']): flag(20,'Sensitive information terms','The message mentions account access or personal/financial information.')
    if any(x in low for x in ['you have won','winner','claim your prize','free gift','lottery']): flag(15,'Prize or reward language','Unexpected prizes are commonly used in scam messages.')
    links=re.findall(r'https?://[^\s<>]+|www\.[^\s<>]+',t,re.I)
    if links: flag(10,'Links included',f'Found {len(links)} link(s). Inspect each destination before opening.')
    for link in links[:5]:
        u=assess_url(link)
        if u['score']>=25: flag(15,'Potentially suspicious link',f'An included link triggered URL warning signs: {link[:100]}'); break
    if 'dear customer' in low or 'dear user' in low: flag(5,'Generic greeting','Generic greetings can be suspicious in messages claiming to be personalized.')
    if re.search(r'\b(send|share|reply with)\b.{0,35}\b(password|pin|otp|code)\b',low): flag(25,'Request for secret credentials','Legitimate services generally should not ask you to send passwords or one-time codes by email.')
    return result(score,ind)
def analyze_headers(raw):
    msg=Parser(policy=default).parsestr(raw or '')
    get=lambda k: str(msg.get(k,'Not provided'))
    fromv=get('From'); reply=get('Reply-To'); return_path=get('Return-Path'); subject=get('Subject')
    auth=get('Authentication-Results'); received_spf=get('Received-SPF')
    score=0; ind=[]
    def flag(p,l,e):
        nonlocal score; score+=p; ind.append({'label':l,'explanation':e,'points':p})
    if fromv=='Not provided': flag(10,'Missing From header','No From header was found in the supplied text.')
    if reply!='Not provided' and fromv!='Not provided' and reply.lower()!=fromv.lower(): flag(20,'Reply-To differs from From','A different reply address can be legitimate, but should be verified.')
    authlow=(auth+' '+received_spf).lower()
    if 'fail' in authlow: flag(25,'Authentication failure reported','The supplied headers contain an SPF/DKIM/DMARC or authentication failure indicator.')
    elif auth=='Not provided' and received_spf=='Not provided': ind.append({'label':'Authentication result unavailable','explanation':'No Authentication-Results or Received-SPF header was supplied; authentication cannot be assessed.','points':0})
    if re.search(r'\b(urgent|verify|suspended|password|payment)\b',subject,re.I): flag(10,'Sensitive subject wording','The subject includes urgency or account-related wording.')
    result_obj=result(score,ind,'Email header inspection (user-supplied headers only)')
    result_obj['header_details']={'From':fromv,'Reply-To':reply,'Return-Path':return_path,'Subject':subject,'Authentication-Results':auth,'Received-SPF':received_spf}
    return result_obj

def safe_browsing(url):
    if not GOOGLE_SAFE_BROWSING_KEY: return {'configured':False,'status':'Not checked','message':'No Google Safe Browsing API key configured. Only local rule-based checks were used.'}
    payload=json.dumps({'client':{'clientId':'PhishGuardStudentProject','clientVersion':'1.0'},'threatInfo':{'threatTypes':['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],'platformTypes':['ANY_PLATFORM'],'threatEntryTypes':['URL'],'threatEntries':[{'url':url}]}}).encode()
    req=urllib.request.Request('https://safebrowsing.googleapis.com/v4/threatMatches:find?key='+GOOGLE_SAFE_BROWSING_KEY,data=payload,headers={'Content-Type':'application/json'},method='POST')
    try:
        with urllib.request.urlopen(req,timeout=8) as resp: data=json.loads(resp.read().decode())
        matches=data.get('matches',[])
        if matches: return {'configured':True,'status':'Match found','message':'Google Safe Browsing returned one or more threat matches. Treat this URL as dangerous.','matches':[m.get('threatType','Unknown') for m in matches]}
        return {'configured':True,'status':'No match returned','message':'No match was returned by this lookup. This does not guarantee the URL is safe.','matches':[]}
    except Exception as e:
        return {'configured':True,'status':'Lookup error','message':'The external lookup failed (network, key, quota, or API setup). Rule-based results are shown separately.','error':type(e).__name__}
def save_scan(kind, content, res):
    uid=session.get('user_id')
    with db() as c:
        cur=c.execute('INSERT INTO scans(user_id,scan_type,input_text,risk_score,threat_level,indicators,result_json,source,scanned_at) VALUES(?,?,?,?,?,?,?,?,?)',(uid,kind,content[:5000],res['score'],res['level'],json.dumps([i['label'] for i in res['indicators']]),json.dumps(res),res.get('source','Rule-based heuristic'),now()))
        return cur.lastrowid
def login_required(f):
    @wraps(f)
    def inner(*a,**kw):
        if not session.get('user_id'): flash('Please sign in to access that page.','warning'); return redirect(url_for('login',next=request.path))
        return f(*a,**kw)
    return inner
def admin_required(f):
    @wraps(f)
    def inner(*a,**kw):
        if not session.get('user_id'): return redirect(url_for('login',next=request.path))
        if session.get('role')!='admin': flash('Admin access is required.','danger'); return redirect(url_for('index'))
        return f(*a,**kw)
    return inner
@app.context_processor
def context(): return {'current_user':session.get('username'),'current_role':session.get('role')}
@app.route('/')
def index():
    with db() as c:
        total=c.execute('SELECT COUNT(*) FROM scans').fetchone()[0]; threats=c.execute("SELECT COUNT(*) FROM scans WHERE threat_level IN ('High','Critical')").fetchone()[0]
        high=c.execute("SELECT COUNT(*) FROM scans WHERE threat_level IN ('Medium','High','Critical')").fetchone()[0]
        recent=c.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 8').fetchall()
        levels={r['threat_level']:r['n'] for r in c.execute('SELECT threat_level,COUNT(*) n FROM scans GROUP BY threat_level').fetchall()}
    return render_template('index.html',total=total,threats=threats,high=high,recent=recent,levels=levels,api_configured=bool(GOOGLE_SAFE_BROWSING_KEY))
@app.route('/scan',methods=['POST'])
def scan():
    data=request.get_json(silent=True) or request.form; kind=data.get('scan_type','url'); content=(data.get('content') or '').strip()
    if not content: return jsonify({'error':'Please enter content to analyze.'}),400
    if kind=='email': res=assess_email(content)
    elif kind=='headers': res=analyze_headers(content)
    else:
        res=assess_url(content); ext=safe_browsing(content); res['threat_intelligence']=ext
        if ext.get('status')=='Match found':
            res['indicators'].append({'label':'External threat-intelligence match','explanation':ext['message'],'points':0}); res['score']=max(res['score'],85); res['level']=level_for(res['score']); res['recommendations']=recs(res['level']); res['source']='Rule-based heuristic + Google Safe Browsing'
        elif ext.get('configured'): res['source']='Rule-based heuristic + Google Safe Browsing lookup'
    scan_id=save_scan(kind,content,res)
    res['scan_id']=scan_id; return jsonify(res)
@app.route('/history')
@login_required
def history():
    with db() as c:
        if session.get('role')=='admin': scans=c.execute('SELECT scans.*,users.username FROM scans LEFT JOIN users ON users.id=scans.user_id ORDER BY scans.id DESC LIMIT 200').fetchall()
        else: scans=c.execute('SELECT * FROM scans WHERE user_id=? OR user_id IS NULL ORDER BY id DESC LIMIT 100',(session['user_id'],)).fetchall()
    return render_template('history.html',scans=scans)
@app.route('/report/<int:scan_id>.pdf')
def pdf_report(scan_id):
    with db() as c: row=c.execute('SELECT * FROM scans WHERE id=?',(scan_id,)).fetchone()
    if not row: return 'Report not found',404
    if row['user_id'] and row['user_id']!=session.get('user_id') and session.get('role')!='admin': return 'Sign in as the scan owner to download this report.',403
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except ImportError: return 'PDF library missing. Run: python -m pip install -r requirements.txt',500
    buf=io.BytesIO(); p=canvas.Canvas(buf,pagesize=letter); width,height=letter; y=height-55
    p.setFont('Helvetica-Bold',20); p.drawString(50,y,'PhishGuard Scan Report'); y-=32
    p.setFont('Helvetica',10)
    for line in [f"Scan ID: {row['id']}",f"Type: {row['scan_type']}",f"Date: {row['scanned_at']}",f"Risk score: {row['risk_score']}/100",f"Risk level: {row['threat_level']}",f"Analysis source: {row['source']}"]:
        p.drawString(50,y,line); y-=17
    y-=10; p.setFont('Helvetica-Bold',12); p.drawString(50,y,'Input (truncated)'); y-=18; p.setFont('Helvetica',9)
    for line in wrap(row['input_text'][:1200],95):
        if y<65: p.showPage(); y=height-55; p.setFont('Helvetica',9)
        p.drawString(50,y,line); y-=12
    y-=12; p.setFont('Helvetica-Bold',12); p.drawString(50,y,'Indicators'); y-=18; p.setFont('Helvetica',9)
    try: inds=json.loads(row['result_json']).get('indicators',[])
    except Exception: inds=[]
    for it in inds:
        for line in wrap(f"- {it.get('label')}: {it.get('explanation')}",95):
            if y<55: p.showPage(); y=height-55; p.setFont('Helvetica',9)
            p.drawString(50,y,line); y-=12
    y-=10; p.setFont('Helvetica-Oblique',8); p.drawString(50,max(y,35),'Educational assessment only. Heuristic results are not a guarantee; external checks are identified separately.')
    p.save(); buf.seek(0); return send_file(buf,as_attachment=True,download_name=f'PhishGuard_Scan_{scan_id}.pdf',mimetype='application/pdf')
def wrap(text,n): return [text[i:i+n] for i in range(0,len(text),n)] or ['']
@app.route('/awareness',methods=['GET','POST'])
def awareness():
    questions=[{'q':'An email says your account closes in 10 minutes unless you click a link. What is the best first action?','opts':['Click immediately','Open the official site independently','Reply with your password'],'answer':1,'why':'Urgency is a common pressure tactic. Verify through a known official channel.'},{'q':'Which is the strongest sign a URL may be deceptive?','opts':['It uses a familiar logo','The domain is misspelled or unrelated to the claimed brand','It has a short path'],'answer':1,'why':'Check the actual registered domain, not just brand words in the URL.'},{'q':'A sender asks you to email an OTP. What should you do?','opts':['Send it if the email looks official','Never share it; verify independently','Post it to support chat'],'answer':1,'why':'One-time codes are secrets and should not be shared with someone who contacts you.'},{'q':'What does an HTTPS padlock prove?','opts':['The site is legitimate','The connection is encrypted, not that the site is trustworthy','The URL has been scanned'],'answer':1,'why':'Phishing websites can also use HTTPS.'},{'q':'What should you do with a suspicious attachment?','opts':['Open it to see what it is','Forward it to friends','Do not open it; report it using your organization’s process'],'answer':2,'why':'Avoid opening unexpected attachments and report them safely.'}]
    return render_template('awareness.html',questions=questions)
@app.route('/report-site',methods=['GET','POST'])
def report_site():
    if request.method=='POST':
        url=(request.form.get('url') or '').strip(); details=(request.form.get('details') or '').strip()
        if not url: flash('Please enter the suspicious URL.','danger')
        else:
            with db() as c: c.execute('INSERT INTO reports(user_id,url,details,status,created_at) VALUES(?,?,?,?,?)',(session.get('user_id'),url[:2000],details[:2000],'Pending',now()))
            flash('Report submitted for review. This demo stores the report locally; it does not automatically notify a security provider.','success'); return redirect(url_for('report_site'))
    return render_template('report.html')
@app.route('/admin')
@admin_required
def admin():
    with db() as c:
        users=c.execute('SELECT id,username,role,created_at FROM users ORDER BY id').fetchall(); reports=c.execute('SELECT reports.*,users.username FROM reports LEFT JOIN users ON users.id=reports.user_id ORDER BY reports.id DESC LIMIT 100').fetchall()
        counts={'users':c.execute('SELECT COUNT(*) FROM users').fetchone()[0],'scans':c.execute('SELECT COUNT(*) FROM scans').fetchone()[0],'pending':c.execute("SELECT COUNT(*) FROM reports WHERE status='Pending'").fetchone()[0]}
    return render_template('admin.html',users=users,reports=reports,counts=counts)
@app.route('/admin/report/<int:rid>',methods=['POST'])
@admin_required
def update_report(rid):
    status=request.form.get('status','Pending')
    if status not in ('Pending','Reviewed','Confirmed threat','False positive'): status='Pending'
    with db() as c: c.execute('UPDATE reports SET status=? WHERE id=?',(status,rid))
    flash('Report status updated.','success'); return redirect(url_for('admin'))
@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        username=(request.form.get('username') or '').strip(); password=request.form.get('password') or ''
        with db() as c: user=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
        if user and verify_password(password,user['password_hash']):
            session.clear(); session.update(user_id=user['id'],username=user['username'],role=user['role']); return redirect(request.args.get('next') or url_for('index'))
        flash('Incorrect username or password.','danger')
    return render_template('login.html')
@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        username=(request.form.get('username') or '').strip(); password=request.form.get('password') or ''
        if not re.fullmatch(r'[A-Za-z0-9_]{3,24}',username): flash('Username must be 3–24 letters, numbers, or underscores.','danger')
        elif len(password)<10: flash('Use a password with at least 10 characters.','danger')
        else:
            try:
                with db() as c: c.execute('INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)',(username,hash_password(password),'user',now()))
                flash('Account created. Please sign in.','success'); return redirect(url_for('login'))
            except sqlite3.IntegrityError: flash('That username is already taken.','danger')
    return render_template('register.html')
@app.route('/logout')
def logout(): session.clear(); flash('You have signed out.','success'); return redirect(url_for('index'))
@app.route('/about')
def about(): return render_template('about.html',api_configured=bool(GOOGLE_SAFE_BROWSING_KEY))
@app.route('/api/stats')
def stats():
    with db() as c: rows=c.execute('SELECT threat_level,COUNT(*) n FROM scans GROUP BY threat_level').fetchall()
    return jsonify({r['threat_level']:r['n'] for r in rows})
init_db()
if __name__=='__main__': app.run(debug=False)
