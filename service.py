"""Hosted API adapter around the supplied trained UPI Guard decision engine."""
import json
import os
import secrets
import sqlite3
import time
import hashlib
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

import numpy as np
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from model_pipeline import AssessmentBinding, HybridDecisionEngine, load_pipeline
from content_checks import MessageRequest, QRRequest, analyze_message, inspect_qr

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("UPI_GUARD_DB_PATH", str(ROOT / "events.db")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
API_KEY = os.environ.get("UPI_GUARD_API_KEY", "")
if os.environ.get('UPI_GUARD_REQUIRE_AUTH') == '1' and (not API_KEY or not os.environ.get('UPI_GUARD_SIGNING_KEY')):
    raise RuntimeError('Hosted deployment requires API and assessment-signing keys.')

@contextmanager
def connection():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

with connection() as db:
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("""CREATE TABLE IF NOT EXISTS api_assessments (
        id TEXT PRIMARY KEY, client_id TEXT NOT NULL, payment_id TEXT NOT NULL,
        session_id TEXT NOT NULL, result TEXT NOT NULL, request TEXT NOT NULL,
        review_status TEXT NOT NULL, user_action TEXT NOT NULL,
        invalidated INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)""")
    db.execute("CREATE INDEX IF NOT EXISTS api_client_time ON api_assessments(client_id, created_at)")
    db.execute("""CREATE TABLE IF NOT EXISTS api_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id TEXT, client_id TEXT,
        action TEXT, rationale TEXT, timestamp INTEGER)""")
    db.execute("CREATE TABLE IF NOT EXISTS api_preferences (client_id TEXT PRIMARY KEY, candidate_ready INTEGER NOT NULL DEFAULT 0)")
    db.execute("""CREATE TABLE IF NOT EXISTS api_content_checks (
        id TEXT PRIMARY KEY, client_id TEXT NOT NULL, kind TEXT NOT NULL, request TEXT NOT NULL,
        result TEXT NOT NULL, review_status TEXT NOT NULL DEFAULT 'Pending review',
        request_hash TEXT NOT NULL, created_at INTEGER NOT NULL)""")
    db.execute('CREATE INDEX IF NOT EXISTS api_content_client ON api_content_checks(client_id, created_at)')
    db.execute('CREATE TABLE IF NOT EXISTS api_ai_requests (client_id TEXT NOT NULL, created_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS api_pair_codes (code_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, expires_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS api_devices (id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, client_id TEXT NOT NULL, name TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS api_pair_attempts (source TEXT NOT NULL, created_at INTEGER NOT NULL)')

tx, intent, novelty, metadata = load_pipeline(str(ROOT / 'models'))
engine = HybridDecisionEngine(tx, intent, novelty, threshold_warn=metadata.get('threshold_warn', .5))
with (ROOT / 'data' / 'merchants.json').open(encoding='utf-8') as f:
    merchants = {m['vpa']:m for m in json.load(f)}

app = FastAPI(title="UPI Guard Decision API", version="1.6.0", description="Message and public-link analysis, connected companions, QR inspection, and payment risk checks. No payments are executed.")
origins = os.environ.get('UPI_GUARD_ALLOWED_ORIGINS', 'http://127.0.0.1:4173,http://localhost:4173,https://upi-guard-payment-safety.copperlemur.chatgpt.site').split(',')
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in origins if x.strip()], allow_origin_regex=r'^chrome-extension://[a-p]{32}$', allow_methods=['GET','POST','DELETE'], allow_headers=['Content-Type','X-Demo-Client-ID','X-API-Key','Authorization'], allow_credentials=False)

@app.middleware('http')
async def guard(request: Request, call_next):
    from fastapi.responses import JSONResponse
    # A hosted deployment sets this shared key; the private Sites gateway supplies it.
    if API_KEY and request.url.path not in ['/health','/companion/redeem','/companion/analyze','/companion/disconnect'] and request.method != 'OPTIONS':
        if not secrets.compare_digest(request.headers.get('x-api-key',''), API_KEY):
            return JSONResponse({'detail':'Backend authentication required.'}, status_code=401)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cache-Control'] = 'no-store' if request.url.path not in ['/styles.css','/app.js'] else 'no-cache'
    return response

def client_id(x_demo_client_id: str = Header(default='local-demo')):
    if not 1 <= len(x_demo_client_id) <= 128 or any(ord(c)<32 for c in x_demo_client_id):
        raise HTTPException(400, 'Invalid demo workspace ID.')
    return x_demo_client_id

class ScoreRequest(BaseModel):
    payment_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    amount: float = Field(gt=0, le=1000000, multiple_of=0.01, allow_inf_nan=False)
    currency: Literal['INR'] = 'INR'
    recipient: str = Field(min_length=1, max_length=160)
    recipient_account: str = Field(min_length=1, max_length=160, pattern=r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+$')
    source: Literal['demo','user'] = 'demo'
    expected_recipient: str | None = Field(default=None, max_length=160)
    message: str = Field(default='', max_length=5000)
    user_intent: Literal['receive','pay','verify'] | None = None
    screen_sharing: Literal[0,1] = 0
    device_novelty: Literal[0,1] = 0
    prior_recipient_count: int = Field(default=0, ge=0, le=10000)
    interaction_time_seconds: float = Field(default=12, gt=0, le=3600, allow_inf_nan=False)
    scenario: str = Field(default='custom', max_length=64)
    purpose: str = Field(default='Demo payment', max_length=200)

class ConfirmRequest(BaseModel):
    assessment_id: str
    payment_id: str
    session_id: str
    amount: float = Field(gt=0, multiple_of=0.01, allow_inf_nan=False)
    currency: str = 'INR'
    recipient: str
    recipient_account: str
    assessment_token: str

class ReviewRequest(BaseModel):
    assessment_id: str
    review_status: Literal['Fraudulent','Legitimate','Needs investigation']
    rationale: str = Field(default='Reviewed by analyst', max_length=2000)

class ActionRequest(BaseModel):
    assessment_id: str
    user_action: Literal['Cancelled','Reviewed','Recheck required']

class PairRedeem(BaseModel):
    code: str = Field(min_length=8,max_length=24)
    name: str = Field(default='UPI Guard companion',min_length=1,max_length=80)

class DeviceRevoke(BaseModel):
    device_id: str = Field(min_length=1,max_length=80)

def credential_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()

def device_client(authorization: str = Header(default='')):
    if not authorization.startswith('Bearer '):
        raise HTTPException(401,'Connect this companion from website Settings first.')
    with connection() as db:
        row=db.execute('SELECT * FROM api_devices WHERE token_hash=? AND expires_at>?',(credential_hash(authorization[7:]),int(time.time()))).fetchone()
    if not row:
        raise HTTPException(401,'The companion connection expired or was revoked. Reconnect from website Settings.')
    return row

@app.post('/companion/pair')
def create_pair(client: str = Depends(client_id)):
    code=secrets.token_hex(6).upper();expires=int(time.time())+600
    with connection() as db:
        db.execute('DELETE FROM api_pair_codes WHERE client_id=? OR expires_at<?',(client,int(time.time())))
        db.execute('INSERT INTO api_pair_codes VALUES (?,?,?)',(credential_hash(code),client,expires))
    return {'code':code,'expires_at':expires,'expires_in_seconds':600,'notice':'One use only. Enter this code only in your UPI Guard extension or Windows companion.'}

@app.post('/companion/redeem')
def redeem_pair(req: PairRedeem, request: Request):
    now=int(time.time());source=credential_hash(request.client.host if request.client else 'unknown')
    with connection() as db:
        db.execute('DELETE FROM api_pair_attempts WHERE created_at<?',(now-3600,))
        count=db.execute('SELECT COUNT(*) FROM api_pair_attempts WHERE source=? AND created_at>?',(source,now-600)).fetchone()[0]
        if count>=15:
            raise HTTPException(429,'Too many connection attempts. Retry in ten minutes.')
        db.execute('INSERT INTO api_pair_attempts VALUES (?,?)',(source,now))
    code=req.code.replace(' ','').replace('-','').upper()
    with connection() as db:
        # Consume the code atomically; concurrent redemption cannot create two devices.
        row=db.execute('DELETE FROM api_pair_codes WHERE code_hash=? AND expires_at>? RETURNING client_id',(credential_hash(code),now)).fetchone()
        if not row: raise HTTPException(401,'Invalid, expired or already-used connection code.')
        device_id='device-'+uuid.uuid4().hex;token=secrets.token_urlsafe(40);expires=now+30*86400
        db.execute('DELETE FROM api_devices WHERE expires_at<?',(now,))
        existing=db.execute('SELECT COUNT(*) FROM api_devices WHERE client_id=?',(row['client_id'],)).fetchone()[0]
        if existing>=10: raise HTTPException(409,'Disconnect an old companion from website Settings before adding another.')
        db.execute('INSERT INTO api_devices VALUES (?,?,?,?,?,?)',(device_id,credential_hash(token),row['client_id'],req.name,expires,now))
    return {'token':token,'device_id':device_id,'expires_at':expires,'name':req.name}

@app.get('/companion/devices')
def devices(client: str = Depends(client_id)):
    with connection() as db:
        rows=db.execute('SELECT id,name,expires_at,created_at FROM api_devices WHERE client_id=? AND expires_at>? ORDER BY created_at DESC',(client,int(time.time()))).fetchall()
    return {'devices':[dict(r) for r in rows]}

@app.post('/companion/revoke')
def revoke_device(req: DeviceRevoke,client: str = Depends(client_id)):
    with connection() as db:
        row=db.execute('DELETE FROM api_devices WHERE id=? AND client_id=? RETURNING id',(req.device_id,client)).fetchone()
        if not row: raise HTTPException(404,'Connected companion not found.')
    return {'status':'DISCONNECTED'}

@app.post('/companion/disconnect')
def disconnect_device(device=Depends(device_client)):
    with connection() as db: db.execute('DELETE FROM api_devices WHERE id=?',(device['id'],))
    return {'status':'DISCONNECTED'}

@app.post('/companion/analyze')
async def companion_analyze(req: MessageRequest,device=Depends(device_client)):
    return await message_check(req,device['client_id'])

def get_row(db, assessment_id, client):
    row = db.execute('SELECT * FROM api_assessments WHERE id=? AND client_id=?', (assessment_id,client)).fetchone()
    if row is None:
        raise HTTPException(404,'Assessment not found in this demo workspace.')
    return row

def as_record(row):
    res=json.loads(row['result']); req=json.loads(row['request'])
    return dict(id=row['id'], scenario=req['scenario'], recipient=res['recipient'], account=res['account'], amount=res['amount'], currency=res['currency'], risk=res['risk_tier'], category=res['category'], action=row['user_action'], review=row['review_status'], customer='Aarav Mehta', time=row['created_at']*1000, session=row['session_id'], reference={0:'match',2:'match',1:'mismatch',3:'unavailable'}[res['merchant_status']], expected=req.get('expected_recipient'), purpose=req['purpose'], message=req['message'], evidence=res['observed_facts']+res['inferred_facts'], observed=res['observed_facts'], inferred=res['inferred_facts'], missing=res['missing_signals'], featureContributions=res['feature_contributions'], modelVersion=res['model_version'], latency=res['scoring_latency_ms'], invalidated=bool(row['invalidated']), backend=True)

def content_record(row):
    result=json.loads(row['result']); req=json.loads(row['request']); details=result.get('details',{})
    return dict(id=row['id'], kind=row['kind'], scenario=row['kind'], recipient=('Message check' if row['kind']=='message' else details.get('recipient') or 'QR · '+result['qr_type']), account=details.get('account') or details.get('host') or 'No payment destination', amount=details.get('amount'), currency='INR', risk=result['risk'], category=('Message · '+result['verdict'].replace('_',' ') if row['kind']=='message' else 'QR · '+result['qr_type']), action='Reviewed', review=row['review_status'], customer='Aarav Mehta', time=row['created_at']*1000, session=row['id'], reference='unavailable', purpose='Content inspection', message=req.get('message') or req.get('payload',''), evidence=[result['summary']]+[f['signal']+': '+f['evidence'] for f in result['red_flags']], observed=['User-supplied content only.'], inferred=[result['summary']], missing=result['limitations'], featureContributions={}, modelVersion=result.get('model') or 'QR parser v1', latency=result.get('latency_ms'), invalidated=False, backend=True, content=result)

def save_content(req, result, client):
    created=int(time.time()); check_id='UG-'+uuid.uuid4().hex[:16]
    digest=hashlib.sha256(req.model_dump_json().encode()).hexdigest()
    result.update(id=check_id,created_at=created)
    with connection() as db:
        db.execute('INSERT INTO api_content_checks (id,client_id,kind,request,result,request_hash,created_at) VALUES (?,?,?,?,?,?,?)',(check_id,client,result['kind'],req.model_dump_json(),json.dumps(result),digest,created))
        row=db.execute('SELECT * FROM api_content_checks WHERE id=?',(check_id,)).fetchone()
        result['record']=content_record(row)
    return result

@app.post('/analyze-message')
async def message_check(req: MessageRequest, client: str = Depends(client_id)):
    now=int(time.time()); digest=hashlib.sha256(req.model_dump_json().encode()).hexdigest()
    cache_seconds=60 if req.inspect_link else 600
    with connection() as db:
        cached=db.execute('SELECT * FROM api_content_checks WHERE client_id=? AND kind=? AND request_hash=? AND created_at>? ORDER BY created_at DESC LIMIT 1',(client,'message',digest,now-cache_seconds)).fetchone()
        if cached:
            result=json.loads(cached['result']); result['record']=content_record(cached); result['cached']=True;result['cached_age_seconds']=now-cached['created_at']
            return result
        recent=db.execute('SELECT COUNT(*) FROM api_ai_requests WHERE client_id=? AND created_at>?',(client,now-60)).fetchone()[0]
        daily=db.execute('SELECT COUNT(*) FROM api_ai_requests WHERE client_id=? AND created_at>?',(client,now-86400)).fetchone()[0]
        if recent>=20 or daily>=200:
            raise HTTPException(429,'Message-check limit reached for this workspace. Please retry later.')
        db.execute('INSERT INTO api_ai_requests VALUES (?,?)',(client,now))
        db.execute('DELETE FROM api_ai_requests WHERE created_at<?',(now-86400,))
    start=time.perf_counter(); result=await analyze_message(req)
    result['latency_ms']=round((time.perf_counter()-start)*1000,2)
    return save_content(req,result,client)

@app.post('/analyze-qr')
def qr_check(req: QRRequest, client: str = Depends(client_id)):
    return save_content(req,inspect_qr(req),client)

@app.get('/health')
def health():
    return {'status':'ok','service':'upi-guard-api','model_version':metadata.get('model_version'),'demo':True,'message_analysis_configured':bool(os.environ.get('OPENAI_API_KEY')),'version':'1.6.0','public_link_inspection':True,'companion_api':True,'ephemeral_storage':os.environ.get('UPI_GUARD_EPHEMERAL')=='1'}

@app.post('/score-payment')
def score_payment(req: ScoreRequest, client: str = Depends(client_id)):
    if not req.message.strip() and not req.user_intent:
        raise HTTPException(422, 'Choose whether you intend to receive money, pay someone, or verify your account.')
    start=time.perf_counter()
    if req.source=='demo' and not req.recipient_account.endswith('@demo'):
        raise HTTPException(422,'Select user-supplied mode for an external UPI address.')
    payload=req.model_dump()
    if req.source=='user':
        payload.update(prior_recipient_count=0,screen_sharing=0,device_novelty=0)
    result=engine.score(payload, merchants_registry=merchants if req.source=='demo' else {})
    if req.source=='user':
        result['observed_facts']=[fact for fact in result['observed_facts'] if fact!='First payment to this recipient.']
        result['missing_signals']+=['Recipient identity, bank validation, prior payment history and device signals were not available.','The payment direction is inferred from the UPI payment request; no transaction was executed.']
    result['scoring_latency_ms']=round((time.perf_counter()-start)*1000,2)
    result['model_version']=metadata.get('model_version','hybrid-v1.3')
    with connection() as db:
        db.execute('INSERT INTO api_assessments (id,client_id,payment_id,session_id,result,request,review_status,user_action,created_at) VALUES (?,?,?,?,?,?,?,?,?)', (result['assessment_id'],client,req.payment_id,req.session_id,json.dumps(result),req.model_dump_json(),'Pending review','Reviewed',result['timestamp']))
        row=get_row(db,result['assessment_id'],client)
        result['record']=as_record(row)
    return result

@app.get('/assessments')
def list_assessments(client: str = Depends(client_id)):
    with connection() as db:
        rows=db.execute('SELECT * FROM api_assessments WHERE client_id=? ORDER BY created_at DESC, rowid DESC LIMIT 500',(client,)).fetchall()
        candidate=db.execute('SELECT candidate_ready FROM api_preferences WHERE client_id=?',(client,)).fetchone()
        content=db.execute('SELECT * FROM api_content_checks WHERE client_id=? ORDER BY created_at DESC LIMIT 500',(client,)).fetchall()
    records=[as_record(r) for r in rows]+[content_record(r) for r in content]
    records.sort(key=lambda r:r['time'],reverse=True)
    return {'records':records[:500], 'candidate_ready':bool(candidate and candidate[0])}

@app.post('/assessment-action')
def action(req: ActionRequest, client: str = Depends(client_id)):
    with connection() as db:
        row=get_row(db,req.assessment_id,client)
        if row['user_action']=='Simulated completion':
            raise HTTPException(409,'This demo assessment has already been completed.')
        db.execute('UPDATE api_assessments SET user_action=?, invalidated=? WHERE id=? AND client_id=?',(req.user_action, int(req.user_action=='Recheck required' or row['invalidated']),req.assessment_id,client))
        db.execute('INSERT INTO api_audit (assessment_id,client_id,action,timestamp) VALUES (?,?,?,?)',(req.assessment_id,client,req.user_action,int(time.time())))
    return {'status':'SAVED'}

@app.post('/confirm-demo-payment')
def confirm(req: ConfirmRequest, client: str = Depends(client_id)):
    with connection() as db:
        row=get_row(db,req.assessment_id,client)
        result=json.loads(row['result'])
        if json.loads(row['request']).get('source')=='user':
            raise HTTPException(409,'External payment details are inspection-only. This website does not execute payments.')
        valid,reason=AssessmentBinding.verify_token(req.assessment_token,req.recipient,req.amount,req.currency,req.recipient_account,req.payment_id,req.session_id)
        if not valid or row['invalidated'] or row['user_action']=='Cancelled' or req.assessment_token!=result['assessment_token']:
            raise HTTPException(409,{'status':'INVALIDATED','message':reason if not valid else 'Assessment invalidated or cancelled. Reassessment required.'})
        if result['risk_tier']!='low':
            raise HTTPException(409,'This assessment still requires review; demo completion is blocked.')
        db.execute("UPDATE api_assessments SET user_action='Simulated completion' WHERE id=? AND client_id=?",(req.assessment_id,client))
    return {'status':'APPROVED','message':'Simulated completion saved. No money moved.'}

@app.post('/review-label')
def review(req: ReviewRequest, client: str = Depends(client_id)):
    with connection() as db:
        row=db.execute('SELECT id FROM api_assessments WHERE id=? AND client_id=?',(req.assessment_id,client)).fetchone()
        table='api_assessments' if row else 'api_content_checks'
        if not row and not db.execute('SELECT id FROM api_content_checks WHERE id=? AND client_id=?',(req.assessment_id,client)).fetchone():
            raise HTTPException(404,'Check not found in this workspace.')
        db.execute(f'UPDATE {table} SET review_status=? WHERE id=? AND client_id=?',(req.review_status,req.assessment_id,client))
        db.execute('INSERT INTO api_audit (assessment_id,client_id,action,rationale,timestamp) VALUES (?,?,?,?,?)',(req.assessment_id,client,req.review_status,req.rationale,int(time.time())))
    return {'status':'SAVED','review_status':req.review_status}

@app.get('/metrics')
def metrics(client: str = Depends(client_id)):
    with connection() as db:
        rows=db.execute('SELECT * FROM api_assessments WHERE client_id=?',(client,)).fetchall()
        content=db.execute('SELECT * FROM api_content_checks WHERE client_id=?',(client,)).fetchall()
    results=[json.loads(r['result']) for r in rows]
    latency=[r['scoring_latency_ms'] for r in results]
    flagged=sum(r['risk_tier']!='low' for r in results)+sum(json.loads(r['result'])['risk']!='low' for r in content)
    total=len(rows)+len(content)
    return {'total_assessed':total,'payment_checks':len(rows),'message_checks':sum(r['kind']=='message' for r in content),'qr_checks':sum(r['kind']=='qr' for r in content),'flagged_transactions':flagged,'pending_reviews':sum(r['review_status'] in ['Pending review','Needs investigation'] for r in [*rows,*content]),'warning_rate':f'{flagged/total*100:.1f}%' if total else '0%','median_latency_ms':round(float(np.median(latency)),2) if latency else None,'p95_latency_ms':round(float(np.percentile(latency,95)),2) if latency else None,'labelled_fraudulent':sum(r['review_status']=='Fraudulent' for r in [*rows,*content]),'user_cancellations':sum(r['user_action']=='Cancelled' for r in rows),'message_analysis_configured':bool(os.environ.get('OPENAI_API_KEY')),'ephemeral_storage':os.environ.get('UPI_GUARD_EPHEMERAL')=='1'}

@app.get('/evaluation-results')
def evaluation():
    file=ROOT/'evaluation_results.json'
    if not file.exists():
        raise HTTPException(503,'Evaluation artifact unavailable.')
    with file.open(encoding='utf-8') as f:
        result=json.load(f)
    result['provenance']='Evaluation artifact supplied with the model; synthetic dataset; not a live production benchmark.'
    result['scope']='Offline evaluation. Hosting integration changes do not constitute model re-evaluation.'
    return result

@app.post('/pattern-lab/prepare-candidate')
def candidate(client: str = Depends(client_id)):
    if not (ROOT/'models/candidate_tx_model.joblib').exists():
        raise HTTPException(503,'Candidate model artifact unavailable.')
    with connection() as db:
        labelled=db.execute("SELECT COUNT(*) FROM api_assessments WHERE client_id=? AND review_status IN ('Fraudulent','Legitimate','Needs investigation')",(client,)).fetchone()[0]
        labelled+=db.execute("SELECT COUNT(*) FROM api_content_checks WHERE client_id=? AND review_status IN ('Fraudulent','Legitimate','Needs investigation')",(client,)).fetchone()[0]
        if not labelled:
            raise HTTPException(409,'Review and label at least one case before preparing a candidate comparison.')
        db.execute('INSERT INTO api_preferences (client_id,candidate_ready) VALUES (?,1) ON CONFLICT(client_id) DO UPDATE SET candidate_ready=1',(client,))
    return {'status':'CANDIDATE_READY','version':'v1.4-candidate','training_performed':False,'message':'Existing trained candidate artifact selected for comparison. No retraining or deployment performed.'}

@app.delete('/demo-data')
def reset(client: str = Depends(client_id)):
    with connection() as db:
        db.execute('DELETE FROM api_assessments WHERE client_id=?',(client,))
        db.execute('DELETE FROM api_audit WHERE client_id=?',(client,))
        db.execute('DELETE FROM api_preferences WHERE client_id=?',(client,))
        db.execute('DELETE FROM api_content_checks WHERE client_id=?',(client,))
    return {'status':'RESET','scope':'current demo workspace only'}

@app.get('/')
def index():
    return FileResponse(ROOT/'dist/index.html')

@app.get('/{filename:path}')
def static(filename: str):
    root=(ROOT/'dist').resolve(); file=(root/filename).resolve()
    if not file.is_relative_to(root) or not file.is_file() or file.suffix not in ['.html','.css','.js','.svg','.png','.json','.zip'] or 'server' in file.relative_to(root).parts:
        raise HTTPException(404,'Not found')
    return FileResponse(file)
