"""Exercise untrusted content, provider failures, saved records and isolation."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

os.environ.setdefault('UPI_GUARD_DB_PATH', str(Path(tempfile.mkdtemp())/'content-tests.db'))
os.environ.setdefault('UPI_GUARD_API_KEY','test-only-key')
import httpx
from fastapi.testclient import TestClient
from service import app


class ContentTests(unittest.TestCase):
    def setUp(self):
        self.api=TestClient(app)
        self.headers={'X-API-Key':'test-only-key','X-Demo-Client-ID':self.id()}

    def qr(self,payload,status=200):
        r=self.api.post('/analyze-qr',headers=self.headers,json={'payload':payload})
        self.assertEqual(r.status_code,status,r.text)
        return r.json()

    def test_any_text_types_and_upi_without_amount(self):
        for payload,kind in [('A normal QR note','text'),('WIFI:T:WPA;S:Example;P:sample;;','wifi'),('BEGIN:VCARD\nFN:Example\nEND:VCARD','contact'),('mailto:sample@example.com','email'),('https://example.com/path','website')]:
            with self.subTest(kind=kind):
                result=self.qr(payload);self.assertEqual(result['qr_type'],kind)
                self.assertEqual(result['payload'],payload)
        result=self.qr('upi://pay?pa=shop%40upi&pn=Example%20Shop')
        self.assertIsNone(result['details']['amount'])
        self.assertEqual(result['details']['account'],'shop@upi')
        self.assertEqual(result['risk'],'medium')

    def test_malformed_amount_duplicate_and_unsafe(self):
        for extra in ['am=NaN','am=Infinity','am=-1','am=0','am=1.001','am=1000001','am=1&am=2','pa=other@upi','cu=USD']:
            with self.subTest(extra=extra):self.qr('upi://pay?pa=shop@upi&'+extra,422)
        self.qr('upi://pay?pn=Shop',422)
        self.qr('upi://pay?pa=shop@upi&'+'&'.join(f'x{i}=y' for i in range(110)),422)
        self.assertEqual(self.qr('javascript:alert(1)')['risk'],'high')
        self.assertEqual(self.qr('https://bank.example@unrelated.example')['risk'],'high')

    def test_content_review_isolation_and_reset(self):
        result=self.qr('upi://pay?pa=example@upi&pn=Example&am=12.50')
        other=self.headers|{'X-Demo-Client-ID':'different-workspace'}
        body={'assessment_id':result['id'],'review_status':'Needs investigation'}
        self.assertEqual(self.api.post('/review-label',headers=other,json=body).status_code,404)
        self.assertEqual(self.api.post('/review-label',headers=self.headers,json=body).status_code,200)
        records=self.api.get('/assessments',headers=self.headers).json()['records']
        self.assertEqual(records[0]['review'],'Needs investigation')
        self.assertEqual(records[0]['kind'],'qr')
        self.assertEqual(self.api.get('/metrics',headers=self.headers).json()['qr_checks'],1)
        self.api.delete('/demo-data',headers=self.headers)
        self.assertEqual(self.api.get('/assessments',headers=self.headers).json()['records'],[])

    def test_provider_schema_cache_and_no_secret_in_output(self):
        result={'verdict':'likely_scam','summary':'An OTP request is a warning sign.','red_flags':[{'signal':'OTP request','evidence':'share your OTP'}],'reassuring_signals':[],'next_steps':['Contact your bank independently.'],'limitations':['Sender identity was not verified.']}
        response=httpx.Response(200,json={'status':'completed','output':[{'content':[{'type':'output_text','text':json.dumps(result)}]}]})
        mock=AsyncMock(return_value=response)
        with patch.dict(os.environ,{'OPENAI_API_KEY':'unit-test-provider-credential'}),patch('content_checks.httpx.AsyncClient.post',new=mock):
            r=self.api.post('/analyze-message',headers=self.headers,json={'message':'Please share your OTP'})
            self.assertEqual(r.status_code,200,r.text)
            self.assertEqual(r.json()['verdict'],'likely_scam')
            self.assertNotIn('unit-test-provider-credential',r.text)
            again=self.api.post('/analyze-message',headers=self.headers,json={'message':'Please share your OTP'})
            self.assertTrue(again.json()['cached']);self.assertEqual(mock.await_count,1)
            request=mock.call_args.kwargs['json']
            self.assertFalse(request['store']);self.assertTrue(request['text']['format']['strict'])

    def test_provider_failures_never_save_a_fabricated_assessment(self):
        for provider_status,expected in [(401,503),(429,429),(500,502)]:
            with self.subTest(provider_status=provider_status),patch.dict(os.environ,{'OPENAI_API_KEY':'unit-test-provider-credential'}),patch('content_checks.httpx.AsyncClient.post',new=AsyncMock(return_value=httpx.Response(provider_status,json={'error':{'message':'private provider error'}}))):
                r=self.api.post('/analyze-message',headers=self.headers,json={'message':'A message to inspect'})
                self.assertEqual(r.status_code,expected,r.text)
                self.assertNotIn('private provider error',r.text)
        self.assertEqual(self.api.get('/assessments',headers=self.headers).json()['records'],[])

    def test_external_upi_is_inspection_only(self):
        payload=dict(payment_id='external-test',session_id='external-test',amount=50,recipient='Example',recipient_account='example@upi',source='user',message='Pay for a coffee',user_intent='pay')
        r=self.api.post('/score-payment',headers=self.headers,json=payload)
        self.assertEqual(r.status_code,200,r.text);result=r.json()
        self.assertEqual(result['merchant_status'],3)
        self.assertEqual(result['risk_tier'],'medium')
        self.assertIsNone(result['ml_fraud_probability'])
        body={key:result[key] for key in ['assessment_id','payment_id','session_id','amount','currency','recipient','assessment_token']}|{'recipient_account':result['account']}
        self.assertEqual(self.api.post('/confirm-demo-payment',headers=self.headers,json=body).status_code,409)


if __name__=='__main__': unittest.main()
