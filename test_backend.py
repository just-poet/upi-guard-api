"""Integration checks using real trained models and an isolated SQLite file."""
import os
import tempfile
import unittest
from pathlib import Path

temporary=tempfile.TemporaryDirectory(prefix='upi-guard-test-')
os.environ['UPI_GUARD_DB_PATH']=str(Path(temporary.name)/'events.db')
os.environ['UPI_GUARD_API_KEY']='test-only-key'
from fastapi.testclient import TestClient
from service import app

class BackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api=TestClient(app)
    def setUp(self):
        self.headers={'X-API-Key':'test-only-key','X-Demo-Client-ID':self.id()}
    def payload(self,**changes):
        data=dict(payment_id='PAY-test',session_id='SESSION-test',amount=450,currency='INR',recipient='Sharma Medical',recipient_account='sharmamedical@demo',expected_recipient='Sharma Medical',message='Your medicines total ₹450. Please pay Sharma Medical at the counter.',prior_recipient_count=3,scenario='merchant')
        data.update(changes);return data
    def score(self,**changes):
        response=self.api.post('/score-payment',json=self.payload(**changes),headers=self.headers)
        self.assertEqual(response.status_code,200,response.text);return response.json()
    def confirmation(self,result):
        return {key:result[key] for key in ['assessment_id','payment_id','session_id','amount','currency','recipient','assessment_token']}|{'recipient_account':result['account']}
    def test_legitimate_confirmation(self):
        result=self.score();self.assertEqual(result['risk_tier'],'low')
        response=self.api.post('/confirm-demo-payment',json=self.confirmation(result),headers=self.headers)
        self.assertEqual(response.status_code,200,response.text)
        records=self.api.get('/assessments',headers=self.headers).json()['records']
        self.assertEqual(records[0]['action'],'Simulated completion')
    def test_each_bound_field_is_enforced(self):
        result=self.score();base=self.confirmation(result)
        for key,value in [('recipient_account','unrelated@demo'),('recipient','Other Name'),('amount',450.01),('currency','USD'),('payment_id','other-payment'),('session_id','other-session')]:
            with self.subTest(key=key):
                response=self.api.post('/confirm-demo-payment',json=base|{key:value},headers=self.headers)
                self.assertEqual(response.status_code,409,response.text)
    def test_refund_warning_and_cancel_are_persisted(self):
        result=self.score(amount=5000,recipient='Ravi Enterprises',recipient_account='ravienterprises@demo',expected_recipient='Refund support',message='Your ₹5,000 refund is ready. Approve payment to receive your refund.',prior_recipient_count=0,scenario='refund')
        self.assertEqual(result['risk_tier'],'high');self.assertEqual(result['category'],'Refund deception')
        self.assertTrue(any('appears' in item for item in result['inferred_facts']))
        response=self.api.post('/confirm-demo-payment',json=self.confirmation(result),headers=self.headers)
        self.assertEqual(response.status_code,409)
        self.assertEqual(self.api.post('/assessment-action',json={'assessment_id':result['assessment_id'],'user_action':'Cancelled'},headers=self.headers).status_code,200)
        self.assertEqual(self.api.get('/metrics',headers=self.headers).json()['user_cancellations'],1)
    def test_qr_reference_and_name_variation(self):
        alias=self.score(recipient='Rajesh Sharma');self.assertEqual(alias['merchant_status'],0)
        mismatch=self.score(recipient='Amit Personal',recipient_account='amitpersonal@demo',expected_recipient='Campus Canteen',message='Please pay for lunch at Campus Canteen.',scenario='qr')
        self.assertEqual(mismatch['merchant_status'],1);self.assertEqual(mismatch['category'],'QR substitution')
        spoof=self.score(recipient_account='fake-sharma@demo');self.assertEqual(spoof['merchant_status'],1)
    def test_job_letter_is_not_an_incoming_refund(self):
        result=self.score(amount=1500,recipient='CareerBridge Services',recipient_account='careerbridge@demo',expected_recipient='New employer',message='Congratulations on your new role! Pay a refundable onboarding deposit of ₹1,500 to receive your offer letter.',scenario='job',prior_recipient_count=0)
        self.assertEqual(result['category'],'Unfamiliar pattern')
        self.assertEqual(self.api.post('/review-label',json={'assessment_id':result['assessment_id'],'review_status':'Needs investigation'},headers=self.headers).status_code,200)
        response=self.api.post('/pattern-lab/prepare-candidate',headers=self.headers)
        self.assertEqual(response.status_code,200);self.assertFalse(response.json()['training_performed'])
    def test_workspace_isolation_and_reset(self):
        result=self.score();other={'X-API-Key':'test-only-key','X-Demo-Client-ID':'unrelated-workspace'}
        self.assertEqual(self.api.get('/assessments',headers=other).json()['records'],[])
        self.assertEqual(self.api.post('/review-label',json={'assessment_id':result['assessment_id'],'review_status':'Fraudulent'},headers=other).status_code,404)
        self.assertEqual(self.api.delete('/demo-data',headers=self.headers).status_code,200)
        self.assertEqual(self.api.get('/assessments',headers=self.headers).json()['records'],[])
    def test_auth_and_validation(self):
        self.assertEqual(self.api.get('/health').status_code,200)
        self.assertEqual(self.api.get('/metrics').status_code,401)
        self.assertEqual(self.api.post('/score-payment',json=self.payload(recipient_account='real@bank'),headers=self.headers).status_code,422)
        self.assertEqual(self.api.post('/score-payment',json=self.payload(message='',user_intent=None),headers=self.headers).status_code,422)
        self.assertEqual(self.api.post('/score-payment',json=self.payload(amount=450.001),headers=self.headers).status_code,422)
    def test_invalidation_blocks_even_unchanged_details(self):
        result=self.score()
        self.api.post('/assessment-action',json={'assessment_id':result['assessment_id'],'user_action':'Recheck required'},headers=self.headers)
        self.assertEqual(self.api.post('/confirm-demo-payment',json=self.confirmation(result),headers=self.headers).status_code,409)

if __name__=='__main__':
    unittest.main()
