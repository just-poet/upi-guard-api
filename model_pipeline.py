"""
UPI Guard - Model Pipeline & Decision Engine
Implements the core ML components from CC6-AI02 UPI Guard Specification:
1. TransactionRiskClassifier (Calibrated Random Forest / Gradient Boosting)
2. MessageIntentClassifier (Multilingual Word + Char N-gram TF-IDF + Calibrated Logistic Regression)
3. NoveltyDetector (Isolation Forest on numeric features)
4. HybridDecisionEngine (Intent contradiction checks, merchant verification, risk policy)
5. AssessmentBinding (HMAC-SHA256 tamper-evident assessment tokens)
"""

import os
import re
import json
import time
import hmac
import hashlib
import secrets
import uuid
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple, Optional
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import FeatureUnion, Pipeline
import joblib

SECRET_KEY = os.environ.get("UPI_GUARD_SIGNING_KEY", "").encode() or secrets.token_bytes(32)

FEATURE_COLUMNS = [
    "log_amount",
    "amount_to_user_median_ratio",
    "prior_recipient_count",
    "is_new_recipient",
    "time_of_day_deviation",
    "recent_tx_velocity_1h",
    "recent_tx_velocity_24h",
    "device_novelty",
    "interaction_time_seconds",
    "screen_recording_active",
    "merchant_ref_mismatch",
    "merchant_ref_unavailable"
]

class TransactionRiskClassifier:
    """Supervised tree-based classifier for payment risk scoring."""
    def __init__(self, n_estimators=120, max_depth=10, random_state=42):
        self.random_state = random_state
        self.base_rf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=6,
            min_samples_leaf=3,
            class_weight="balanced_subsample",
            random_state=random_state,
            n_jobs=-1
        )
        self.calibrated_model = None
        self.feature_names = FEATURE_COLUMNS
        self.feature_importances_ = None

    def _prepare_df(self, df: pd.DataFrame) -> pd.DataFrame:
        X = pd.DataFrame(index=df.index)
        X["log_amount"] = df["log_amount"] if "log_amount" in df.columns else np.log1p(df["amount"])
        
        if "amount_to_user_median_ratio" in df.columns:
            X["amount_to_user_median_ratio"] = df["amount_to_user_median_ratio"]
        else:
            user_med = df.get("user_median_amount", df["amount"])
            X["amount_to_user_median_ratio"] = df["amount"] / (user_med + 1e-4)

        X["prior_recipient_count"] = df.get("prior_recipient_count", 0)
        X["is_new_recipient"] = df.get("is_new_recipient", (X["prior_recipient_count"] == 0).astype(int))
        X["time_of_day_deviation"] = df.get("time_of_day_deviation", 2.0)
        X["recent_tx_velocity_1h"] = df.get("recent_tx_velocity_1h", 0)
        X["recent_tx_velocity_24h"] = df.get("recent_tx_velocity_24h", 1)
        X["device_novelty"] = df.get("device_novelty", 0)
        X["interaction_time_seconds"] = df.get("interaction_time_seconds", 12.0)
        X["screen_recording_active"] = df.get("screen_recording_active", 0)

        # Merchant reference status: 0=match, 1=mismatch, 2=alias, 3=unavailable
        ref_status = df.get("merchant_reference_status", 0)
        X["merchant_ref_mismatch"] = (ref_status == 1).astype(int)
        X["merchant_ref_unavailable"] = (ref_status == 3).astype(int)

        return X[self.feature_names].fillna(0)

    def fit(self, X_train: pd.DataFrame, y_train: pd.Series, X_val: pd.DataFrame = None, y_val: pd.Series = None):
        X_tr = self._prepare_df(X_train)
        self.base_rf.fit(X_tr, y_train)
        self.feature_importances_ = dict(zip(self.feature_names, self.base_rf.feature_importances_))

        # Calibrate probabilities with 3-fold cross validation
        self.calibrated_model = CalibratedClassifierCV(estimator=self.base_rf, method="sigmoid", cv=3)
        self.calibrated_model.fit(X_tr, y_train)

        return self

    def predict_proba(self, df: pd.DataFrame) -> np.ndarray:
        X = self._prepare_df(df)
        return self.calibrated_model.predict_proba(X)

    def get_feature_contributions(self, row: pd.Series) -> Dict[str, float]:
        """Provides intuitive feature importance attribution for the given transaction."""
        df_row = pd.DataFrame([row])
        X = self._prepare_df(df_row).iloc[0]
        
        contributions = {}
        # Relative weights modulated by value severity
        if X["screen_recording_active"] == 1:
            contributions["Screen recording / remote access active"] = 85.0
        if X["merchant_ref_mismatch"] == 1:
            contributions["QR destination differs from merchant record"] = 82.0
        if X["merchant_ref_unavailable"] == 1:
            contributions["Independent merchant record unavailable"] = 45.0
        if X["amount_to_user_median_ratio"] > 4.0:
            contributions["Payment amount is unusually high for customer"] = min(90.0, float(X["amount_to_user_median_ratio"] * 12))
        if X["is_new_recipient"] == 1:
            contributions["First transaction to this recipient"] = 38.0
        if X["device_novelty"] == 1:
            contributions["Unrecognized device signal"] = 28.0
        if X["interaction_time_seconds"] < 6.0:
            contributions["Unusually rushed payment confirmation"] = 25.0

        if not contributions:
            contributions["Transaction pattern matches normal baseline"] = 5.0
            
        return dict(sorted(contributions.items(), key=lambda item: item[1], reverse=True))


class MessageIntentClassifier:
    """Multilingual intent classifier using Character and Word n-gram TF-IDF + Logistic Regression."""
    CLASSES = [
        "receive_refund_reward",
        "purchase",
        "return_money",
        "kyc_threat",
        "job_deposit",
        "unknown_other"
    ]

    def __init__(self, random_state=42):
        self.random_state = random_state
        # Word + Char n-grams to handle English, Hindi (Devanagari), and Hinglish transliterations
        self.pipeline = Pipeline([
            ("features", FeatureUnion([
                ("word_tfidf", TfidfVectorizer(
                    ngram_range=(1, 2),
                    analyzer="word",
                    token_pattern=r"(?u)\b\w+\b",
                    min_df=2,
                    max_features=4000
                )),
                ("char_tfidf", TfidfVectorizer(
                    ngram_range=(2, 4),
                    analyzer="char_wb",
                    min_df=2,
                    max_features=6000
                ))
            ])),
            ("clf", LogisticRegression(
                C=3.0,
                max_iter=1000,
                class_weight="balanced",
                random_state=random_state
            ))
        ])
        self.calibrated_pipeline = None

    def fit(self, texts: List[str], labels: List[str]):
        clean_texts = [str(t) if pd.notna(t) else "" for t in texts]
        self.pipeline.fit(clean_texts, labels)
        self.calibrated_pipeline = CalibratedClassifierCV(estimator=self.pipeline, method="sigmoid", cv=3)
        self.calibrated_pipeline.fit(clean_texts, labels)
        return self

    def predict(self, texts: List[str]) -> List[str]:
        clean_texts = [str(t) if pd.notna(t) else "" for t in texts]
        return list(self.calibrated_pipeline.predict(clean_texts))

    def predict_proba(self, texts: List[str]) -> np.ndarray:
        clean_texts = [str(t) if pd.notna(t) else "" for t in texts]
        return self.calibrated_pipeline.predict_proba(clean_texts)

    def extract_entities(self, text: str) -> Dict[str, Any]:
        """Extracts high-confidence entity cues (e.g. monetary amounts, refund keywords)."""
        if not text:
            return {"amount": None, "keywords": []}
            
        amt_match = re.search(r"(?:₹|rs\.?|inr)\s*([\d,]+(?:\.\d{1,2})?)", text, re.IGNORECASE)
        amt = None
        if amt_match:
            try:
                amt = float(amt_match.group(1).replace(",", ""))
            except ValueError:
                amt = None
                
        keywords = []
        is_return = bool(re.search(r"\b(borrowed|returning|udhaar|udhar|share|split|loan|dost|dinner|trip|petrol)\b", text, re.IGNORECASE))
        if not is_return and re.search(r"\b(refund|cashback|reward|reimbursement|रिफंड|क्लेम|bonus)\b", text, re.IGNORECASE):
            keywords.append("refund_incoming_cue")
        if re.search(r"\b(kyc|suspend|block|freeze|बंद|केवाईसी)\b", text, re.IGNORECASE):
            keywords.append("kyc_threat_cue")
        if re.search(r"\b(refundable|deposit|offer letter|task job|joining fee)\b", text, re.IGNORECASE):
            keywords.append("job_deposit_cue")
            
        return {"amount": amt, "keywords": keywords}


class NoveltyDetector:
    """Isolation Forest to detect outlier feature combinations on numeric payment behaviors."""
    def __init__(self, random_state=42):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.06,
            random_state=random_state,
            n_jobs=-1
        )
        self.features = [
            "log_amount",
            "amount_to_user_median_ratio",
            "time_of_day_deviation",
            "recent_tx_velocity_1h",
            "recent_tx_velocity_24h",
            "interaction_time_seconds"
        ]

    def fit(self, df_normal: pd.DataFrame):
        X = df_normal[self.features].fillna(0)
        self.model.fit(X)
        return self

    def score_samples(self, df: pd.DataFrame) -> np.ndarray:
        X = df[self.features].fillna(0)
        # Isolation Forest anomaly score: lower is more anomalous
        return self.model.decision_function(X)


class AssessmentBinding:
    """Issues and validates transaction-bound tamper-evident tokens."""
    @staticmethod
    def generate_token(payment_id: str, session_id: str, recipient: str, amount: float, currency: str, risk_tier: str, recipient_account: str = "") -> str:
        timestamp = int(time.time())
        expiry = timestamp + 600 # 10 minutes validity
        payload = json.dumps([payment_id, session_id, recipient, f"{float(amount):.2f}", currency, risk_tier, timestamp, expiry, recipient_account], ensure_ascii=False, separators=(",", ":"))
        signature = hmac.new(SECRET_KEY, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        token = f"{payload}|{signature}"
        return token

    @staticmethod
    def verify_token(token: str, current_recipient: str, current_amount: float, current_currency: str = "INR", current_account: str = "", payment_id: str = "", session_id: str = "") -> Tuple[bool, str]:
        if not token or "|" not in token:
            return False, "Missing or malformed assessment token."
            
        try:
            expected_payload, sig = token.rsplit("|", 1)
            pid, sid, rec, amt_str, curr, tier, ts_str, exp_str, account = json.loads(expected_payload)
        except (ValueError, TypeError):
            return False, "Invalid token structure."
        expected_sig = hmac.new(SECRET_KEY, expected_payload.encode("utf-8"), hashlib.sha256).hexdigest()
        
        if not hmac.compare_digest(sig, expected_sig):
            return False, "Token signature verification failed (tampered assessment)."
        if payment_id != pid or session_id != sid:
            return False, "Payment or session changed. Reassessment required."
        if account != current_account:
            return False, "Recipient account changed. Reassessment required."
            
        # Check expiry
        now = int(time.time())
        if now > int(exp_str):
            return False, "Assessment expired. Please re-check the payment."
            
        # PAYMENT CHANGE GUARD: Verify fields have not changed since safety assessment!
        if rec.strip().lower() != current_recipient.strip().lower():
            return False, f"Payment destination changed from '{rec}' to '{current_recipient}'. Assessment invalidated."
            
        if f"{float(amt_str):.2f}" != f"{float(current_amount):.2f}":
            return False, f"Payment amount changed from ₹{float(amt_str):,.2f} to ₹{float(current_amount):,.2f}. Assessment invalidated."
            
        if curr.strip().upper() != current_currency.strip().upper():
            return False, f"Currency changed from {curr} to {current_currency}. Assessment invalidated."

        return True, "Valid assessment."


class HybridDecisionEngine:
    """Synthesizes supervised transaction risk, message intent, novelty, and rules."""
    def __init__(
        self,
        tx_model: TransactionRiskClassifier,
        intent_model: MessageIntentClassifier,
        novelty_model: NoveltyDetector,
        threshold_warn: float = 0.50,
        threshold_verify: float = 0.28
    ):
        self.tx_model = tx_model
        self.intent_model = intent_model
        self.novelty_model = novelty_model
        self.threshold_warn = threshold_warn
        self.threshold_verify = threshold_verify

    def score(
        self,
        tx_data: Dict[str, Any],
        merchants_registry: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Scores a candidate payment and renders deterministic reason codes,
        separating Observed Facts, Inferred Intent, and Unavailable Information.
        """
        payment_id = tx_data.get("payment_id") or f"PAY_{uuid.uuid4().hex}"
        session_id = tx_data.get("session_id", "demo-session-1")
        amount = float(tx_data.get("amount", 0.0))
        recipient = str(tx_data.get("recipient") or "Unknown")
        account = str(tx_data.get("recipient_account") or (recipient.lower().replace(" ", "") + "@demo"))
        expected_recipient = str(tx_data.get("expected_recipient") or recipient)
        message = tx_data.get("message", "")
        user_declared_intent = tx_data.get("user_intent", None)
        screen_sharing = int(tx_data.get("screen_sharing", 0))
        device_novelty = int(tx_data.get("device_novelty", 0))
        is_new_recipient = 1 if tx_data.get("prior_recipient_count", 0) == 0 else 0

        # 1. Message Intent Classification
        inferred_intent = "unknown_other"
        intent_confidence = 0.0
        entities = {"amount": None, "keywords": []}
        
        if message and message.strip():
            intent_probs = self.intent_model.predict_proba([message])[0]
            classes = list(self.intent_model.calibrated_pipeline.classes_)
            top_idx = int(np.argmax(intent_probs))
            inferred_intent = classes[top_idx]
            intent_confidence = float(intent_probs[top_idx])
            entities = self.intent_model.extract_entities(message)

        # 2. Check Merchant Reference Registry
        merchant_status = 3 # unavailable
        ref_explanation = "No independent merchant record found."
        
        if merchants_registry and account in merchants_registry:
            m_info = merchants_registry[account]
            if m_info["name"].lower() == expected_recipient.lower():
                merchant_status = 0 # match
                ref_explanation = "Destination matches the independently verified merchant record."
            elif any(alias.lower() == recipient.lower() for alias in m_info.get("aliases", [])):
                merchant_status = 2 # alias_approved
                ref_explanation = f"Destination matches verified merchant; '{recipient}' is an approved proprietor alias."
            else:
                merchant_status = 1 # mismatch
                ref_explanation = f"QR destination '{account}' differs from expected merchant '{expected_recipient}'."
        elif merchants_registry:
            expected_record = next((m for m in merchants_registry.values() if expected_recipient.casefold() in [m['name'].casefold(), *[a.casefold() for a in m.get('aliases', [])]]), None)
            if expected_record:
                merchant_status = 1
                ref_explanation = f"QR destination differs from the independent saved record for {expected_record['name']}."

        # 3. Supervised Transaction ML Score
        df_single = None
        if "precomputed_tx_prob" in tx_data:
            tx_prob = float(tx_data["precomputed_tx_prob"])
            novelty_score = float(tx_data.get("precomputed_novelty_score", 0.05))
            feature_contributions = tx_data.get("feature_contributions", {"Transaction behavioral score": round(tx_prob * 100, 1)})
        else:
            df_single = pd.DataFrame([{
                "amount": amount,
                "log_amount": np.log1p(amount),
                "amount_to_user_median_ratio": tx_data.get("amount_to_user_median_ratio", amount / 500.0),
                "prior_recipient_count": tx_data.get("prior_recipient_count", 0),
                "is_new_recipient": 1 if tx_data.get("prior_recipient_count", 0) == 0 else 0,
                "time_of_day_deviation": tx_data.get("time_of_day_deviation", 1.5),
                "recent_tx_velocity_1h": tx_data.get("recent_tx_velocity_1h", 0),
                "recent_tx_velocity_24h": tx_data.get("recent_tx_velocity_24h", 1),
                "device_novelty": device_novelty,
                "interaction_time_seconds": tx_data.get("interaction_time_seconds", 12.0),
                "screen_recording_active": screen_sharing,
                "merchant_reference_status": merchant_status
            }])
            tx_prob = float(self.tx_model.predict_proba(df_single)[0][1])
            feature_contributions = self.tx_model.get_feature_contributions(df_single.iloc[0])
            novelty_score = float(self.novelty_model.score_samples(df_single)[0])

        is_novel = novelty_score < -0.05

        # 5. Core Contradiction & Decision Policy
        # Check Direction Contradiction: User pays outgoing money, but message/intent promises incoming refund/reward
        is_p2p_return = (
            inferred_intent == "return_money" or
            bool(re.search(r"\b(borrowed|returning|udhaar|udhar|share|split|loan|dost|dinner|trip|petrol)\b", message, re.IGNORECASE))
        )

        # Receiving an offer letter is not a promise to receive money. The original
        # classifier has never seen the held-out deposit family; keep its raw
        # interpretation in the result, but don't turn it into an observed refund.
        is_job_deposit = "job_deposit_cue" in entities["keywords"] or inferred_intent == "job_deposit"
        is_refund_promise = user_declared_intent == "receive" or (not is_p2p_return and not is_job_deposit and (
            inferred_intent == "receive_refund_reward" or
            user_declared_intent == "receive" or
            "refund_incoming_cue" in entities["keywords"] or
            bool(re.search(r"\b(refund|cashback|reward|claim|bonus|रिफंड)\b", message, re.IGNORECASE))
        ))

        observed_facts = [
            f"Payment amount: ₹{amount:,.2f} leaving your account (outgoing debit).",
            f"Destination VPA: {account} ({recipient}).",
            "Payment direction: Outgoing (debit)."
        ]
        
        if is_new_recipient == 1:
            observed_facts.append("First payment to this recipient.")
        if screen_sharing == 1:
            observed_facts.append("Simulated screen sharing / recording is active.")
            
        inferred_facts = []
        if message:
            inferred_facts.append(f"Supplied message interpreted as: {inferred_intent.replace('_', ' ').title()} (confidence {intent_confidence*100:.1f}%).")
            
        missing_signals = []
        if merchant_status == 3:
            missing_signals.append("Independent merchant directory confirmation unavailable.")
        if not message:
            missing_signals.append("Payment message context was omitted.")

        # Evaluate risk tiers:
        # Rule 1: Strong Intent Contradiction -> HIGH RISK / WARN
        if is_refund_promise:
            risk_tier = "high"
            category = "Refund deception"
            reason = "Incoming refund/reward promised in message, but payment sends outgoing money."
            inferred_facts.append("The supplied message appears to promise incoming money; the observed payment sends money from your account.")

        # Rule 2: QR Destination Mismatch -> HIGH RISK / WARN
        elif merchant_status == 1:
            risk_tier = "high"
            category = "QR substitution"
            reason = ref_explanation
            observed_facts.append(ref_explanation)

        # Rule 3: Fake KYC threat -> HIGH RISK / WARN
        elif inferred_intent == "kyc_threat" or "kyc_threat_cue" in entities["keywords"]:
            risk_tier = "high"
            category = "Fake KYC"
            reason = "Urgent account block threat demanding verification fee to an unrelated account."
            inferred_facts.append("The supplied message appears to threaten account suspension and request a verification transfer.")

        # Rule 4: Remote Access Sharing -> HIGH RISK / WARN
        elif screen_sharing == 1 and (is_new_recipient == 1 or tx_prob > 0.35):
            risk_tier = "high"
            category = "Remote access risk"
            reason = "Screen sharing is active during payment to a first-time or high-risk recipient."

        # Rule 5: Job deposit pattern (held-out / adaptation pattern)
        elif inferred_intent == "job_deposit" or "job_deposit_cue" in entities["keywords"]:
            risk_tier = "medium" if tx_prob < 0.6 else "high"
            category = "Unfamiliar pattern"
            reason = "Job task offer requesting upfront refundable deposit to an unverified recipient."

        # Rule 6: High Supervised ML Risk
        elif tx_prob >= self.threshold_warn:
            risk_tier = "high"
            category = "High risk transaction"
            reason = "Multiple behavioral risk signals exceed the safe threshold."

        # Rule 7: Medium Risk / Verification needed
        elif tx_prob >= self.threshold_verify or is_novel or merchant_status == 3:
            risk_tier = "medium"
            category = "Identity unavailable" if merchant_status == 3 else "Needs review"
            reason = "Independent identity unavailable or transaction has unfamiliar patterns."

        # Rule 8: Low Risk / Safe
        else:
            risk_tier = "low"
            category = "Merchant payment"
            reason = "Destination matches trusted record and transaction attributes align with normal behavior."

        # Cryptographically signed assessment token
        token = AssessmentBinding.generate_token(
            payment_id=payment_id,
            session_id=session_id,
            recipient=recipient,
            amount=amount,
            currency="INR",
            risk_tier=risk_tier,
            recipient_account=account
        )

        return {
            "assessment_id": f"UG-{uuid.uuid4().hex[:16]}",
            "payment_id": payment_id,
            "session_id": session_id,
            "amount": amount,
            "currency": "INR",
            "recipient": recipient,
            "account": account,
            "risk_tier": risk_tier,
            "category": category,
            "primary_reason": reason,
            "ml_fraud_probability": round(tx_prob, 4),
            "novelty_score": round(novelty_score, 4),
            "inferred_intent": inferred_intent,
            "intent_confidence": round(intent_confidence, 4),
            "merchant_status": merchant_status,
            "merchant_reference": ref_explanation,
            "observed_facts": observed_facts,
            "inferred_facts": inferred_facts,
            "missing_signals": missing_signals,
            "feature_contributions": feature_contributions,
            "assessment_token": token,
            "model_version": "hybrid-v1.3",
            "timestamp": int(time.time())
        }

def save_pipeline(
    tx_model: TransactionRiskClassifier,
    intent_model: MessageIntentClassifier,
    novelty_model: NoveltyDetector,
    metadata: Dict[str, Any],
    models_dir: str = "models",
    prefix: str = ""
):
    os.makedirs(models_dir, exist_ok=True)
    p = f"{prefix}_" if prefix else ""
    joblib.dump(tx_model, os.path.join(models_dir, f"{p}tx_model.joblib"))
    joblib.dump(intent_model, os.path.join(models_dir, f"{p}intent_model.joblib"))
    joblib.dump(novelty_model, os.path.join(models_dir, f"{p}novelty_model.joblib"))
    
    with open(os.path.join(models_dir, f"{p}metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

def load_pipeline(models_dir: str = "models", prefix: str = "") -> Tuple[TransactionRiskClassifier, MessageIntentClassifier, NoveltyDetector, Dict[str, Any]]:
    p = f"{prefix}_" if prefix else ""
    tx_model = joblib.load(os.path.join(models_dir, f"{p}tx_model.joblib"))
    intent_model = joblib.load(os.path.join(models_dir, f"{p}intent_model.joblib"))
    novelty_model = joblib.load(os.path.join(models_dir, f"{p}novelty_model.joblib"))
    
    meta_path = os.path.join(models_dir, f"{p}metadata.json")
    metadata = {}
    if os.path.exists(meta_path):
        with open(meta_path, "r") as f:
            metadata = json.load(f)
            
    return tx_model, intent_model, novelty_model, metadata
