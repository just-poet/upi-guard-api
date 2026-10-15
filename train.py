"""
UPI Guard - Model Training Pipeline
Trains the complete multi-modal AI detection suite:
1. Supervised Transaction Risk Tree Model (Random Forest with Sigmoid Calibration)
2. Multilingual Message Intent Classifier (TF-IDF + Logistic Regression)
3. Unsupervised Novelty Detector (Isolation Forest)
4. Candidate Model (v1.4) for Pattern Lab Adaptation Experiment

Usage:
  python train.py
  python train.py --epochs-fast --data-dir data --models-dir models
"""

import os
import sys
import json
import time
import argparse
import numpy as np
import pandas as pd
from datetime import datetime

# Windows encoding safety
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from model_pipeline import (
    TransactionRiskClassifier,
    MessageIntentClassifier,
    NoveltyDetector,
    HybridDecisionEngine,
    save_pipeline
)

def print_header(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def main():
    parser = argparse.ArgumentParser(description="UPI Guard Model Training Suite")
    parser.add_argument("--data-dir", type=str, default="data", help="Directory containing generated datasets")
    parser.add_argument("--models-dir", type=str, default="models", help="Directory to save trained model artifacts")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    start_total_time = time.time()
    print_header("UPI GUARD: AI DETECTION OF CREATIVE PAYMENT FRAUDS - TRAINING")
    print(f"[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Data directory:   {args.data_dir}")
    print(f"[*] Models directory: {args.models_dir}")

    # Check if data exists; if not, generate it automatically
    train_tx_path = os.path.join(args.data_dir, "train_transactions.csv")
    if not os.path.exists(train_tx_path):
        print("\n[!] Dataset files not found. Automatically generating 40,000 transactions...")
        from download_and_generate_dataset import main as gen_main
        gen_main()

    # 1. LOAD DATASETS
    print("\n[1/5] Loading partitioned datasets...")
    df_train = pd.read_csv(train_tx_path)
    df_val = pd.read_csv(os.path.join(args.data_dir, "val_transactions.csv"))
    df_messages = pd.read_csv(os.path.join(args.data_dir, "messages.csv"))
    
    print(f"  - Training transactions:   {len(df_train):,} rows (Fraud: {df_train['is_fraud'].sum():,})")
    print(f"  - Validation transactions: {len(df_val):,} rows (Fraud: {df_val['is_fraud'].sum():,})")
    print(f"  - Multilingual messages:   {len(df_messages):,} rows across {df_messages['intent'].nunique()} intents")

    # 2. TRAIN MESSAGE INTENT CLASSIFIER (Multilingual: EN, HI, Hinglish)
    print("\n[2/5] Training Multilingual Message Intent Classifier...")
    t0 = time.time()
    
    # Page 10 protocol: Exclude 'job_deposit' from initial v1.3 training
    df_msg_train = df_messages[df_messages["intent"] != "job_deposit"].copy().reset_index(drop=True)
    
    intent_model = MessageIntentClassifier(random_state=args.seed)
    intent_model.fit(df_msg_train["text"].tolist(), df_msg_train["intent"].tolist())
    
    # Quick sanity validation
    sample_tests = [
        ("Your refund of ₹5,000 is ready. Tap to receive.", "receive_refund_reward"),
        ("Aapka Rs 2000 refund process ho gaya, click karein", "receive_refund_reward"),
        ("रिफंड पाने के लिए कृपया भुगतान स्वीकार करें", "receive_refund_reward"),
        ("Medicines bill ₹450 at counter", "purchase"),
        ("Bhai kal ke petrol ke paise wapas bhej raha hoon ₹400", "return_money"),
        ("URGENT: Bank account block ho jayega, pay KYC fee ₹99", "kyc_threat")
    ]
    correct = 0
    for text, expected in sample_tests:
        pred = intent_model.predict([text])[0]
        if pred == expected:
            correct += 1
    intent_acc = (correct / len(sample_tests)) * 100
    print(f"  [+] Intent Classifier trained in {time.time() - t0:.2f}s | Sanity Accuracy: {intent_acc:.1f}%")
    print(f"      Classes recognized: {list(intent_model.calibrated_pipeline.classes_)}")

    # 3. TRAIN SUPERVISED TRANSACTION RISK TREE MODEL
    print("\n[3/5] Training Supervised Transaction Risk Scorer (Calibrated Random Forest)...")
    t0 = time.time()
    
    y_train = df_train["is_fraud"]
    y_val = df_val["is_fraud"]
    
    tx_model = TransactionRiskClassifier(n_estimators=140, max_depth=12, random_state=args.seed)
    tx_model.fit(df_train, y_train, df_val, y_val)
    
    # Feature importances
    print(f"  [+] Transaction Model trained in {time.time() - t0:.2f}s")
    print("      Top Behavioral Feature Importances:")
    sorted_fi = sorted(tx_model.feature_importances_.items(), key=lambda x: x[1], reverse=True)
    for feat, imp in sorted_fi[:6]:
        print(f"        - {feat:<28}: {imp*100:5.2f}%")

    # 4. TRAIN NOVELTY & ANOMALY DETECTOR (Isolation Forest)
    print("\n[4/5] Training Novelty & Anomaly Detector (Isolation Forest)...")
    t0 = time.time()
    df_normal = df_train[df_train["is_fraud"] == 0].copy()
    novelty_model = NoveltyDetector(random_state=args.seed)
    novelty_model.fit(df_normal)
    print(f"  [+] Novelty Detector fitted on {len(df_normal):,} legitimate transactions in {time.time() - t0:.2f}s")

    # VALIDATION THRESHOLD TUNING (Page 9: Legitimate FPR < 1%, Known-Scam Recall > 85%)
    print("\n[*] Tuning Decision Thresholds on Validation Partition...")
    val_probs = tx_model.predict_proba(df_val)[:, 1]
    
    # Search for threshold with FPR <= 0.01 (1%)
    thresholds = np.linspace(0.2, 0.8, 61)
    best_thresh = 0.50
    best_recall = 0.0
    
    for th in thresholds:
        preds = (val_probs >= th).astype(int)
        fp = ((preds == 1) & (y_val == 0)).sum()
        fpr = fp / (y_val == 0).sum()
        tp = ((preds == 1) & (y_val == 1)).sum()
        recall = tp / (y_val == 1).sum()
        
        if fpr <= 0.010 and recall > best_recall:
            best_recall = recall
            best_thresh = th
            
    print(f"  [+] Optimal Operating Threshold: {best_thresh:.2f} (Val Recall: {best_recall*100:.2f}%, FPR <= 1.0%)")

    # SAVE BASELINE PIPELINE (v1.3)
    meta_v13 = {
        "model_version": "v1.3-baseline",
        "trained_at": datetime.now().isoformat(),
        "training_samples": len(df_train),
        "validation_samples": len(df_val),
        "threshold_warn": round(float(best_thresh), 2),
        "threshold_verify": 0.28,
        "feature_importances": tx_model.feature_importances_,
        "classes": list(intent_model.calibrated_pipeline.classes_)
    }
    save_pipeline(tx_model, intent_model, novelty_model, meta_v13, models_dir=args.models_dir, prefix="base")
    # Also save as default active model
    save_pipeline(tx_model, intent_model, novelty_model, meta_v13, models_dir=args.models_dir, prefix="")
    print(f"  [+] Active Model artifacts saved to '{args.models_dir}/'")

    # 5. TRAIN CANDIDATE MODEL (v1.4) FOR PATTERN LAB ADAPTATION EXPERIMENT (Page 10)
    print("\n[5/5] Training Candidate Model (v1.4) with Pattern Lab Held-Out Adaptation Slice...")
    t0 = time.time()
    
    # Load held-out job deposit scam
    job_scam_path = os.path.join(args.data_dir, "held_out_job_scam.csv")
    df_candidate_train = df_train.copy()
    
    if os.path.exists(job_scam_path):
        df_job = pd.read_csv(job_scam_path)
        # Take 50% of the job deposit cases as analyst-labeled training batch, reserve remaining 50% for untouched test evaluation
        n_adapt = len(df_job) // 2
        df_adapt_batch = df_job.iloc[:n_adapt].copy()
        df_candidate_train = pd.concat([df_train, df_adapt_batch], ignore_index=True)
        print(f"  - Incorporating {len(df_adapt_batch)} analyst-reviewed 'job_deposit' scam examples into Candidate v1.4")
    
    # Candidate Intent Model (trained on full messages including job_deposit)
    candidate_intent = MessageIntentClassifier(random_state=args.seed)
    candidate_intent.fit(df_messages["text"].tolist(), df_messages["intent"].tolist())
    
    # Candidate Transaction Risk Scorer
    candidate_tx = TransactionRiskClassifier(n_estimators=140, max_depth=12, random_state=args.seed)
    candidate_tx.fit(df_candidate_train, df_candidate_train["is_fraud"], df_val, y_val)
    
    meta_v14 = {
        "model_version": "v1.4-candidate",
        "trained_at": datetime.now().isoformat(),
        "training_samples": len(df_candidate_train),
        "adaptation_pattern": "job_deposit",
        "threshold_warn": round(float(best_thresh), 2),
        "threshold_verify": 0.28,
        "feature_importances": candidate_tx.feature_importances_,
        "classes": list(candidate_intent.calibrated_pipeline.classes_)
    }
    save_pipeline(candidate_tx, candidate_intent, novelty_model, meta_v14, models_dir=args.models_dir, prefix="candidate")
    print(f"  [+] Candidate v1.4 Model trained in {time.time() - t0:.2f}s and saved to '{args.models_dir}/candidate_*'")

    elapsed = time.time() - start_total_time
    print_header("TRAINING COMPLETE")
    print(f"[OK] Full multi-modal model suite trained successfully in {elapsed:.2f}s!")
    print(f"[OK] Artifacts saved in '{args.models_dir}':")
    print("    - tx_model.joblib & candidate_tx_model.joblib")
    print("    - intent_model.joblib & candidate_intent_model.joblib")
    print("    - novelty_model.joblib")
    print("    - metadata.json & candidate_metadata.json")
    print("\nNext step: Run evaluation to verify accuracy and benchmark metrics:")
    print("    python evaluate.py\n")

if __name__ == "__main__":
    main()
