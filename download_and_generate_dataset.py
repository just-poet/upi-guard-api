"""
UPI Guard - Dataset Generator & Downloader
Implements the dataset specifications from the CC6-AI02 UPI Guard Research Proposal:
- 1,000 synthetic users
- 150 merchants with verified records and proprietor aliases
- 40,000 chronological transactions (30,000 - 50,000 range)
- 3,000+ multilingual messages across 6 intent classes (English, Hindi, Hinglish)
- Difficult legitimate controls (P2P return, approved proprietor aliases, normal high-value payments)
- Held-out partition for unseen 'job_deposit' scam family for Pattern Lab adaptation
"""

import os
import json
import random
import argparse
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

def set_seed(seed=42):
    random.seed(seed)
    np.random.seed(seed)

FIRST_NAMES = [
    "Aarav", "Priya", "Rohan", "Ananya", "Vikram", "Sneha", "Aditya", "Pooja", 
    "Rahul", "Neha", "Arjun", "Kavya", "Amit", "Divya", "Suresh", "Meera", 
    "Rajesh", "Sunita", "Deepak", "Ritu", "Manish", "Swati", "Sanjay", "Preeti",
    "Karan", "Simran", "Varun", "Isha", "Naveen", "Shreya", "Gaurav", "Nisha"
]

LAST_NAMES = [
    "Mehta", "Nair", "Verma", "Sharma", "Singh", "Patel", "Gupta", "Kumar",
    "Iyer", "Reddy", "Joshi", "Chopra", "Malhotra", "Das", "Bose", "Kulkarni",
    "Deshmukh", "Aggarwal", "Bhatia", "Saxena", "Kapoor", "Mishra", "Pandey"
]

MERCHANT_PRESETS = [
    {"name": "Sharma Medical", "category": "pharma", "vpa": "sharmamedical@demo", "proprietor": "Rajesh Sharma", "aliases": ["Rajesh Sharma", "Sharma Pharmacy"]},
    {"name": "Campus Canteen", "category": "dining", "vpa": "campuscanteen@demo", "proprietor": "Sunil Shetty", "aliases": ["Sunil Shetty", "Canteen Foods"]},
    {"name": "Apollo Pharmacy", "category": "pharma", "vpa": "apollopharmacy@demo", "proprietor": "Apollo Health Ltd", "aliases": ["Apollo Retail"]},
    {"name": "Daily Fresh Grocery", "category": "grocery", "vpa": "dailyfresh@demo", "proprietor": "Mohan Lal", "aliases": ["Mohan Lal Kirana", "Daily Fresh Supermarket"]},
    {"name": "Chai Point", "category": "dining", "vpa": "chaipoint@demo", "proprietor": "Mountain Trail Foods", "aliases": ["Chai Point Express"]},
    {"name": "Reliance Smart", "category": "retail", "vpa": "reliancesmart@demo", "proprietor": "Reliance Retail Ltd", "aliases": ["Smart Bazaar"]},
    {"name": "A-1 Electronics", "category": "electronics", "vpa": "a1electronics@demo", "proprietor": "Harish Bajaj", "aliases": ["Harish Bajaj Electronics"]},
    {"name": "City General Hospital", "category": "healthcare", "vpa": "cityhospital@demo", "proprietor": "City Care Trust", "aliases": ["City Hospital Billing"]},
    {"name": "Metro Station Kiosk", "category": "transport", "vpa": "metrokiosk@demo", "proprietor": "DMRC Retail", "aliases": ["Metro SmartCard Recharge"]},
    {"name": "Modern Book Depot", "category": "retail", "vpa": "modernbooks@demo", "proprietor": "Alok Mathur", "aliases": ["Mathur Book Store"]}
]

MESSAGE_TEMPLATES = {
    "receive_refund_reward": [
        # English
        ("Your refund of ₹{amt} for order #{order} is approved. Click and authorise to receive payment into your bank account.", "en"),
        ("Congratulations! You have received ₹{amt} cashback reward from payment gateway. Claim now by tapping link.", "en"),
        ("Dear customer, your electricity bill excess payment of ₹{amt} is refunded. Tap to accept credit.", "en"),
        ("Refund initiated: ₹{amt} will be credited once you confirm the payment request on this link.", "en"),
        ("You have won a scratch card bonus of ₹{amt}! Approve this request to claim your instant reward.", "en"),
        ("Refund department: Click here to receive your security deposit refund of ₹{amt}.", "en"),
        # Hindi
        ("आपके ऑर्डर #{order} का ₹{amt} का रिफंड तैयार है। तुरंत अपने खाते में पैसे पाने के लिए इस लिंक पर क्लिक करें और स्वीकार करें।", "hi"),
        ("बधाई हो! आपको ₹{amt} का कैशबैक रिवॉर्ड मिला है। पैसे लेने के लिए तुरंत भुगतान अनुरोध स्वीकार करें।", "hi"),
        ("बिजली बिल का अतिरिक्त ₹{amt} रिफंड आपके खाते में भेजा जा रहा है। लिंक पर जाकर क्लेम करें।", "hi"),
        ("रिफंड पाने के लिए कृपया इस भुगतान को स्वीकार करें और पैसे प्राप्त करें।", "hi"),
        # Hinglish
        ("Aapka Rs {amt} refund order #{order} ka issue ho chuka hai. Link open karke payment approve karein aur refund receive karein.", "hinglish"),
        ("Congratulations! Aapko Rs {amt} cashback reward mila hai, turant collect karne ke liye tap karein.", "hinglish"),
        ("Refund department se call tha, Rs {amt} receive karne ke liye ye request accept karo abhi.", "hinglish"),
        ("Aapke account me Rs {amt} wapas bhej rahe hain, link par jaakar receive karein.", "hinglish")
    ],
    "purchase": [
        # English
        ("Your medicines total ₹{amt}. Please pay {merchant} at the counter.", "en"),
        ("Invoice #{order}: ₹{amt} for grocery delivery from {merchant}. Pay via UPI.", "en"),
        ("Bill for your meal at {merchant}: ₹{amt}. Thank you for dining with us!", "en"),
        ("Please pay ₹{amt} for your books and stationery purchase at {merchant}.", "en"),
        ("Utility payment: ₹{amt} for monthly maintenance bill. Receipt will be generated.", "en"),
        ("Your order #{order} is ready. Total amount payable is ₹{amt}.", "en"),
        # Hindi
        ("दुकान का बिल ₹{amt} है। कृपया काउंटर पर {merchant} को भुगतान करें।", "hi"),
        ("किराना सामान का बिल ₹{amt}। धन्यवाद!", "hi"),
        ("दवाइयों का कुल बिल ₹{amt} हुआ। कृपया यूपीआई से भुगतान करें।", "hi"),
        # Hinglish
        ("Bhaiya stationery ka total bill ₹{amt} hua, pay kar dijiye.", "hinglish"),
        ("Medicines ka total ₹{amt} hai, counter par QR scan karke pay kar do.", "hinglish"),
        ("Kirana store bill ₹{amt}, delivery boy ko pay karein.", "hinglish")
    ],
    "return_money": [ # Difficult legitimate control: user returning money to friend/family
        # English
        ("Hey {name}, returning the ₹{amt} I borrowed for dinner yesterday! Thanks a lot.", "en"),
        ("Here is my share for the cab ride: ₹{amt}. Sent via UPI.", "en"),
        ("Returning ₹{amt} for the movie tickets. Thanks for booking!", "en"),
        ("Paying back ₹{amt} towards the weekend trip expenses. Let me know when received.", "en"),
        ("Hi, transferring ₹{amt} as promised for last week's groceries.", "en"),
        # Hindi
        ("आरव, कल के खाने के लिए जो पैसे लिए थे, वह ₹{amt} वापस कर रहा हूँ। बहुत धन्यवाद!", "hi"),
        ("गाड़ी के किराए का मेरा हिस्सा ₹{amt} भेज रहा हूँ।", "hi"),
        ("उधार लिए पैसे ₹{amt} वापस कर रहा हूँ, चेक कर लेना भाई।", "hi"),
        # Hinglish
        ("Bhai kal jo udhaar liya tha wo ₹{amt} wapas bhej raha hu, thanks!", "hinglish"),
        ("Trip ka split payment ₹{amt} send kar diya hai, confirm karna.", "hinglish"),
        ("Kal ke petrol ke paise bhej raha hoon ₹{amt}.", "hinglish")
    ],
    "kyc_threat": [
        # English
        ("URGENT NOTICE: Your bank account will be permanently closed today. Pay ₹{amt} verification fee to update KYC immediately.", "en"),
        ("SBI alert: UPI services blocked due to pending PAN-Aadhaar KYC. Pay ₹{amt} to re-activate within 2 hours.", "en"),
        ("Dear customer, KYC verification expired. Deposit ₹{amt} to avoid legal freeze and penalty.", "en"),
        ("Account Suspension Warning: Transfer ₹{amt} to verify active account holder identity now.", "en"),
        # Hindi
        ("अति आवश्यक: आपका बैंक खाता आज बंद कर दिया जाएगा। केवाईसी पूरा करने के लिए तुरंत ₹{amt} का भुगतान करें।", "hi"),
        ("चेतावनी: आपका यूपीआई ब्लॉक कर दिया गया है। चालू रखने के लिए ₹{amt} सत्यापन शुल्क भरें।", "hi"),
        ("केवाईसी अपडेट न होने पर खाता फ्रीज होगा। तुरंत ₹{amt} जमा करें।", "hi"),
        # Hinglish
        ("ALERT: Aapka bank account aaj suspend ho jayega. Turant KYC update fee ₹{amt} pay karein warna account block.", "hinglish"),
        ("Urgent notice: PAN card verify nahi hua. ₹{amt} pay karke KYC re-activate karein 1 ghante me.", "hinglish")
    ],
    "job_deposit": [ # Held-out family for unseen scam evaluation!
        # English
        ("Congratulations! You are shortlisted for Part-Time Task Evaluator role (₹3,000/day). Pay refundable security deposit ₹{amt} to receive official offer letter.", "en"),
        ("Work-from-home typing job approved: Deposit refundable training fee ₹{amt} to unlock your high-paying portal access.", "en"),
        ("Amazon product review task: Pay ₹{amt} refundable onboarding fee to activate daily VIP commission tasks.", "en"),
        ("Telegram data rating job: Deposit ₹{amt} refundable guarantee to receive contract and equipment allowance.", "en"),
        # Hindi
        ("बधाई! पार्ट-टाइम जॉब के लिए आपका चयन हुआ है। ऑफर लेटर प्राप्त करने के लिए ₹{amt} की रिफंडेबल सिक्योरिटी डिपॉजिट जमा करें।", "hi"),
        ("घर बैठे डेटा एंट्री कार्य: ₹{amt} रिफंडेबल फीस जमा करके आज ही काम शुरू करें।", "hi"),
        ("टेलीग्राम टास्क जॉब: रोजाना ₹2,500 कमाएं। रिफंडेबल सुरक्षा राशि ₹{amt} जमा करें।", "hi"),
        # Hinglish
        ("Congratulations! Part time data entry job confirm ho gaya hai. Offer letter pane ke liye refundable onboarding deposit ₹{amt} pay karein.", "hinglish"),
        ("Work from home task job: Rs {amt} refundable security jama karein aur daily payment paayein.", "hinglish"),
        ("Telegram VIP task: Deposit ₹{amt} refundable registration fee to start earning daily.", "hinglish")
    ],
    "unknown_other": [
        ("Thank you! Have a great day.", "en"),
        ("See you tomorrow at 5 PM.", "en"),
        ("Happy birthday! Best wishes.", "en"),
        ("Got it, thanks.", "en"),
        ("धन्यवाद!", "hi"),
        ("कल मिलते हैं भाई।", "hi"),
        ("Theek hai bhai kal milte hain.", "hinglish"),
        ("Payment done.", "en"),
        ("Ok thanks", "en")
    ]
}

def generate_users(n_users=1000):
    users = []
    for i in range(1, n_users + 1):
        fn = random.choice(FIRST_NAMES)
        ln = random.choice(LAST_NAMES)
        name = f"{fn} {ln}"
        vpa_handle = f"{fn.lower()}{random.randint(10, 99)}@okaxis"
        median_amt = round(float(np.random.lognormal(mean=5.8, sigma=0.6)), 2) # median ~330 - ~800
        typical_hour = int(np.clip(np.random.normal(loc=15, scale=3), 8, 22))
        users.append({
            "user_id": f"USR_{i:04d}",
            "name": name,
            "vpa": vpa_handle,
            "median_amount": median_amt,
            "typical_hour": typical_hour,
            "created_days_ago": random.randint(60, 600)
        })
    return users

def generate_merchants(n_merchants=150):
    merchants = list(MERCHANT_PRESETS)
    categories = ["retail", "grocery", "pharma", "dining", "services", "utilities", "electronics"]
    
    for i in range(len(merchants) + 1, n_merchants + 1):
        fn = random.choice(FIRST_NAMES)
        ln = random.choice(LAST_NAMES)
        cat = random.choice(categories)
        tag = random.choice(["Store", "Enterprises", "Traders", "Pharmacy", "Cafe", "Bazaar", "Depot", "Stationery"])
        m_name = f"{ln} {tag}"
        vpa = f"{ln.lower()}{tag.lower()}{i}@demo"
        proprietor = f"{fn} {ln}"
        aliases = [proprietor, f"{fn} Traders", f"{ln} Store"]
        merchants.append({
            "name": m_name,
            "category": cat,
            "vpa": vpa,
            "proprietor": proprietor,
            "aliases": aliases,
            "merchant_id": f"MERCH_{i:03d}"
        })
    return merchants

def generate_messages(n_messages=3000):
    records = []
    intent_classes = list(MESSAGE_TEMPLATES.keys())
    # Generate balanced distribution with held-out job_deposit
    while len(records) < n_messages:
        intent = random.choice(intent_classes)
        templates = MESSAGE_TEMPLATES[intent]
        tmpl, lang = random.choice(templates)
        amt = random.choice([99, 180, 250, 450, 500, 800, 1200, 1500, 2000, 3500, 5000, 10000])
        order = random.randint(1024, 9890)
        merchant = random.choice(MERCHANT_PRESETS)["name"]
        name = random.choice(FIRST_NAMES)
        
        text = tmpl.format(amt=amt, order=order, merchant=merchant, name=name)
        records.append({
            "message_id": f"MSG_{len(records)+1:05d}",
            "text": text,
            "intent": intent,
            "language": lang,
            "extracted_amount": amt if intent in ["receive_refund_reward", "purchase", "kyc_threat", "job_deposit"] else None
        })
    return records

def generate_transactions(users, merchants, messages, n_transactions=40000):
    start_time = datetime(2026, 9, 15, 8, 0, 0)
    tx_list = []
    
    # Pre-index messages by intent
    msg_by_intent = {}
    for m in messages:
        msg_by_intent.setdefault(m["intent"], []).append(m)
        
    user_tx_history = {u["user_id"]: [] for u in users}
    user_payee_history = {u["user_id"]: set() for u in users}

    # Simulation timeline
    current_time = start_time
    time_step_seconds = (30 * 86400) / n_transactions

    for i in range(1, n_transactions + 1):
        current_time += timedelta(seconds=random.uniform(0.5, 2.0) * time_step_seconds)
        user = random.choice(users)
        uid = user["user_id"]
        user_median = user["median_amount"]
        
        # Decide transaction archetype:
        # ~88% Legitimate, ~12% Fraud candidates (including ~2.5% held-out job scams)
        roll = random.random()
        
        if roll < 0.88:
            # LEGITIMATE TRANSACTION
            is_fraud = 0
            sub_roll = random.random()
            
            if sub_roll < 0.65:
                # Normal merchant purchase
                scam_cat = "legitimate_merchant_purchase"
                merch = random.choice(merchants)
                
                # Check proprietor alias variation
                if random.random() < 0.15 and merch.get("aliases"):
                    recipient_name = merch["proprietor"]
                    merchant_ref_status = 2 # alias_approved
                else:
                    recipient_name = merch["name"]
                    merchant_ref_status = 0 # match
                    
                recipient_account = merch["vpa"]
                amount = round(float(np.random.lognormal(mean=np.log(user_median), sigma=0.5)), 2)
                amount = max(10.0, min(amount, 45000.0))
                
                msg_obj = random.choice(msg_by_intent["purchase"] + msg_by_intent["unknown_other"])
                msg_text = msg_obj["text"]
                msg_lang = msg_obj["language"]
                user_intent = "pay"
                screen_recording = 0
                device_novelty = 1 if random.random() < 0.05 else 0
                
            elif sub_roll < 0.88:
                # Legitimate P2P transfer / returning borrowed money (Hard control)
                scam_cat = "legitimate_p2p_return"
                other_user = random.choice(users)
                while other_user["user_id"] == uid:
                    other_user = random.choice(users)
                recipient_name = other_user["name"]
                recipient_account = other_user["vpa"]
                merchant_ref_status = 3 # unavailable (personal P2P)
                
                amount = round(float(random.choice([150, 300, 500, 800, 1200, 2000, 5000])), 2)
                msg_obj = random.choice(msg_by_intent["return_money"])
                msg_text = msg_obj["text"]
                msg_lang = msg_obj["language"]
                user_intent = "pay"
                screen_recording = 0
                device_novelty = 1 if random.random() < 0.06 else 0
                
            else:
                # Legitimate cashback followup or utility payment
                scam_cat = "legitimate_utility_or_cashback"
                merch = random.choice(merchants[:10])
                recipient_name = merch["name"]
                recipient_account = merch["vpa"]
                merchant_ref_status = 0
                amount = round(float(random.choice([450, 699, 999, 1499, 2499])), 2)
                msg_obj = random.choice(msg_by_intent["purchase"])
                msg_text = msg_obj["text"]
                msg_lang = msg_obj["language"]
                user_intent = "pay"
                screen_recording = 0
                device_novelty = 0

        else:
            # FRAUDULENT SCENARIO
            is_fraud = 1
            fraud_type_roll = random.random()
            
            if fraud_type_roll < 0.35:
                # 1. REFUND DECEPTION SCAM
                scam_cat = "refund_deception"
                recipient_name = random.choice(["Ravi Enterprises", "Quick Refund Hub", "Support Desk Online", "Customer Help Care"])
                recipient_account = f"{recipient_name.lower().replace(' ', '')}@demo"
                merchant_ref_status = 3 # unavailable
                amount = round(float(random.choice([2000, 3500, 5000, 8500, 12000, 19500])), 2)
                msg_obj = random.choice(msg_by_intent["receive_refund_reward"])
                msg_text = msg_obj["text"]
                msg_lang = msg_obj["language"]
                user_intent = "receive" # User falsely believes they will receive money!
                screen_recording = 1 if random.random() < 0.25 else 0
                device_novelty = 1 if random.random() < 0.35 else 0

            elif fraud_type_roll < 0.60:
                # 2. QR SUBSTITUTION SCAM
                scam_cat = "qr_substitution"
                shop = random.choice(merchants)
                recipient_name = random.choice(["Amit Personal", "Rakesh Kumar", "Mule Account 204", "Sunil P2P"])
                recipient_account = f"{recipient_name.lower().replace(' ', '')}@demo"
                merchant_ref_status = 1 # MISMATCH: Shop QR replaced with rogue personal VPA!
                amount = round(float(random.choice([120, 180, 240, 350, 480, 750, 1200])), 2)
                msg_obj = random.choice(msg_by_intent["purchase"] + msg_by_intent["unknown_other"])
                msg_text = msg_obj["text"]
                msg_lang = msg_obj["language"]
                user_intent = "pay"
                screen_recording = 0
                device_novelty = 0

            elif fraud_type_roll < 0.80:
                # 3. FAKE KYC PAYMENT
                scam_cat = "fake_kyc"
                recipient_name = random.choice(["Quick Verify Services", "KYC Desk eServices", "Account Security Portal"])
                recipient_account = f"{recipient_name.lower().replace(' ', '')}@demo"
                merchant_ref_status = 3 # unavailable
                amount = round(float(random.choice([49, 99, 149, 199, 299, 499])), 2)
                msg_obj = random.choice(msg_by_intent["kyc_threat"])
                msg_text = msg_obj["text"]
                msg_lang = msg_obj["language"]
                user_intent = "verify"
                screen_recording = 1 if random.random() < 0.30 else 0
                device_novelty = 1 if random.random() < 0.40 else 0

            elif fraud_type_roll < 0.88:
                # 4. REMOTE ACCESS RISK
                scam_cat = "remote_access_scam"
                recipient_name = random.choice(["Neeraj Solutions", "AnyTech Support", "Direct Connect Services"])
                recipient_account = f"{recipient_name.lower().replace(' ', '')}@demo"
                merchant_ref_status = 3 # unavailable
                amount = round(float(random.choice([2450, 4999, 9800, 15000])), 2)
                msg_text = "Please share your AnyDesk/TeamViewer screen so our technician can verify the refund credit."
                msg_lang = "en"
                user_intent = "verify"
                screen_recording = 1 # Remote desktop recording active!
                device_novelty = 1

            else:
                # 5. HELD-OUT UNSEEN SCAM: JOB-ONBOARDING TASK DEPOSIT
                scam_cat = "job_deposit"
                recipient_name = random.choice(["CareerBridge Services", "Apex Task Partners", "Global Hiring Desk", "WorkFlex India"])
                recipient_account = f"{recipient_name.lower().replace(' ', '')}@demo"
                merchant_ref_status = 3 # unavailable
                amount = round(float(random.choice([1500, 2000, 2500, 3500, 5000])), 2)
                msg_obj = random.choice(msg_by_intent["job_deposit"])
                msg_text = msg_obj["text"]
                msg_lang = msg_obj["language"]
                user_intent = "pay"
                screen_recording = 0
                device_novelty = 1 if random.random() < 0.45 else 0

        # Behavioral & history features
        prior_payees = user_payee_history[uid]
        prior_recipient_count = 1 if recipient_account in prior_payees else 0
        is_new_recipient = 1 if prior_recipient_count == 0 else 0
        if not is_fraud or random.random() < 0.1:
            prior_payees.add(recipient_account)
            
        recent_txs = user_tx_history[uid]
        cutoff_1h = current_time - timedelta(hours=1)
        cutoff_24h = current_time - timedelta(hours=24)
        
        velocity_1h = sum(1 for t in recent_txs if t >= cutoff_1h)
        velocity_24h = sum(1 for t in recent_txs if t >= cutoff_24h)
        recent_txs.append(current_time)
        
        hour_deviation = abs(current_time.hour - user["typical_hour"])
        log_amt = float(np.log1p(amount))
        amt_to_median_ratio = round(amount / (user_median + 1e-4), 3)
        interaction_seconds = max(3.0, round(float(np.random.normal(loc=18.0 if not is_fraud else 8.0, scale=4.0)), 1))
        
        tx_record = {
            "transaction_id": f"TX_{i:06d}",
            "timestamp": current_time.isoformat(),
            "user_id": uid,
            "user_name": user["name"],
            "recipient_name": recipient_name,
            "recipient_account": recipient_account,
            "merchant_reference_status": merchant_ref_status, # 0=match, 1=mismatch, 2=alias, 3=unavailable
            "amount": amount,
            "log_amount": log_amt,
            "user_median_amount": user_median,
            "amount_to_user_median_ratio": amt_to_median_ratio,
            "prior_recipient_count": prior_recipient_count,
            "is_new_recipient": is_new_recipient,
            "time_of_day_deviation": hour_deviation,
            "recent_tx_velocity_1h": velocity_1h,
            "recent_tx_velocity_24h": velocity_24h,
            "device_novelty": device_novelty,
            "interaction_time_seconds": interaction_seconds,
            "screen_recording_active": screen_recording,
            "message_text": msg_text,
            "message_language": msg_lang,
            "user_declared_intent": user_intent,
            "payment_direction": "outgoing",
            "scam_category": scam_cat,
            "is_fraud": is_fraud
        }
        tx_list.append(tx_record)
        
    return tx_list

def main():
    parser = argparse.ArgumentParser(description="UPI Guard Dataset Generator & Partitioning")
    parser.add_argument("--n-transactions", type=int, default=40000, help="Total transactions (30,000-50,000)")
    parser.add_argument("--n-users", type=int, default=1000, help="Synthetic users count")
    parser.add_argument("--n-merchants", type=int, default=150, help="Synthetic merchants count")
    parser.add_argument("--n-messages", type=int, default=3000, help="Multilingual messages count")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--output-dir", type=str, default="data", help="Output directory")
    args = parser.parse_args()

    set_seed(args.seed)
    os.makedirs(args.output_dir, exist_ok=True)
    
    print(f"[*] Generating {args.n_users} synthetic users...")
    users = generate_users(args.n_users)
    with open(os.path.join(args.output_dir, "users.json"), "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)

    print(f"[*] Generating {args.n_merchants} synthetic merchants with verified aliases...")
    merchants = generate_merchants(args.n_merchants)
    with open(os.path.join(args.output_dir, "merchants.json"), "w", encoding="utf-8") as f:
        json.dump(merchants, f, indent=2)

    print(f"[*] Generating {args.n_messages} multilingual messages in English, Hindi, Hinglish...")
    messages = generate_messages(args.n_messages)
    pd.DataFrame(messages).to_csv(os.path.join(args.output_dir, "messages.csv"), index=False, encoding="utf-8")

    print(f"[*] Generating {args.n_transactions} chronological transactions with realistic fraud distributions...")
    transactions = generate_transactions(users, merchants, messages, args.n_transactions)
    df_all = pd.DataFrame(transactions)
    
    # Sort strictly chronologically
    df_all = df_all.sort_values("timestamp").reset_index(drop=True)
    df_all.to_csv(os.path.join(args.output_dir, "transactions_full.csv"), index=False)

    print(f"[*] Total transactions: {len(df_all)}")
    print(f"[*] Fraud prevalence: {df_all['is_fraud'].mean()*100:.2f}% ({df_all['is_fraud'].sum()} cases)")
    print("[*] Scenario breakdown:\n", df_all["scam_category"].value_counts())

    # PARTITIONING ACCORDING TO RESEARCH PROTOCOL (Pages 9-10):
    # 1. HELD-OUT SCAM EXPERIMENT: Exclude 'job_deposit' completely from Train & Validation!
    # 2. Chronological split: First 70% Train, Next 15% Validation, Final 15% Test.
    
    is_job_scam = df_all["scam_category"] == "job_deposit"
    df_job_scam = df_all[is_job_scam].copy().reset_index(drop=True)
    df_base = df_all[~is_job_scam].copy().reset_index(drop=True)

    # Save held-out job scam family separately for the Pattern Lab adaptation experiment!
    df_job_scam.to_csv(os.path.join(args.output_dir, "held_out_job_scam.csv"), index=False)

    n_base = len(df_base)
    idx_train = int(n_base * 0.70)
    idx_val = int(n_base * 0.85)

    df_train = df_base.iloc[:idx_train].copy().reset_index(drop=True)
    df_val = df_base.iloc[idx_train:idx_val].copy().reset_index(drop=True)
    df_test = df_base.iloc[idx_val:].copy().reset_index(drop=True)

    df_train.to_csv(os.path.join(args.output_dir, "train_transactions.csv"), index=False)
    df_val.to_csv(os.path.join(args.output_dir, "val_transactions.csv"), index=False)
    df_test.to_csv(os.path.join(args.output_dir, "test_transactions.csv"), index=False)

    # Message intent dataset splitting (holding out job_deposit for candidate model)
    df_msgs = pd.DataFrame(messages)
    msgs_job = df_msgs[df_msgs["intent"] == "job_deposit"].copy().reset_index(drop=True)
    msgs_base = df_msgs[df_msgs["intent"] != "job_deposit"].copy().reset_index(drop=True)
    
    msgs_job.to_csv(os.path.join(args.output_dir, "held_out_job_messages.csv"), index=False)
    msgs_base.to_csv(os.path.join(args.output_dir, "train_messages.csv"), index=False)

    metadata = {
        "generator_version": "1.0.0-cc6-ai02",
        "random_seed": args.seed,
        "total_transactions": len(df_all),
        "train_size": len(df_train),
        "val_size": len(df_val),
        "test_size": len(df_test),
        "held_out_job_scam_size": len(df_job_scam),
        "fraud_prevalence_pct": round(float(df_all['is_fraud'].mean() * 100), 2),
        "generated_at": datetime.now().isoformat()
    }
    with open(os.path.join(args.output_dir, "dataset_metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    print("\n[+] Dataset generation complete! Files saved in 'data/':")
    print(f"    - train_transactions.csv: {len(df_train)} rows")
    print(f"    - val_transactions.csv:   {len(df_val)} rows")
    print(f"    - test_transactions.csv:  {len(df_test)} rows")
    print(f"    - held_out_job_scam.csv:  {len(df_job_scam)} rows (held-out for Pattern Lab adaptation)")
    print(f"    - messages.csv:           {len(df_msgs)} multilingual messages")
    print(f"    - dataset_metadata.json:  provenance & parameters")

if __name__ == "__main__":
    main()
