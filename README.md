# UPI Guard

A responsive, interactive prototype of the consumer payment-safety app and connected bank analyst workspace. All records, device signals, model interpretations, and evaluation results are synthetic or illustrative. No payments or live bank connections are made.

## Run

With Node.js available, run `npm start` and open http://127.0.0.1:4173. No installation or build is required. `npm run check` validates JavaScript syntax. Deploy the `dist` directory to static hosting.

## Demo flows

- Home → Scan QR → Sharma Medical → Check payment → Continue to demo preview → Simulate payment completion.
- Try a demo scenario → Refund deception → Check payment → Intent comparison → Warning → Cancel payment → Connected analyst record.
- Scan QR → Campus Canteen → Check payment → Review details → Compare merchant identity.
- Choose recipient-change scenario → Check payment → Simulate recipient change → Previous assessment invalidated → Check new details.
- Choose onboarding-deposit scenario → Check payment → Review → Analyst dashboard → Pattern Lab → Review examples → Analyst decision → Prepare candidate → Illustrative evaluation comparison.

QR scanning is simulated with four selectable synthetic records, including a proprietor name variation and an unavailable reference. Camera access and image decoding are not implemented. Demo links use only `https://pay.demo/{scenario-id}` and are parsed locally, never navigated. Read-aloud uses browser speech synthesis when a suitable voice is available.

Both experiences share browser localStorage, with a cross-tab storage listener. Review decisions update related views. Payment assessments bind amount, account, recipient display name, currency, session and supplied context; edits invalidate previous checks. Settings provides English/Hindi key flows, read-aloud, larger text, contrast and reset controls. Browser data remains local to each origin; local and hosted copies have separate demo storage.

Analyst charts, timing values, feature contributions and evaluation metrics are explicitly illustrative. The operational cards and queues use actual synthetic records from this browser. A candidate can be prepared for comparison, never deployed.
