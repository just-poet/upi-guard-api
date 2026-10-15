# Connected UPI Guard deployment

The supplied FastAPI/scikit-learn backend is connected to the UI. Scoring, confirmation, activity, analyst labels, operational metrics, evaluation artifacts and workspace reset use HTTP APIs. Offline browser decisions are not used as fallback.

## Local verification

Use Python 3.14 (matching the supplied model environment), install `requirements.txt` and run `python server.py`. Open `http://127.0.0.1:4173`. Test with `python -m unittest test_backend -v` (requires `httpx` in the development environment).

## Hosted architecture

Private existing Sites URL → authenticated Worker gateway → HTTPS FastAPI service → trained artifacts + ephemeral SQLite demo store.

The Dockerfile preserves the supplied model artifacts and pins their library versions. The owner selected **free hosting only**. `render.yaml` uses the free plan in Singapore with no paid disk. Demo history is ephemeral: it can reset on service restart, idle shutdown or redeployment. The UI discloses this limitation. No paid resources are created.

1. Deploy this repository directory as a Docker web service on Render. Set the intended root directory if it is in a monorepo.
2. Use `UPI_GUARD_DB_PATH=/tmp/upi-guard-events.db` and `UPI_GUARD_EPHEMERAL=1` for the selected free plan. Records do not survive restarts or redeploys. The development `events.db` is not uploaded. A persistent disk would require a separately approved paid plan.
3. Configure a strong `UPI_GUARD_API_KEY` on the backend and `BACKEND_API_KEY` with the same value in Sites runtime settings. Keep both out of client code, Git, logs, and the hosting manifest. Set `UPI_GUARD_SIGNING_KEY` on the backend to a generated secret that survives restarts.
4. Set Sites `BACKEND_URL` to the backend HTTPS origin. The backend health check is `/health`; the public response contains no credentials or transaction records.
5. Remove the `static` field from `.openai/hosting.json` for the Worker deployment, run `node scripts/build-worker.cjs`, package the exact pushed commit, and update the existing private Site. Preserve its project ID and audience. The Worker reads authenticated Sites identity, derives a workspace ID, forwards only the supported API paths and adds the backend key server-side.
6. Verify a payment assessment, cancellation, analyst decision, recipient/account mutation rejection, and the free-storage disclosure before considering hosting complete.

## Data and model provenance

Only synthetic payments ending in `@demo` are accepted. New deployment records are partitioned per authenticated Sites user; local development uses a browser workspace ID. There is no real payment integration. No API credentials or assessment tokens are stored in browser preferences.

The evaluation page reads `evaluation_results.json` as the supplied offline evaluation artifact; it does not claim deployment changes were re-evaluated. The supplied candidate is selected for comparison, not retrained or automatically deployed. The supplied artifact reports no original-to-candidate recall gain for the held-out family (100% versus 100%); the UI displays those values without inventing improvement. Feature signals are backend heuristic weights, not SHAP explanations.

The legacy development database uses a different schema and is left intact. Connected requests use `api_assessments`, `api_audit`, and `api_preferences` tables.
