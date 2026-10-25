# FOSS Club CTF — IIIT Kalyani

A small Flask CTF event site with three wizard-school-themed challenges, answer submission, and a persistent leaderboard.

## Tech stack

- Frontend: server-rendered HTML templates and responsive CSS
- Backend: Python and Flask
- Local runtime storage: JSON file at `runtime/results.json`
- Vercel runtime storage: Upstash Redis (REST)

## Run locally

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>. The result file and its parent folder are created automatically when the first correct flag is submitted.

## Routes

- `/` — event home and challenge list
- `/challenge/1` — Easy: The Owl Post Cipher
- `/challenge/2` — Medium: Wand-Key Dispatch
- `/challenge/3` — Tough: The Three Wards
- `/leaderboard` — scores loaded from the runtime result file

Participants should use the same name and phone number on every submission. Phone numbers are normalized to digits and used as the participant key; they are stored in the result file but never displayed on the leaderboard.

## Deploy to Vercel

1. Push this project to a Git provider and import it into Vercel. Vercel uses `vercel.json` and the Flask entry point at `api/index.py`.
2. Create an Upstash Redis database and add these environment variables in the Vercel project settings for each deployment environment:
   - `UPSTASH_REDIS_REST_URL`
   - `UPSTASH_REDIS_REST_TOKEN`
   - `FLASK_SECRET_KEY` — a unique, randomly generated secret
3. Deploy. The leaderboard uses Redis so scores persist across serverless invocations. Vercel deployments intentionally fail clearly if the required secrets or persistent Redis configuration are missing.

The uploaded logo at `static/foss_logo.png` is used in the site header. Vercel includes both templates and static assets with the Python function. Local development continues to use the JSON result file unless Upstash credentials are configured.

Phone numbers are stored to associate solves across challenges. Treat the database credentials as secrets and restrict access to the Upstash database.
