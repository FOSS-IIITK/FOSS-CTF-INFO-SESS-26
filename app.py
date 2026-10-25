import json
import os
import re
import tempfile
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, url_for


BASE_DIR = Path(__file__).resolve().parent
RESULTS_FILE = Path(os.environ.get("CTF_RESULTS_FILE", BASE_DIR / "runtime" / "results.json"))
RESULTS_LOCK = threading.Lock()
REDIS_INDEX_KEY = "foss-ctf:participants"
REDIS_PARTICIPANT_PREFIX = "foss-ctf:participant:"
REDIS_SOLVE_SCRIPT = """
local participant = KEYS[1]
local participants = KEYS[2]
local solve_field = ARGV[3]
redis.call('HSET', participant, 'name', ARGV[1], 'phone', ARGV[2])
if redis.call('HEXISTS', participant, solve_field) == 1 then
    return 0
end
redis.call('HSET', participant, solve_field, ARGV[4], 'last_solve', ARGV[5])
redis.call('SADD', participants, ARGV[2])
return 1
"""

CHALLENGES = {
    1: {
        "title": "The Midnight Aviary",
        "category": "Cryptography",
        "difficulty": "Easy",
        "points": 100,
        "story": (
            "The Lantern Academy has gone quiet beneath its first winter fog. "
            "Just before dawn, a silver-feathered courier slips through the "
            "high windows and drops a singed note on your desk. The message "
            "was left by a student who vanished from the academy rolls years "
            "ago—and someone has hidden its meaning in a simple letter-shift."
        ),
        "description": (
            "The note was encoded with ROT13. Decode it to reveal the flag."
        ),
        "artifact": "SBFF{bjy_cbfg_qrpbqrq}",
        "hint": "ROT13 shifts every letter halfway around the alphabet.",
        "flag": "FOSS{owl_post_decoded}",
    },
    2: {
        "title": "Wand-Key Dispatch",
        "category": "Classical cryptography",
        "difficulty": "Medium",
        "points": 200,
        "story": (
            "Rain taps against the glass dome of the academy observatory. "
            "Inside, an apprentice astronomer has left a coded dispatch beside "
            "a brass instrument and a half-finished star chart. Their warning "
            "is still legible in the margin: “Every spell begins at its focus.” "
            "The night watch is approaching; work out the key before the "
            "message is swept away with the charts."
        ),
        "description": (
            "A Vigenere cipher guards the dispatch. Use the four-letter focus "
            "named by the margin clue as the key."
        ),
        "artifact": "BOFV{nuah_gel_ikuag}",
        "hint": "The four-letter focus is a wand. Vigenere shifts each letter by the corresponding repeated key letter.",
        "flag": "FOSS{rune_key_found}",
    },
    3: {
        "title": "The Three Wards",
        "category": "Multi-step decoding",
        "difficulty": "Tough",
        "points": 350,
        "story": (
            "Beneath the academy's oldest tower is a sealed archive that "
            "opens only once each century. Tonight, its stone door has "
            "unlatched—but the keeper's final warning says the inscription "
            "was veiled by three wards. Beyond it lies the lost register of "
            "names, and the corridor behind you is already beginning to "
            "close. Unravel each layer in order."
        ),
        "description": (
            "Undo the three layers in order: decode Base64, reverse the "
            "resulting text, then decode the hex bytes as ASCII."
        ),
        "artifact": "ZDczNzU2Mzc5NjI3ZjU4Nzk2ZTY1NmY2ODYwN2I3MzUzNWY0NjQ=",
        "hint": "Keep each layer's output intact: Base64 text → reversed hex → ASCII flag.",
        "flag": "FOSS{phoenix_rises}",
    },
}

app = Flask(__name__)
if os.environ.get("VERCEL") and not os.environ.get("FLASK_SECRET_KEY"):
    raise RuntimeError("Set FLASK_SECRET_KEY in the Vercel project environment variables.")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "local-ctf-development-key")


def redis_credentials():
    url = os.environ.get("UPSTASH_REDIS_REST_URL")
    token = os.environ.get("UPSTASH_REDIS_REST_TOKEN")
    if bool(url) != bool(token):
        raise RuntimeError(
            "Set both UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN."
        )
    if os.environ.get("VERCEL") and not url:
        raise RuntimeError(
            "Configure Upstash Redis and set its REST URL and token in Vercel."
        )
    return url, token


if os.environ.get("VERCEL"):
    redis_credentials()


def redis_request(path, payload):
    url, token = redis_credentials()
    endpoint = url.rstrip("/") + ("/" + path.lstrip("/") if path else "")
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        app.logger.error("Upstash Redis request failed: %s", exc)
        raise RuntimeError("Could not access the configured score database.") from exc
    if path == "pipeline":
        if not isinstance(result, list):
            raise RuntimeError("Upstash Redis returned an invalid pipeline response.")
        pipeline_results = []
        for item in result:
            if "error" in item:
                app.logger.error("Upstash Redis returned an error: %s", item["error"])
                raise RuntimeError("The configured score database rejected a request.")
            pipeline_results.append(item.get("result"))
        return pipeline_results
    if not isinstance(result, dict):
        raise RuntimeError("Upstash Redis returned an invalid response.")
    if "error" in result:
        app.logger.error("Upstash Redis returned an error: %s", result["error"])
        raise RuntimeError("The configured score database rejected a request.")
    return result.get("result")


def redis_load_results():
    phones = redis_request("", ["SMEMBERS", REDIS_INDEX_KEY]) or []
    if not phones:
        return {}
    hashes = redis_request(
        "pipeline",
        [["HGETALL", f"{REDIS_PARTICIPANT_PREFIX}{phone}"] for phone in phones],
    )
    results = {}
    for phone, fields in zip(phones, hashes):
        if not fields:
            continue
        values = dict(zip(fields[::2], fields[1::2]))
        solves = {}
        for field, raw_solve in values.items():
            if field.startswith("solve:"):
                solves[field.removeprefix("solve:")] = json.loads(raw_solve)
        results[phone] = {
            "name": values.get("name", "Anonymous"),
            "phone": phone,
            "solves": solves,
            "last_solve": values.get("last_solve"),
        }
    return results


def redis_record_solve(phone, name, challenge_id, selected, solved_at):
    solve = json.dumps(
        {
            "title": selected["title"],
            "points": selected["points"],
            "solved_at": solved_at,
        }
    )
    result = redis_request(
        "",
        [
            "EVAL",
            REDIS_SOLVE_SCRIPT,
            "2",
            f"{REDIS_PARTICIPANT_PREFIX}{phone}",
            REDIS_INDEX_KEY,
            name,
            phone,
            f"solve:{challenge_id}",
            solve,
            solved_at,
        ],
    )
    return result == 1


def load_results():
    """Load the runtime result file, treating a first run as an empty event."""
    url, _ = redis_credentials()
    if url:
        return redis_load_results()
    try:
        with RESULTS_FILE.open("r", encoding="utf-8") as results_file:
            data = json.load(results_file)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        app.logger.error("Could not parse results file %s: %s", RESULTS_FILE, exc)
        raise

    if not isinstance(data, dict):
        raise ValueError(f"Results file must contain a JSON object: {RESULTS_FILE}")
    return data


def save_results(data):
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=RESULTS_FILE.parent,
            delete=False,
        ) as temp_file:
            json.dump(data, temp_file, indent=2)
            temp_file.write("\n")
            temp_path = Path(temp_file.name)
        os.replace(temp_path, RESULTS_FILE)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def normalize_phone(phone):
    return re.sub(r"\D", "", phone)


@app.get("/")
def index():
    return render_template(
        "index.html",
        challenges=CHALLENGES,
        challenge_count=len(CHALLENGES),
    )


@app.get("/challenge/<int:challenge_id>")
def challenge(challenge_id):
    selected = CHALLENGES.get(challenge_id)
    if selected is None:
        return render_template("404.html"), 404
    return render_template(
        "challenge.html",
        challenge=selected,
        challenge_id=challenge_id,
    )


@app.post("/challenge/<int:challenge_id>")
def submit_answer(challenge_id):
    selected = CHALLENGES.get(challenge_id)
    if selected is None:
        return render_template("404.html"), 404

    name = " ".join(request.form.get("name", "").split())
    phone = request.form.get("phone", "").strip()
    normalized_phone = normalize_phone(phone)
    answer = request.form.get("answer", "").strip()

    if not name or len(name) > 80:
        flash("Enter your name (up to 80 characters).", "error")
        return redirect(url_for("challenge", challenge_id=challenge_id))
    if len(normalized_phone) < 7 or len(normalized_phone) > 15:
        flash("Enter a valid phone number containing 7 to 15 digits.", "error")
        return redirect(url_for("challenge", challenge_id=challenge_id))
    if not answer:
        flash("Enter a flag before submitting.", "error")
        return redirect(url_for("challenge", challenge_id=challenge_id))
    if answer.casefold() != selected["flag"].casefold():
        flash("Not quite — check the challenge and try again.", "error")
        return redirect(url_for("challenge", challenge_id=challenge_id))

    with RESULTS_LOCK:
        redis_url, _ = redis_credentials()
        if redis_url:
            solved_at = datetime.now(timezone.utc).isoformat()
            if redis_record_solve(
                normalized_phone,
                name,
                challenge_id,
                selected,
                solved_at,
            ):
                flash(
                    f"Correct! {selected['points']} points added to your score.",
                    "success",
                )
            else:
                flash(
                    "You already solved this challenge. Your score is unchanged.",
                    "info",
                )
            return redirect(url_for("leaderboard"))

        results = load_results()
        participant = results.get(normalized_phone)
        if participant is None:
            participant = {
                "name": name,
                "phone": normalized_phone,
                "solves": {},
                "last_solve": None,
            }
            results[normalized_phone] = participant
        else:
            participant["name"] = name

        challenge_key = str(challenge_id)
        if challenge_key in participant["solves"]:
            flash("You already solved this challenge. Your score is unchanged.", "info")
        else:
            solved_at = datetime.now(timezone.utc).isoformat()
            participant["solves"][challenge_key] = {
                "title": selected["title"],
                "points": selected["points"],
                "solved_at": solved_at,
            }
            participant["last_solve"] = solved_at
            save_results(results)
            flash(f"Correct! {selected['points']} points added to your score.", "success")

    return redirect(url_for("leaderboard"))


@app.get("/leaderboard")
def leaderboard():
    with RESULTS_LOCK:
        results = load_results()

    standings = []
    for participant in results.values():
        solves = participant.get("solves", {})
        standings.append(
            {
                "name": participant.get("name", "Anonymous"),
                "score": sum(
                    int(solve.get("points", 0))
                    for solve in solves.values()
                    if isinstance(solve, dict)
                ),
                "solved_count": len(solves),
                "last_solve": participant.get("last_solve"),
            }
        )
    standings.sort(
        key=lambda row: (-row["score"], row["last_solve"] or "")
    )
    return render_template(
        "leaderboard.html",
        standings=standings,
        challenge_count=len(CHALLENGES),
    )


@app.errorhandler(500)
def internal_error(error):
    app.logger.error("Request failed: %s", error)
    return render_template("500.html"), 500


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
