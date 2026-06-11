"""
HashCrack Pro Web — Flask Backend
Red Team Internship Project
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response
import hashlib, threading, time, os, csv, io, json, datetime, itertools, string

app = Flask(__name__)
app.secret_key = "hashcrack_secret_2024"

# ── In-memory user store (no DB needed for internship demo) ──
USERS = {
    "admin": {"password": "admin123", "role": "Red Team"},
    "redteam": {"password": "crack123", "role": "Analyst"},
}

# ── Crack history stored in memory ──
crack_history = []

# ── Active crack jobs ──
active_jobs = {}   # job_id → {"status","result","log","stats"}

# ══════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════

HASH_LENGTHS = {32:"md5", 40:"sha1", 56:"sha224", 64:"sha256", 96:"sha384", 128:"sha512"}

def detect_hash(h):
    return HASH_LENGTHS.get(len(h.strip()), "unknown")

def compute_hash(word, algo):
    try:
        h = hashlib.new(algo)
        h.update(word.encode("utf-8", errors="ignore"))
        return h.hexdigest()
    except:
        return None

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ══════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════

@app.route("/", methods=["GET"])
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        user = USERS.get(username)
        if user and user["password"] == password:
            session["user"] = username
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ══════════════════════════════════════
#  MAIN PAGES
# ══════════════════════════════════════

@app.route("/dashboard")
@login_required
def dashboard():
    stats = {
        "total_cracked": len(crack_history),
        "wordlist_attacks": sum(1 for r in crack_history if r["method"]=="Wordlist"),
        "brute_attacks":    sum(1 for r in crack_history if r["method"]=="Brute Force"),
        "multi_attacks":    sum(1 for r in crack_history if r["method"]=="Multi-Hash"),
        "recent": crack_history[-5:][::-1],
    }
    return render_template("dashboard.html", stats=stats,
                           user=session["user"], role=session["role"])

@app.route("/crack")
@login_required
def crack():
    return render_template("crack.html", user=session["user"], role=session["role"])

@app.route("/history")
@login_required
def history():
    return render_template("history.html",
                           history=crack_history[::-1],
                           user=session["user"], role=session["role"])

@app.route("/generator")
@login_required
def generator():
    return render_template("generator.html", user=session["user"], role=session["role"])

# ══════════════════════════════════════
#  API — CRACK
# ══════════════════════════════════════

@app.route("/api/detect", methods=["POST"])
@login_required
def api_detect():
    data = request.json
    h = data.get("hash","").strip()
    t = detect_hash(h)
    return jsonify({"type": t, "length": len(h)})

@app.route("/api/crack/wordlist", methods=["POST"])
@login_required
def api_crack_wordlist():
    data    = request.json
    target  = data.get("hash","").strip()
    algo    = data.get("algo","auto")
    wl_text = data.get("wordlist","")   # wordlist text pasted or uploaded

    if algo == "auto":
        algo = detect_hash(target)
        if algo == "unknown":
            return jsonify({"error": "Cannot detect hash type. Select manually."}), 400

    job_id = f"wl_{int(time.time()*1000)}"
    active_jobs[job_id] = {"status":"running","result":None,"log":[],"stats":{"tries":0,"speed":0,"elapsed":0}}

    words = [l.strip() for l in wl_text.splitlines() if l.strip()]

    def worker():
        start = time.time()
        count = 0
        total = len(words)
        for word in words:
            if active_jobs[job_id]["status"] == "stopped":
                break
            count += 1
            computed = compute_hash(word, algo)
            if computed == target:
                elapsed = round(time.time()-start, 2)
                result = {"hash":target,"password":word,"algo":algo.upper(),
                          "method":"Wordlist","time":f"{elapsed}s","tries":count,
                          "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                active_jobs[job_id]["result"] = result
                active_jobs[job_id]["status"] = "found"
                active_jobs[job_id]["log"].append(f"✅ CRACKED! Password: {word} ({elapsed}s, {count} tries)")
                crack_history.append(result)
                return
            if count % 1000 == 0:
                elapsed = time.time()-start
                speed = int(count/elapsed) if elapsed > 0 else 0
                active_jobs[job_id]["stats"] = {"tries":count,"speed":speed,"elapsed":round(elapsed,1),"total":total}
                active_jobs[job_id]["log"].append(f"[{count:,}/{total:,}] {speed:,} w/s — trying: {word}")
        if active_jobs[job_id]["status"] == "running":
            active_jobs[job_id]["status"] = "notfound"
            active_jobs[job_id]["log"].append(f"❌ Not found after {count:,} words.")

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/api/crack/brute", methods=["POST"])
@login_required
def api_crack_brute():
    data   = request.json
    target = data.get("hash","").strip()
    algo   = data.get("algo","auto")
    min_l  = int(data.get("min_len", 1))
    max_l  = int(data.get("max_len", 4))
    cs_key = data.get("charset","lower_digits")

    charsets = {
        "lower":        string.ascii_lowercase,
        "upper":        string.ascii_uppercase,
        "digits":       string.digits,
        "lower_digits": string.ascii_lowercase + string.digits,
        "all_alpha":    string.ascii_letters + string.digits,
        "printable":    string.printable.strip(),
    }
    charset = charsets.get(cs_key, string.ascii_lowercase + string.digits)

    if algo == "auto":
        algo = detect_hash(target)
        if algo == "unknown":
            return jsonify({"error": "Cannot detect hash type."}), 400

    job_id = f"bf_{int(time.time()*1000)}"
    active_jobs[job_id] = {"status":"running","result":None,"log":[],"stats":{"tries":0,"speed":0,"elapsed":0}}

    def worker():
        start = time.time()
        count = 0
        for length in range(min_l, max_l+1):
            active_jobs[job_id]["log"].append(f"[*] Trying length {length}...")
            for combo in itertools.product(charset, repeat=length):
                if active_jobs[job_id]["status"] == "stopped": return
                word = "".join(combo)
                count += 1
                computed = compute_hash(word, algo)
                if computed == target:
                    elapsed = round(time.time()-start, 2)
                    result = {"hash":target,"password":word,"algo":algo.upper(),
                              "method":"Brute Force","time":f"{elapsed}s","tries":count,
                              "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                    active_jobs[job_id]["result"] = result
                    active_jobs[job_id]["status"] = "found"
                    active_jobs[job_id]["log"].append(f"✅ CRACKED! Password: {word}")
                    crack_history.append(result)
                    return
                if count % 10000 == 0:
                    elapsed = time.time()-start
                    speed = int(count/elapsed) if elapsed > 0 else 0
                    active_jobs[job_id]["stats"] = {"tries":count,"speed":speed,"elapsed":round(elapsed,1)}
                    active_jobs[job_id]["log"].append(f"[{count:,}] {speed:,} w/s — trying: {word}")
        if active_jobs[job_id]["status"] == "running":
            active_jobs[job_id]["status"] = "notfound"
            active_jobs[job_id]["log"].append(f"❌ Not found after {count:,} combinations.")

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/api/crack/multi", methods=["POST"])
@login_required
def api_crack_multi():
    data    = request.json
    hashes  = [h.strip() for h in data.get("hashes",[]) if h.strip() and not h.startswith("#")]
    wl_text = data.get("wordlist","")

    if not hashes:
        return jsonify({"error": "No valid hashes provided."}), 400

    job_id = f"mh_{int(time.time()*1000)}"
    active_jobs[job_id] = {"status":"running","result":[],"log":[],"stats":{"tries":0,"speed":0,"elapsed":0}}

    words = [l.strip() for l in wl_text.splitlines() if l.strip()]

    def worker():
        start   = time.time()
        count   = 0
        groups  = {}
        for h in hashes:
            algo = detect_hash(h)
            if algo != "unknown":
                groups.setdefault(algo, set()).add(h)
                active_jobs[job_id]["log"].append(f"[*] {h[:16]}... → {algo.upper()}")
            else:
                active_jobs[job_id]["log"].append(f"[!] Skipping unknown hash: {h[:16]}...")

        remaining = {a: set(hs) for a,hs in groups.items()}
        all_rem   = set(h for hs in remaining.values() for h in hs)

        for word in words:
            if active_jobs[job_id]["status"] == "stopped" or not all_rem: break
            count += 1
            for algo, rem in list(remaining.items()):
                if not rem: continue
                computed = compute_hash(word, algo)
                if computed in rem:
                    rem.discard(computed)
                    all_rem.discard(computed)
                    elapsed = round(time.time()-start, 2)
                    result = {"hash":computed,"password":word,"algo":algo.upper(),
                              "method":"Multi-Hash","time":f"{elapsed}s","tries":count,
                              "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                    active_jobs[job_id]["result"].append(result)
                    active_jobs[job_id]["log"].append(f"✅ CRACKED: {word}  ← {computed[:16]}...")
                    crack_history.append(result)
            if count % 1000 == 0:
                elapsed = time.time()-start
                speed = int(count/elapsed) if elapsed > 0 else 0
                active_jobs[job_id]["stats"] = {"tries":count,"speed":speed,"elapsed":round(elapsed,1)}

        status = "found" if active_jobs[job_id]["result"] else "notfound"
        if all_rem:
            status = "partial" if active_jobs[job_id]["result"] else "notfound"
            active_jobs[job_id]["log"].append(f"❌ {len(all_rem)} hash(es) not found.")
        active_jobs[job_id]["status"] = status

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/api/job/<job_id>")
@login_required
def api_job_status(job_id):
    job = active_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@app.route("/api/job/<job_id>/stop", methods=["POST"])
@login_required
def api_stop_job(job_id):
    if job_id in active_jobs:
        active_jobs[job_id]["status"] = "stopped"
    return jsonify({"ok": True})


# ══════════════════════════════════════
#  API — GENERATOR
# ══════════════════════════════════════

@app.route("/api/generate", methods=["POST"])
@login_required
def api_generate():
    data  = request.json
    text  = data.get("text","").strip()
    algos = data.get("algos", ["md5","sha1","sha256"])
    if not text:
        return jsonify({"error": "Enter text to hash."}), 400
    results = {}
    for algo in algos:
        results[algo] = compute_hash(text, algo)
    return jsonify({"input": text, "hashes": results})


# ══════════════════════════════════════
#  API — EXPORT
# ══════════════════════════════════════

@app.route("/api/export/<fmt>")
@login_required
def api_export(fmt):
    if not crack_history:
        return jsonify({"error": "No results to export."}), 400

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "csv":
        si = io.StringIO()
        w  = csv.DictWriter(si, fieldnames=["hash","password","algo","method","time","tries","timestamp"])
        w.writeheader()
        w.writerows(crack_history)
        return Response(si.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment;filename=hashcrack_{ts}.csv"})

    if fmt == "txt":
        lines = ["="*60, "   HashCrack Pro v2.0 — Crack Report",
                 f"   Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                 "="*60, ""]
        for i,r in enumerate(crack_history,1):
            lines += [f"[{i}]"] + [f"  {k:<12}: {v}" for k,v in r.items()] + [""]
        lines += ["="*60, "  For educational and ethical use only.", "="*60]
        return Response("\n".join(lines), mimetype="text/plain",
                        headers={"Content-Disposition": f"attachment;filename=hashcrack_{ts}.txt"})

    if fmt == "json":
        return Response(json.dumps(crack_history, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": f"attachment;filename=hashcrack_{ts}.json"})

    return jsonify({"error": "Unknown format"}), 400


@app.route("/api/history/clear", methods=["POST"])
@login_required
def api_clear_history():
    crack_history.clear()
    return jsonify({"ok": True})


# ══════════════════════════════════════
#  RUN
# ══════════════════════════════════════

if __name__ == "__main__":
    print("\n" + "="*55)
    print("   HashCrack Pro v2.0 — Web Application")
    print("   Red Team Internship Project")
    print("="*55)
    print("   URL   : http://127.0.0.1:5000")
    print("   Login : admin / admin123")
    print("          : redteam / crack123")
    print("="*55 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
