"""Secure AI-IoT Smart Parking Management System (fully software prototype)
Paper 3: OpenCV slot detection (grayscale -> adaptive threshold -> pixel count per slot)
Paper 1: IoT sensors (temp/humidity/gas) over publish-subscribe messaging (MQTT-style broker, simulated)
Security: Indigo lessons -> hashing, OTP-MFA, RBAC, lockout, CSRF, audit log, device auth, anomaly detection
"""
import cv2, numpy as np, sqlite3, threading, time, random, math, os, secrets
from contextlib import closing
from collections import defaultdict, deque
from functools import wraps
from datetime import datetime
from flask import (Flask, render_template, request, redirect, session,
                   Response, jsonify, abort, flash)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))
DB, RATE = "parking.db", 20            # Rs 20 per hour
now_s = lambda: datetime.now().strftime("%H:%M:%S")

# ---------------- Database (cloud layer) ----------------
def q(sql, a=()):
    with closing(sqlite3.connect(DB, timeout=10)) as c:
        c.row_factory = sqlite3.Row
        return c.execute(sql, a).fetchall()          # parameterized -> no SQL injection
def ex(sql, a=()):
    with closing(sqlite3.connect(DB, timeout=10)) as c:
        c.execute(sql, a); c.commit()

def init_db():
    for t in ["users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw TEXT, role TEXT)",
              "bookings(id INTEGER PRIMARY KEY, user TEXT, slot INT, start REAL, end REAL, fee INT)",
              "sensor_data(id INTEGER PRIMARY KEY, zone TEXT, temp REAL, hum REAL, gas INT, ts TEXT)",
              "alerts(id INTEGER PRIMARY KEY, kind TEXT, msg TEXT, ts TEXT)",
              "audit_log(id INTEGER PRIMARY KEY, user TEXT, action TEXT, ip TEXT, ts TEXT)"]:
        ex("CREATE TABLE IF NOT EXISTS " + t)
    if not q("SELECT 1 FROM users"):
        ex("INSERT INTO users(username,pw,role) VALUES(?,?,?)", ("admin", generate_password_hash("Admin@123"), "admin"))
        ex("INSERT INTO users(username,pw,role) VALUES(?,?,?)", ("user", generate_password_hash("User@123"), "user"))

_last_alert = {}
def alert(kind, msg):
    if time.time() - _last_alert.get(msg, 0) < 10: return      # de-duplicate
    _last_alert[msg] = time.time()
    ex("INSERT INTO alerts(kind,msg,ts) VALUES(?,?,?)", (kind, msg, now_s()))
def audit(user, action):
    ex("INSERT INTO audit_log(user,action,ip,ts) VALUES(?,?,?,?)",
       (user, action, request.remote_addr if request else "system", now_s()))

# ---------------- Simulated IoT network: authenticated pub/sub broker ----------------
class Broker:
    DEVICES = {"sensor1": "secret123", "sensor2": "secret456"}     # device credentials
    def __init__(self):
        self.hist, self.blocked = defaultdict(lambda: deque(maxlen=60)), {}
    def publish(self, dev, pwd, zone, d):
        if not secrets.compare_digest(self.DEVICES.get(dev, "x"), pwd or ""):
            alert("SECURITY", f"Unauthorized device '{dev}' rejected by broker"); return False
        if self.blocked.get(dev, 0) > time.time(): return False
        t = time.time(); self.hist[dev].append(t)
        if sum(1 for x in self.hist[dev] if t - x < 5) > 10:           # >10 msgs / 5 s
            self.blocked[dev] = t + 30
            alert("SECURITY", f"Flood attack from '{dev}' - device blocked 30s"); return False
        if not (-10 < d["temp"] < 80 and 0 <= d["hum"] <= 100 and 0 <= d["gas"] <= 1000):
            alert("SECURITY", f"Out-of-range data from '{dev}' (possible spoofing)"); return False
        ex("INSERT INTO sensor_data(zone,temp,hum,gas,ts) VALUES(?,?,?,?,?)",
           (zone, d["temp"], d["hum"], d["gas"], now_s()))
        STATE["sensors"][zone] = d
        if d["gas"] > 300: alert("SAFETY", f"Hazardous gas {d['gas']} ppm in {zone}")
        if d["temp"] > 45: alert("SAFETY", f"High temperature {d['temp']} C in {zone}")
        return True
BROKER = Broker()

def sensor_loop(dev, pwd, zone):
    while True:
        gas = random.randint(80, 200) if random.random() > 0.04 else random.randint(320, 450)
        BROKER.publish(dev, pwd, zone, dict(temp=round(random.uniform(26, 40), 1),
                       hum=round(random.uniform(40, 70), 1), gas=gas))
        time.sleep(2)

def attack_sim():
    for _ in range(4): BROKER.publish("rogue", "guess", "Zone-A", dict(temp=30, hum=50, gas=100))
    BROKER.publish("sensor1", "secret123", "Zone-A", dict(temp=999, hum=50, gas=100))   # spoofed value
    for _ in range(25): BROKER.publish("sensor1", "secret123", "Zone-A", dict(temp=30, hum=50, gas=100))  # flood

# ---------------- AI: camera + OpenCV detection (Paper 3) ----------------
SLOTS = [dict(id=r*6+c+1, x=20+c*100, y=y, w=100, h=130) for r, y in enumerate((30, 210)) for c in range(6)]
COLORS = [(40, 60, 200), (200, 200, 200), (60, 160, 60), (190, 120, 40), (30, 190, 220), (150, 60, 150)]
STATE = dict(jpg=b"", sensors={}, slots={}, correct=0, total=0)

def render(occ):                                   # synthetic overhead camera frame
    f = np.full((370, 640, 3), 70, np.uint8)
    cv2.putText(f, "DRIVE LANE", (260, 195), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (120, 120, 120), 1)
    for s in SLOTS:
        x, y, w, h = s["x"], s["y"], s["w"], s["h"]
        cv2.rectangle(f, (x, y), (x+w, y+h), (230, 230, 230), 2)
        if s["id"] in occ:
            cv2.rectangle(f, (x+14, y+12), (x+w-14, y+h-12), COLORS[s["id"] % 6], -1)
            cv2.rectangle(f, (x+22, y+34), (x+w-22, y+56), (40, 40, 40), -1)
    noise = np.random.normal(0, 3, f.shape)
    return np.clip(f + noise, 0, 255).astype(np.uint8)

def detect(frame):
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)                       # 1. grayscale
    blur = cv2.GaussianBlur(gray, (5, 5), 1)                              # 2. denoise
    th = cv2.adaptiveThreshold(blur, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                               cv2.THRESH_BINARY_INV, 25, 16)             # 3. threshold
    res = {}
    for s in SLOTS:                                                       # 4. pixel count per slot
        roi = th[s["y"]+6:s["y"]+s["h"]-6, s["x"]+6:s["x"]+s["w"]-6]
        res[s["id"]] = cv2.countNonZero(roi) > 0.03 * roi.size
    return res

def camera_loop():
    occ = set(random.sample(range(1, 13), 5))
    while True:
        if random.random() < 0.25: occ ^= {random.randint(1, 12)}        # a car arrives / leaves
        frame = render(occ); det = detect(frame)
        reserved = {r["slot"] for r in q("SELECT slot FROM bookings WHERE end>?", (time.time(),))}
        for s in SLOTS:
            i = s["id"]; STATE["total"] += 1; STATE["correct"] += det[i] == (i in occ)
            st = "occupied" if det[i] else ("reserved" if i in reserved else "free")
            STATE["slots"][i] = st
            col = {"occupied": (0, 0, 255), "reserved": (0, 215, 255), "free": (0, 255, 0)}[st]
            cv2.rectangle(frame, (s["x"], s["y"]), (s["x"]+s["w"], s["y"]+s["h"]), col, 3)
            cv2.putText(frame, f"P{i}", (s["x"]+6, s["y"]+22), cv2.FONT_HERSHEY_SIMPLEX, 0.6, col, 2)
        cv2.putText(frame, "CAM-01 " + now_s(), (10, 360), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
        STATE["jpg"] = cv2.imencode(".jpg", frame)[1].tobytes()
        time.sleep(0.5)

# ---------------- Security: CSRF, auth, MFA, RBAC ----------------
@app.before_request
def csrf():
    if "csrf" not in session: session["csrf"] = secrets.token_hex(16)
    if request.method == "POST":
        t = request.form.get("csrf") or request.headers.get("X-CSRF") or ""
        if not secrets.compare_digest(t, session["csrf"]): abort(400)
@app.context_processor
def inject(): return dict(csrf=session.get("csrf", ""), me=session.get("user"), role=session.get("role"))
@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"; r.headers["X-Frame-Options"] = "DENY"; return r

def login_required(f):
    @wraps(f)
    def w(*a, **k): return f(*a, **k) if session.get("user") else redirect("/login")
    return w
def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        if session.get("role") != "admin": audit(session.get("user"), "DENIED admin page"); abort(403)
        return f(*a, **k)
    return w

FAILS = {}
@app.route("/", methods=["GET"])
def home(): return redirect("/dashboard")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u, p = request.form.get("username", "").strip()[:30], request.form.get("password", "")
        cnt, until = FAILS.get(u, (0, 0))
        if until > time.time():
            flash("Account locked for 1 minute (too many failed attempts)."); audit(u, "LOGIN blocked (locked)")
            return render_template("login.html", step="login")
        rows = q("SELECT * FROM users WHERE username=?", (u,))
        if rows and check_password_hash(rows[0]["pw"], p):
            FAILS.pop(u, None)
            session.update(pre=u, otp=f"{secrets.randbelow(10**6):06d}", otp_exp=time.time() + 120)
            audit(u, "LOGIN password OK, OTP issued"); print(f"[SMS-OTP for {u}] {session['otp']}")
            return redirect("/otp")
        cnt += 1; FAILS[u] = (0, time.time() + 60) if cnt >= 3 else (cnt, 0)
        if cnt >= 3: alert("SECURITY", f"Brute-force suspected on account '{u}' - locked")
        audit(u, "LOGIN failed"); flash("Invalid credentials.")
    return render_template("login.html", step="login")

@app.route("/otp", methods=["GET", "POST"])
def otp():
    if "pre" not in session: return redirect("/login")
    if request.method == "POST":
        if time.time() < session["otp_exp"] and secrets.compare_digest(request.form.get("otp", ""), session["otp"]):
            u = session["pre"]; role = q("SELECT role FROM users WHERE username=?", (u,))[0]["role"]
            session.clear(); session.update(user=u, role=role, csrf=secrets.token_hex(16))
            audit(u, "LOGIN success (MFA)"); return redirect("/dashboard")
        audit(session["pre"], "OTP failed"); flash("Wrong or expired OTP.")
    return render_template("login.html", step="otp", demo_otp=session.get("otp"))

@app.route("/logout")
def logout(): audit(session.get("user"), "LOGOUT"); session.clear(); return redirect("/login")

# ---------------- App routes ----------------
@app.route("/dashboard")
@login_required
def dashboard(): return render_template("dashboard.html")

@app.route("/video")
@login_required
def video():
    def gen():
        while True:
            yield b"--f\r\nContent-Type: image/jpeg\r\n\r\n" + STATE["jpg"] + b"\r\n"; time.sleep(0.5)
    return Response(gen(), mimetype="multipart/x-mixed-replace; boundary=f")

@app.route("/api/status")
@login_required
def status():
    sl = [dict(id=i, state=s) for i, s in sorted(STATE["slots"].items())]
    hist = q("SELECT temp,gas,ts FROM sensor_data ORDER BY id DESC LIMIT 20")[::-1]
    mine = q("SELECT slot,fee,end FROM bookings WHERE user=? AND end>?", (session["user"], time.time()))
    return jsonify(slots=sl, sensors=STATE["sensors"], alerts=[dict(r) for r in q("SELECT * FROM alerts ORDER BY id DESC LIMIT 6")],
                   chart=[dict(r) for r in hist], mine=[dict(r) for r in mine])

@app.route("/book", methods=["POST"])
@login_required
def book():
    d = request.get_json(silent=True) or {}
    try: slot, hrs = int(d["slot"]), float(d["hours"])
    except (KeyError, ValueError, TypeError): return jsonify(ok=False, msg="Invalid input"), 400
    if not (1 <= slot <= 12 and 0 < hrs <= 12): return jsonify(ok=False, msg="Invalid slot or hours"), 400
    if STATE["slots"].get(slot) != "free": return jsonify(ok=False, msg=f"Slot P{slot} is not free"), 409
    fee = math.ceil(hrs) * RATE
    ex("INSERT INTO bookings(user,slot,start,end,fee) VALUES(?,?,?,?,?)", (session["user"], slot, time.time(), time.time() + hrs * 3600, fee))
    audit(session["user"], f"BOOK slot {slot} for {hrs}h fee {fee}")
    return jsonify(ok=True, msg=f"Slot P{slot} booked. Fee = Rs {fee}")

@app.route("/admin")
@login_required
@admin_required
def admin():
    acc = round(100 * STATE["correct"] / max(1, STATE["total"]), 1)
    return render_template("admin.html", acc=acc, alerts=q("SELECT * FROM alerts ORDER BY id DESC LIMIT 15"),
        logs=q("SELECT * FROM audit_log ORDER BY id DESC LIMIT 20"), nb=q("SELECT COUNT(*) c, COALESCE(SUM(fee),0) s FROM bookings")[0],
        nm=q("SELECT COUNT(*) c FROM sensor_data")[0]["c"])

@app.route("/admin/attack", methods=["POST"])
@login_required
@admin_required
def attack():
    audit(session["user"], "Launched attack simulation"); threading.Thread(target=attack_sim, daemon=True).start()
    flash("Attack simulation launched - check the alerts."); return redirect("/admin")

if __name__ == "__main__":
    init_db()
    for t in (camera_loop, lambda: sensor_loop("sensor1", "secret123", "Zone-A"), lambda: sensor_loop("sensor2", "secret456", "Zone-B")):
        threading.Thread(target=t, daemon=True).start()
    print("Open http://127.0.0.1:5000  | admin/Admin@123 or user/User@123 | OTP is printed here")
    app.run(port=5000, threaded=True)
