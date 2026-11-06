"""
PLV Dance Company — Attendance & Contact Tracing v4
Rotating QR (30s) · Device binding · IP flags · Full audit log
"""
import os, io, csv, hmac, hashlib, secrets, base64, sqlite3, datetime
from functools import wraps
from flask import (Flask, request, jsonify, g, session,
                   render_template, Response)
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode

DB_PATH              = os.environ.get("DB_PATH", "plvdc_attendance.db")
ADMIN_USERNAME       = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD       = os.environ.get("ADMIN_PASSWORD", "admin123")
CLASS_START          = datetime.time(17, 30)
CLASS_END            = datetime.time(20, 30)
CHECKIN_OPENS_BEFORE = 30       # minutes
DEFAULT_GRACE        = 15       # present window
ROTATION_SECONDS     = 30       # rotating QR cadence
IP_FLAG_WINDOW       = 10       # minutes to look back for same-IP check-ins
IP_FLAG_THRESHOLD    = 2        # >=2 other users from same IP in window = flag

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  email TEXT,
  password_hash TEXT,
  tier TEXT NOT NULL DEFAULT 'provi' CHECK(tier IN ('exec','member','provi')),
  section TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,
  is_claimed INTEGER NOT NULL DEFAULT 0,
  device_hash TEXT,
  device_bound_at TEXT,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  type TEXT NOT NULL DEFAULT 'class',
  starts_at TEXT NOT NULL,
  ends_at TEXT,
  grace_minutes INTEGER NOT NULL DEFAULT 15,
  code_secret TEXT NOT NULL,
  is_mandatory INTEGER NOT NULL DEFAULT 1,
  notes TEXT,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS attendance(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL REFERENCES sessions(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  check_in_at TEXT,
  check_out_at TEXT,
  status TEXT NOT NULL DEFAULT 'present'
         CHECK(status IN ('present','late','excused','absent')),
  marked_by_admin INTEGER NOT NULL DEFAULT 0,
  device_hash TEXT,
  ip TEXT,
  notes TEXT,
  UNIQUE(session_id, user_id));
CREATE TABLE IF NOT EXISTS attendance_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER,
  user_id INTEGER,
  action TEXT NOT NULL,
  ip TEXT,
  user_agent TEXT,
  device_hash TEXT,
  notes TEXT,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS flags(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER,
  user_id INTEGER,
  kind TEXT NOT NULL,
  detail TEXT,
  resolved INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_att_user    ON attendance(user_id);
CREATE INDEX IF NOT EXISTS ix_att_session ON attendance(session_id);
CREATE INDEX IF NOT EXISTS ix_log_session ON attendance_log(session_id);
CREATE INDEX IF NOT EXISTS ix_flag_session ON flags(session_id);
"""

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

TIER_LABEL    = {"exec": "Executive Board", "member": "Official Member", "provi": "Provisionary"}
SESSION_TYPES = ["class", "performance", "workshop", "meeting", "audition", "other"]


# ---------- helpers ----------
def now_iso(): return datetime.datetime.now().isoformat(timespec="seconds")

def parse_iso(s):
    if not s: return None
    if s.endswith("Z"): s = s[:-1]
    try: dt = datetime.datetime.fromisoformat(s)
    except ValueError: return None
    if dt.tzinfo: dt = dt.astimezone().replace(tzinfo=None)
    return dt

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(_=None):
    d = g.pop("db", None)
    if d: d.close()

def user_dict(row):
    if not row: return None
    return {k: row[k] for k in row.keys() if k != "password_hash"}

def get_client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return (fwd.split(",")[0].strip() or request.remote_addr or "unknown")[:64]

def log_action(session_id, user_id, action, notes=None, device_hash=None):
    db().execute(
        "INSERT INTO attendance_log(session_id,user_id,action,ip,user_agent,device_hash,notes,created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (session_id, user_id, action, get_client_ip(),
         (request.headers.get("User-Agent") or "")[:256],
         (device_hash or "")[:128], notes, now_iso()))
    db().commit()

def log_flag(session_id, user_id, kind, detail):
    db().execute(
        "INSERT INTO flags(session_id,user_id,kind,detail,created_at) VALUES(?,?,?,?,?)",
        (session_id, user_id, kind, detail, now_iso()))
    db().commit()

def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if session.get("auth_type") != "admin":
            return jsonify(error="admin authentication required"), 401
        return f(*a, **kw)
    return w

def user_required(f):
    @wraps(f)
    def w(*a, **kw):
        if session.get("auth_type") != "user" or "user_id" not in session:
            return jsonify(error="authentication required"), 401
        row = db().execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not row or not row["is_active"]:
            session.clear()
            return jsonify(error="account inactive"), 403
        g.current_user = row
        return f(*a, **kw)
    return w

def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        at = session.get("auth_type")
        if at not in ("admin", "user"):
            return jsonify(error="authentication required"), 401
        if at == "user":
            row = db().execute("SELECT * FROM users WHERE id=?", (session.get("user_id"),)).fetchone()
            if not row or not row["is_active"]:
                session.clear()
                return jsonify(error="account inactive"), 403
            g.current_user = row
        return f(*a, **kw)
    return w


# ---------- rotating codes ----------
def gen_secret(): return secrets.token_hex(16)

def rotate_code(secret, offset=0):
    window = (int(datetime.datetime.now().timestamp()) // ROTATION_SECONDS) + offset
    return hmac.new(secret.encode(), str(window).encode(), hashlib.sha256).hexdigest()[:6].upper()

def verify_rotating_code(secret, submitted):
    if not submitted: return False
    submitted = submitted.strip().upper()
    for offset in (-1, 0, 1):
        if hmac.compare_digest(rotate_code(secret, offset), submitted):
            return True
    return False


# ---------- schedule ----------
def friday_saturday_dates(weeks_ahead=4):
    today = datetime.date.today()
    now   = datetime.datetime.now()
    dates = []
    if today.weekday() == 4 and now.time() <= CLASS_END:
        dates.append((today, "Friday"))
    elif today.weekday() == 5 and now.time() <= CLASS_END:
        dates.append((today, "Saturday"))
    tomorrow = today + datetime.timedelta(days=1)
    days_until_fri = (4 - tomorrow.weekday()) % 7
    next_fri = tomorrow + datetime.timedelta(days=days_until_fri)
    for week in range(weeks_ahead):
        fri = next_fri + datetime.timedelta(weeks=week)
        sat = fri + datetime.timedelta(days=1)
        dates += [(fri, "Friday"), (sat, "Saturday")]
    return dates

def ensure_upcoming_classes(weeks_ahead=4):
    con = sqlite3.connect(DB_PATH); con.row_factory = sqlite3.Row
    created = 0
    try:
        for date, name in friday_saturday_dates(weeks_ahead):
            starts = datetime.datetime.combine(date, CLASS_START)
            ends   = datetime.datetime.combine(date, CLASS_END)
            s_iso  = starts.isoformat(timespec="seconds")
            if con.execute("SELECT 1 FROM sessions WHERE type='class' AND starts_at=?",
                           (s_iso,)).fetchone():
                continue
            con.execute(
                "INSERT INTO sessions(title,type,starts_at,ends_at,grace_minutes,"
                "code_secret,is_mandatory,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (f"{name} Class", "class", s_iso,
                 ends.isoformat(timespec="seconds"), DEFAULT_GRACE,
                 gen_secret(), 1, now_iso()))
            created += 1
        con.commit()
    finally:
        con.close()
    return created


# ---------- auth ----------
@app.post("/api/login")
def login():
    d = request.get_json(force=True) or {}
    if d.get("mode") == "admin":
        h_row = db().execute("SELECT value FROM settings WHERE key='admin_password_hash'").fetchone()
        h = h_row["value"] if h_row else None
        if (d.get("username") or "").strip() == ADMIN_USERNAME and h and \
           check_password_hash(h, d.get("password") or ""):
            session.clear()
            session["auth_type"] = "admin"
            return jsonify(type="admin", username=ADMIN_USERNAME)
        return jsonify(error="invalid admin credentials"), 401

    sid = (d.get("student_id") or "").strip()
    row = db().execute("SELECT * FROM users WHERE student_id=?", (sid,)).fetchone()
    if not row:
        return jsonify(error="student ID not found on the roster"), 401
    if not row["is_claimed"] or not row["password_hash"]:
        return jsonify(error="account not yet claimed — use 'Claim Account' first"), 401
    if not check_password_hash(row["password_hash"], d.get("password") or ""):
        return jsonify(error="invalid student ID or password"), 401
    if not row["is_active"]:
        return jsonify(error="account is deactivated — contact the Executive Board"), 403
    session.clear()
    session["auth_type"] = "user"
    session["user_id"] = row["id"]
    return jsonify(type="user", user=user_dict(row))


@app.post("/api/claim")
def claim():
    d = request.get_json(force=True) or {}
    sid   = (d.get("student_id") or "").strip()
    name  = (d.get("name") or "").strip()
    pw    = d.get("password") or ""
    email = (d.get("email") or "").strip().lower() or None
    if not sid or not name or len(pw) < 6:
        return jsonify(error="student ID, full name, and password (>=6 chars) required"), 400
    row = db().execute("SELECT * FROM users WHERE student_id=?", (sid,)).fetchone()
    if not row:
        return jsonify(error="this student ID is not on the roster. Contact the Executive Board."), 404
    if row["is_claimed"]:
        return jsonify(error="this student ID has already been registered. Sign in instead."), 409
    if row["name"].strip().lower() != name.strip().lower():
        return jsonify(error="the name doesn't match our roster. Contact the Executive Board."), 400
    db().execute("UPDATE users SET password_hash=?, email=?, is_claimed=1 WHERE id=?",
                 (generate_password_hash(pw), email, row["id"]))
    db().commit()
    session.clear()
    session["auth_type"] = "user"
    session["user_id"] = row["id"]
    fresh = db().execute("SELECT * FROM users WHERE id=?", (row["id"],)).fetchone()
    return jsonify(type="user", user=user_dict(fresh))


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    at = session.get("auth_type")
    if at == "admin":
        return jsonify(type="admin", username=ADMIN_USERNAME)
    if at == "user":
        row = db().execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not row or not row["is_active"]:
            session.clear()
            return jsonify(error="auth required"), 401
        return jsonify(type="user", user=user_dict(row))
    return jsonify(error="auth required"), 401


@app.post("/api/admin/change-password")
@admin_required
def change_admin_password():
    d = request.get_json(force=True) or {}
    if len(d.get("new_password") or "") < 6:
        return jsonify(error="new password must be at least 6 characters"), 400
    db().execute("UPDATE settings SET value=? WHERE key='admin_password_hash'",
                 (generate_password_hash(d["new_password"]),))
    db().commit()
    return jsonify(ok=True)


# ---------- admin dashboard ----------
@app.get("/api/admin/dashboard")
@admin_required
def admin_dashboard():
    tiers = {r["tier"]: r["c"] for r in db().execute(
        "SELECT tier, COUNT(*) c FROM users WHERE is_active=1 AND is_claimed=1 GROUP BY tier").fetchall()}
    unclaimed = db().execute("SELECT COUNT(*) c FROM users WHERE is_claimed=0").fetchone()["c"]
    unresolved_flags = db().execute("SELECT COUNT(*) c FROM flags WHERE resolved=0").fetchone()["c"]
    today = db().execute(
        "SELECT * FROM sessions WHERE type='class' AND date(starts_at)=date('now','localtime') "
        "ORDER BY starts_at LIMIT 1").fetchone()
    today_stats = None
    if today:
        today_stats = {r["status"]: r["c"] for r in db().execute(
            "SELECT status, COUNT(*) c FROM attendance WHERE session_id=? GROUP BY status",
            (today["id"],)).fetchall()}
    recent_flags = [dict(r) for r in db().execute(
        "SELECT f.*, u.name AS user_name, s.title AS session_title "
        "FROM flags f LEFT JOIN users u ON u.id=f.user_id "
        "LEFT JOIN sessions s ON s.id=f.session_id "
        "WHERE f.resolved=0 ORDER BY f.created_at DESC LIMIT 8").fetchall()]
    using_default = check_password_hash(
        (db().execute("SELECT value FROM settings WHERE key='admin_password_hash'").fetchone() or {"value":""})["value"],
        "admin123")
    return jsonify(
        tiers={"exec": tiers.get("exec",0), "member": tiers.get("member",0),
               "provi": tiers.get("provi",0), "total": sum(tiers.values()),
               "unclaimed": unclaimed},
        unresolved_flags=unresolved_flags,
        today_class=dict(today) if today else None,
        today_stats=today_stats,
        recent_flags=recent_flags,
        using_default_password=using_default)


# ---------- admin sessions ----------
@app.get("/api/admin/sessions")
@admin_required
def admin_list_sessions():
    past = request.args.get("past", type=int, default=0)
    op = "<=" if past else ">="
    rows = db().execute(
        f"SELECT s.*, (SELECT COUNT(*) FROM attendance a WHERE a.session_id=s.id) AS checked_in "
        f"FROM sessions s WHERE s.starts_at {op} ? ORDER BY s.starts_at "
        + ("DESC" if past else "ASC") + " LIMIT 300", (now_iso(),)).fetchall()
    return jsonify(sessions=[dict(r) for r in rows])


@app.post("/api/admin/sessions/generate-classes")
@admin_required
def admin_generate_classes():
    weeks = int((request.get_json(silent=True) or {}).get("weeks", 4))
    return jsonify(created=ensure_upcoming_classes(weeks), weeks=weeks)


@app.post("/api/admin/sessions")
@admin_required
def admin_create_session():
    d = request.get_json(force=True) or {}
    title = (d.get("title") or "").strip()
    stype = (d.get("type") or "class").lower()
    if not title or stype not in SESSION_TYPES or not d.get("starts_at"):
        return jsonify(error="title, valid type, and starts_at required"), 400
    cur = db().execute(
        "INSERT INTO sessions(title,type,starts_at,ends_at,grace_minutes,code_secret,"
        "is_mandatory,notes,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (title, stype, d["starts_at"], d.get("ends_at"),
         int(d.get("grace_minutes") or DEFAULT_GRACE), gen_secret(),
         1 if d.get("is_mandatory", True) else 0, d.get("notes"), now_iso()))
    db().commit()
    row = db().execute("SELECT * FROM sessions WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify(session=dict(row))


@app.get("/api/admin/sessions/<int:sid>")
@admin_required
def admin_get_session(sid):
    row = db().execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    return jsonify(session=dict(row)) if row else (jsonify(error="not found"), 404)


@app.get("/api/admin/sessions/<int:sid>/qr-data")
@admin_required
def admin_qr_data(sid):
    s = db().execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    if not s: return jsonify(error="not found"), 404
    code = rotate_code(s["code_secret"], 0)
    now  = int(datetime.datetime.now().timestamp())
    window = now // ROTATION_SECONDS
    seconds_left = (window + 1) * ROTATION_SECONDS - now
    payload = f"PLVDC:{sid}:{code}"
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=3)
    qr.add_data(payload); qr.make(fit=True)
    img = qr.make_image(fill_color="#0F1F5C", back_color="white")
    buf = io.BytesIO(); img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()
    return jsonify(code=code, qr_png=f"data:image/png;base64,{b64}",
                   seconds_left=seconds_left)


@app.get("/api/admin/sessions/<int:sid>/live")
@admin_required
def admin_session_live(sid):
    count = db().execute("SELECT COUNT(*) c FROM attendance WHERE session_id=? AND status IN ('present','late')",
                         (sid,)).fetchone()["c"]
    recent = [dict(r) for r in db().execute(
        "SELECT u.name, u.student_id, a.check_in_at, a.status "
        "FROM attendance a JOIN users u ON u.id=a.user_id "
        "WHERE a.session_id=? ORDER BY a.check_in_at DESC LIMIT 5", (sid,)).fetchall()]
    flags = [dict(r) for r in db().execute(
        "SELECT f.*, u.name AS user_name FROM flags f LEFT JOIN users u ON u.id=f.user_id "
        "WHERE f.session_id=? AND f.resolved=0 ORDER BY f.created_at DESC", (sid,)).fetchall()]
    return jsonify(count=count, recent=recent, flags=flags)


@app.get("/api/admin/sessions/<int:sid>/attendance")
@admin_required
def admin_session_attendance(sid):
    if not db().execute("SELECT 1 FROM sessions WHERE id=?", (sid,)).fetchone():
        return jsonify(error="session not found"), 404
    rows = db().execute(
        "SELECT u.id AS user_id, u.student_id, u.name, u.email, u.tier, "
        "       a.status, a.check_in_at, a.check_out_at, a.marked_by_admin "
        "FROM users u LEFT JOIN attendance a ON a.user_id=u.id AND a.session_id=? "
        "WHERE u.is_active=1 AND u.is_claimed=1 "
        "ORDER BY CASE u.tier WHEN 'exec' THEN 0 WHEN 'member' THEN 1 ELSE 2 END, u.name",
        (sid,)).fetchall()
    return jsonify(records=[dict(r) for r in rows])


@app.post("/api/admin/sessions/<int:sid>/attendance/<int:user_id>")
@admin_required
def admin_mark_attendance(sid, user_id):
    d = request.get_json(force=True) or {}
    status = (d.get("status") or "").lower()
    if status not in ("present","late","excused","absent"):
        return jsonify(error="invalid status"), 400
    if not db().execute("SELECT 1 FROM sessions WHERE id=?", (sid,)).fetchone():
        return jsonify(error="session not found"), 404
    if not db().execute("SELECT 1 FROM users WHERE id=?", (user_id,)).fetchone():
        return jsonify(error="attendee not found"), 404
    existing = db().execute("SELECT id FROM attendance WHERE session_id=? AND user_id=?",
                            (sid, user_id)).fetchone()
    ts = now_iso()
    check_in = ts if status in ("present","late") else None
    if existing:
        db().execute("UPDATE attendance SET status=?, marked_by_admin=1, notes=?, "
                     "check_in_at=COALESCE(check_in_at, ?) WHERE id=?",
                     (status, d.get("notes"), check_in, existing["id"]))
    else:
        db().execute("INSERT INTO attendance(session_id,user_id,check_in_at,status,marked_by_admin,notes) "
                     "VALUES(?,?,?,?,?,?)", (sid, user_id, check_in, status, 1, d.get("notes")))
    db().commit()
    log_action(sid, user_id, "admin_mark", notes=f"status={status}")
    return jsonify(ok=True)


@app.delete("/api/admin/sessions/<int:sid>/attendance/<int:user_id>")
@admin_required
def admin_clear_attendance(sid, user_id):
    db().execute("DELETE FROM attendance WHERE session_id=? AND user_id=?", (sid, user_id))
    db().commit()
    return jsonify(ok=True)


@app.get("/api/admin/sessions/<int:sid>/attendance.csv")
@admin_required
def admin_export_csv(sid):
    srow = db().execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    if not srow: return jsonify(error="not found"), 404
    rows = db().execute(
        "SELECT u.student_id, u.name, u.tier, u.section, "
        "       a.status, a.check_in_at, a.check_out_at, a.marked_by_admin "
        "FROM users u LEFT JOIN attendance a ON a.user_id=u.id AND a.session_id=? "
        "WHERE u.is_active=1 AND u.is_claimed=1 "
        "ORDER BY CASE u.tier WHEN 'exec' THEN 0 WHEN 'member' THEN 1 ELSE 2 END, u.name",
        (sid,)).fetchall()
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["Session", srow["title"]]); w.writerow(["Starts", srow["starts_at"]])
    w.writerow(["Ends", srow["ends_at"] or ""]); w.writerow([])
    w.writerow(["Student ID","Name","Tier","Section","Status","Check-in","Check-out","Marked by Admin"])
    for r in rows:
        w.writerow([r["student_id"], r["name"], TIER_LABEL[r["tier"]],
                    r["section"] or "", r["status"] or "absent",
                    r["check_in_at"] or "", r["check_out_at"] or "",
                    "yes" if r["marked_by_admin"] else ""])
    return Response(buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=class-{sid}.csv"})


# ---------- admin roster ----------
@app.get("/api/admin/attendees")
@admin_required
def admin_list_attendees():
    rows = db().execute(
        "SELECT id,student_id,name,email,tier,section,is_active,is_claimed,device_hash,created_at "
        "FROM users ORDER BY is_claimed ASC, "
        "CASE tier WHEN 'exec' THEN 0 WHEN 'member' THEN 1 ELSE 2 END, name").fetchall()
    return jsonify(attendees=[dict(r) for r in rows])


@app.post("/api/admin/attendees/bulk")
@admin_required
def admin_bulk_import():
    d = request.get_json(force=True) or {}
    text = (d.get("text") or "").strip()
    default_tier = (d.get("tier") or "provi").lower()
    if default_tier not in ("exec","member","provi"): default_tier = "provi"
    created, updated, skipped = 0, 0, []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"): continue
        parts = [p.strip() for p in line.split(",")]
        if parts[0].lower() in ("student_id","id","student id"): continue
        if len(parts) < 2:
            skipped.append({"line_no": i, "line": line, "reason": "needs student_id and name"}); continue
        sid, name = parts[0], parts[1]
        section = parts[2] if len(parts) > 2 and parts[2] else None
        if not sid or not name:
            skipped.append({"line_no": i, "line": line, "reason": "empty student_id or name"}); continue
        existing = db().execute("SELECT * FROM users WHERE student_id=?", (sid,)).fetchone()
        if existing:
            if existing["is_claimed"]:
                skipped.append({"line_no": i, "line": line, "reason": "already claimed"}); continue
            db().execute("UPDATE users SET name=?, section=?, tier=? WHERE id=?",
                         (name, section or existing["section"], default_tier, existing["id"]))
            updated += 1
        else:
            db().execute("INSERT INTO users(student_id,name,section,tier,is_claimed,is_active,created_at) "
                         "VALUES(?,?,?,?,0,1,?)", (sid, name, section, default_tier, now_iso()))
            created += 1
    db().commit()
    return jsonify(created=created, updated=updated, skipped=skipped)


@app.patch("/api/admin/attendees/<int:uid>")
@admin_required
def admin_update_attendee(uid):
    d = request.get_json(force=True) or {}
    row = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not row: return jsonify(error="not found"), 404
    if "tier" in d:
        if d["tier"] not in ("exec","member","provi"): return jsonify(error="invalid tier"), 400
        db().execute("UPDATE users SET tier=? WHERE id=?", (d["tier"], uid))
    if "is_active" in d:
        db().execute("UPDATE users SET is_active=? WHERE id=?", (1 if d["is_active"] else 0, uid))
    if "reset_device" in d and d["reset_device"]:
        db().execute("UPDATE users SET device_hash=NULL, device_bound_at=NULL WHERE id=?", (uid,))
    if "section" in d:
        db().execute("UPDATE users SET section=? WHERE id=?", (d["section"], uid))
    db().commit()
    return jsonify(attendee=user_dict(db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()))


@app.delete("/api/admin/attendees/<int:uid>")
@admin_required
def admin_delete_attendee(uid):
    row = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not row: return jsonify(error="not found"), 404
    if row["is_claimed"]:
        return jsonify(error="cannot delete a claimed account — deactivate instead"), 400
    db().execute("DELETE FROM users WHERE id=?", (uid,))
    db().commit()
    return jsonify(ok=True)


# ---------- admin flags & log ----------
@app.get("/api/admin/flags")
@admin_required
def admin_flags():
    rows = db().execute(
        "SELECT f.*, u.name AS user_name, u.student_id, s.title AS session_title, s.starts_at "
        "FROM flags f LEFT JOIN users u ON u.id=f.user_id "
        "LEFT JOIN sessions s ON s.id=f.session_id "
        "WHERE f.resolved=0 ORDER BY f.created_at DESC LIMIT 100").fetchall()
    return jsonify(flags=[dict(r) for r in rows])


@app.post("/api/admin/flags/<int:fid>/resolve")
@admin_required
def admin_resolve_flag(fid):
    db().execute("UPDATE flags SET resolved=1 WHERE id=?", (fid,))
    db().commit()
    return jsonify(ok=True)


@app.get("/api/admin/logs")
@admin_required
def admin_logs():
    rows = db().execute(
        "SELECT l.*, u.name AS user_name FROM attendance_log l "
        "LEFT JOIN users u ON u.id=l.user_id "
        "ORDER BY l.created_at DESC LIMIT 200").fetchall()
    return jsonify(logs=[dict(r) for r in rows])


# ---------- admin trace ----------
@app.get("/api/admin/trace")
@admin_required
def admin_trace():
    user_id = request.args.get("user_id", type=int)
    if not user_id: return jsonify(error="user_id is required"), 400
    frm, to = request.args.get("from"), request.args.get("to")
    q = """
    SELECT a2.user_id, u.name, u.student_id, u.tier,
           s.id AS session_id, s.title, s.starts_at
    FROM attendance a
    JOIN sessions s ON s.id=a.session_id
    JOIN attendance a2 ON a2.session_id=a.session_id AND a2.user_id != a.user_id
    JOIN users u ON u.id=a2.user_id
    WHERE a.user_id=? AND a.status IN ('present','late') AND a2.status IN ('present','late')
    """
    params = [user_id]
    if frm: q += " AND a.check_in_at >= ?"; params.append(frm)
    if to:  q += " AND a.check_in_at <= ?"; params.append(to)
    q += " ORDER BY s.starts_at DESC, u.name"
    rows = [dict(r) for r in db().execute(q, params).fetchall()]
    summary = {}
    for r in rows:
        k = r["user_id"]
        if k not in summary:
            summary[k] = {"user_id": k, "name": r["name"], "student_id": r["student_id"],
                          "tier": r["tier"], "shared_sessions": 0, "sessions": []}
        summary[k]["shared_sessions"] += 1
        summary[k]["sessions"].append({"title": r["title"], "starts_at": r["starts_at"]})
    subject = db().execute("SELECT id,name,student_id,tier FROM users WHERE id=?", (user_id,)).fetchone()
    return jsonify(subject=dict(subject) if subject else None,
                   contacts=sorted(summary.values(), key=lambda x: -x["shared_sessions"]))


# ---------- customer: dashboard ----------
@app.get("/api/me/dashboard")
@user_required
def me_dashboard():
    u = g.current_user
    counts = {r["status"]: r["c"] for r in db().execute(
        "SELECT status, COUNT(*) c FROM attendance WHERE user_id=? GROUP BY status",
        (u["id"],)).fetchall()}
    attended = counts.get("present",0) + counts.get("late",0)
    total = sum(counts.values())
    rate = round(100 * attended / total) if total else 0
    today = db().execute(
        "SELECT * FROM sessions WHERE type='class' AND date(starts_at)=date('now','localtime') "
        "ORDER BY starts_at LIMIT 1").fetchone()
    my_today = None
    if today:
        my_today = db().execute("SELECT * FROM attendance WHERE session_id=? AND user_id=?",
                                (today["id"], u["id"])).fetchone()
    upcoming = [dict(r) for r in db().execute(
        "SELECT s.*, (SELECT status FROM attendance a WHERE a.session_id=s.id AND a.user_id=?) AS my_status "
        "FROM sessions s WHERE s.starts_at >= ? ORDER BY s.starts_at ASC LIMIT 8",
        (u["id"], now_iso())).fetchall()]
    return jsonify(
        user=user_dict(u),
        stats={"present": counts.get("present",0), "late": counts.get("late",0),
               "excused": counts.get("excused",0), "absent": counts.get("absent",0),
               "rate": rate, "total": total},
        today_class=dict(today) if today else None,
        my_today=dict(my_today) if my_today else None,
        upcoming=upcoming)


@app.get("/api/me/attendance")
@user_required
def me_attendance():
    rows = db().execute(
        "SELECT a.*, s.title, s.type, s.starts_at, s.is_mandatory "
        "FROM attendance a JOIN sessions s ON s.id=a.session_id "
        "WHERE a.user_id=? ORDER BY s.starts_at DESC LIMIT 200",
        (g.current_user["id"],)).fetchall()
    return jsonify(records=[dict(r) for r in rows])


# ---------- customer: check-in with anti-cheat ----------
@app.post("/api/me/checkin")
@user_required
def me_checkin():
    d = request.get_json(force=True) or {}
    raw = (d.get("code") or "").strip().upper()
    device_hash = (d.get("device_hash") or "").strip()[:128] or None

    sid, code = None, raw
    if raw.startswith("PLVDC:"):
        parts = raw.split(":")
        if len(parts) >= 3:
            try: sid = int(parts[1])
            except ValueError: sid = None
            code = parts[2]

    srow = None
    if sid:
        srow = db().execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
    else:
        now = datetime.datetime.now()
        candidates = db().execute(
            "SELECT * FROM sessions WHERE starts_at BETWEEN ? AND ?",
            ((now - datetime.timedelta(hours=6)).isoformat(),
             (now + datetime.timedelta(hours=1)).isoformat())).fetchall()
        for cand in candidates:
            if verify_rotating_code(cand["code_secret"], code):
                srow = cand; break

    if not srow:
        log_action(None, g.current_user["id"], "checkin_failed", notes="no matching session/code",
                   device_hash=device_hash)
        return jsonify(error="invalid or expired code — codes rotate every 30 seconds"), 400

    if not verify_rotating_code(srow["code_secret"], code):
        log_action(srow["id"], g.current_user["id"], "checkin_failed", notes="code mismatch",
                   device_hash=device_hash)
        return jsonify(error="code expired — scan the QR again"), 400

    existing = db().execute("SELECT 1 FROM attendance WHERE session_id=? AND user_id=?",
                            (srow["id"], g.current_user["id"])).fetchone()
    if existing:
        log_action(srow["id"], g.current_user["id"], "checkin_duplicate", device_hash=device_hash)
        return jsonify(error="you've already checked in to this session"), 409

    now = datetime.datetime.now()
    starts = parse_iso(srow["starts_at"])
    ends   = parse_iso(srow["ends_at"]) or (starts + datetime.timedelta(hours=3))
    if now < starts - datetime.timedelta(minutes=CHECKIN_OPENS_BEFORE):
        return jsonify(error="check-in opens 30 minutes before class"), 400
    if now > ends:
        return jsonify(error="check-in window has closed"), 400

    # --- device binding ---
    u = g.current_user
    if device_hash and not u["device_hash"]:
        db().execute("UPDATE users SET device_hash=?, device_bound_at=? WHERE id=?",
                     (device_hash, now_iso(), u["id"]))
        db().commit()
    elif device_hash and u["device_hash"] and device_hash != u["device_hash"]:
        log_flag(srow["id"], u["id"], "device_changed",
                 f"Previous: {u['device_hash'][:12]}… New: {device_hash[:12]}…")
        log_action(srow["id"], u["id"], "flag_device_change", device_hash=device_hash)

    # --- IP collusion detection ---
    ip = get_client_ip()
    window_start = (now - datetime.timedelta(minutes=IP_FLAG_WINDOW)).isoformat()
    others_same_ip = db().execute(
        "SELECT COUNT(DISTINCT user_id) c FROM attendance_log "
        "WHERE session_id=? AND ip=? AND user_id!=? AND action='checkin_success' AND created_at > ?",
        (srow["id"], ip, u["id"], window_start)).fetchone()["c"]
    if others_same_ip >= IP_FLAG_THRESHOLD:
        log_flag(srow["id"], u["id"], "shared_ip",
                 f"{others_same_ip} other accounts from {ip} within {IP_FLAG_WINDOW} min")

    cutoff = starts + datetime.timedelta(minutes=srow["grace_minutes"] or DEFAULT_GRACE)
    status = "present" if now <= cutoff else "late"
    db().execute(
        "INSERT INTO attendance(session_id,user_id,check_in_at,status,marked_by_admin,device_hash,ip) "
        "VALUES(?,?,?,?,0,?,?)",
        (srow["id"], u["id"], now.isoformat(timespec="seconds"), status, device_hash, ip))
    db().commit()
    log_action(srow["id"], u["id"], "checkin_success", notes=f"status={status}",
               device_hash=device_hash)
    return jsonify(session_id=srow["id"], title=srow["title"], status=status)


@app.post("/api/me/checkout")
@user_required
def me_checkout():
    d = request.get_json(force=True) or {}
    sid = d.get("session_id")
    if not sid: return jsonify(error="session_id required"), 400
    cur = db().execute(
        "UPDATE attendance SET check_out_at=? "
        "WHERE session_id=? AND user_id=? AND check_out_at IS NULL",
        (now_iso(), sid, g.current_user["id"]))
    db().commit()
    if cur.rowcount == 0: return jsonify(error="no open check-in"), 404
    return jsonify(ok=True)


# ---------- policies (served to customer UI) ----------
@app.get("/api/policies")
def policies():
    try:
        with open("POLICIES.md", encoding="utf-8") as f:
            return jsonify(markdown=f.read())
    except FileNotFoundError:
        return jsonify(markdown="# Policies\n\nPOLICIES.md not found.")


# ---------- SPA ----------
@app.get("/")
def index():
    return render_template("index.html")


# ---------- startup ----------
def init_db():
    con = sqlite3.connect(DB_PATH); con.executescript(SCHEMA); con.commit(); con.close()

def ensure_admin_password():
    con = sqlite3.connect(DB_PATH)
    try:
        row = con.execute("SELECT value FROM settings WHERE key='admin_password_hash'").fetchone()
        if not row:
            con.execute("INSERT INTO settings(key,value) VALUES('admin_password_hash',?)",
                        (generate_password_hash(ADMIN_PASSWORD),))
            con.commit()
            if ADMIN_PASSWORD == "admin123":
                print("[WARN] Default admin password in use. Set ADMIN_PASSWORD env or change via UI.")
    finally:
        con.close()

init_db()
ensure_admin_password()
ensure_upcoming_classes(4)
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)