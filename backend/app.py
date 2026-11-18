
import hashlib, secrets, sqlite3
from pathlib import Path
from fastapi import Header, HTTPException
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DB_PATH = DATA / "app.db"
FRONTEND = ROOT / "frontend"
SESSIONS: dict[str, str] = {}

def connect():
    DATA.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def sha(p: str) -> str:
    return hashlib.sha256(p.encode("utf-8")).hexdigest()

SEED_USERS = [
    ("admin", "123456", "管理员"),
    ("admin2", "admin123", "管理员"),  # 第二名值班，用于双人抢审批排队
    ("viewer", "view123", "只读"),
]

def ensure_users(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY, password_sha TEXT NOT NULL, role TEXT NOT NULL)""")
    for u, p, r in SEED_USERS:
        conn.execute("INSERT OR IGNORE INTO users VALUES (?,?,?)", (u, sha(p), r))

class LoginIn(BaseModel):
    username: str
    password: str

def require_user(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "未登录")
    u = SESSIONS.get(authorization.removeprefix("Bearer ").strip())
    if not u:
        raise HTTPException(401, "登录已失效")
    return u

def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")

def audit(conn, actor: str, action: str, detail: str):
    conn.execute("INSERT INTO audit_log(actor,action,detail,created_at) VALUES (?,?,?,?)",
                 (actor, action, detail, now_iso()))

def require_admin(username: str, attempt: str):
    """发布鉴权落点（乙路径，见 docs/publish-authz-registry.md）：仅值班管理员。
    偏离发布鉴权册一律拦下（403，零写入）并记审计「鉴权偏离拦截」。"""
    with connect() as c:
        row = c.execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
        role = row["role"] if row else "未知"
        if role == "管理员":
            return
        audit(c, username, "鉴权偏离拦截",
              f"角色「{role}」尝试{attempt}，按发布鉴权册(乙路径)拦下，零写入")
    raise HTTPException(403, "无权操作：仅值班管理员可执行，已按发布鉴权册记鉴权偏离")

from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

PRODUCT = "入站契约"
SKELETON = "Schema 契约版本约束入站校验，破坏性变更进缓冲或拒收，并与落库结果对账"

app = FastAPI(title=PRODUCT)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

def init_db():
    with connect() as conn:
        ensure_users(conn)
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS contracts(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          version TEXT UNIQUE NOT NULL,
          subject TEXT NOT NULL,
          mode TEXT NOT NULL,
          track TEXT NOT NULL,
          status TEXT NOT NULL,
          required_fields TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ingress_batches(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          subject TEXT NOT NULL,
          payload_fields TEXT NOT NULL,
          contract_version TEXT,
          result TEXT NOT NULL,
          detail TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS buffers(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          batch_id INTEGER NOT NULL,
          reason TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS publish_requests(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          version TEXT NOT NULL,
          subject TEXT NOT NULL,
          mode TEXT NOT NULL,
          required_fields TEXT NOT NULL,
          applicant TEXT NOT NULL,
          status TEXT NOT NULL,
          decided_by TEXT,
          decided_at TEXT,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          actor TEXT NOT NULL,
          action TEXT NOT NULL,
          detail TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        """)
        if conn.execute("SELECT COUNT(*) c FROM contracts").fetchone()["c"] == 0:
            conn.execute("INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,?,?,?)",
                         ("v3","订单入站","严格","正式","启用","order_id,amount,currency"))
            conn.execute("INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,?,?,?)",
                         ("v4-shadow","订单入站","兼容","影子","试跑","order_id,amount,currency,channel"))
            conn.execute("INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,?,?,?)",
                         ("v2","库存入站","严格","正式","停用","sku,qty"))

@app.on_event("startup")
def _s():
    init_db()

@app.get("/api/health")
def health():
    with connect() as c:
        n = c.execute("SELECT COUNT(*) c FROM contracts").fetchone()["c"]
    return {"ok": True, "product": PRODUCT, "skeleton": SKELETON, "contracts": n, "db": str(DB_PATH)}

@app.post("/api/login")
def login(body: LoginIn):
    with connect() as c:
        row = c.execute("SELECT username,role FROM users WHERE username=? AND password_sha=?", (body.username, sha(body.password))).fetchone()
    if not row: raise HTTPException(401, "账号或密码错误")
    tok = secrets.token_hex(16); SESSIONS[tok]=row["username"]
    return {"token": tok, "username": row["username"], "role": row["role"]}

@app.get("/api/contracts")
def contracts(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items":[dict(r) for r in c.execute("SELECT * FROM contracts ORDER BY id").fetchall()]}

class PublishIn(BaseModel):
    version: str
    subject: str
    mode: str
    required_fields: str

@app.post("/api/contracts/publish")
def publish(body: PublishIn, authorization: str | None = Header(default=None)):
    # 发布鉴权册(乙路径)：直发入口已关闭，任何角色一律 403 零写入并记鉴权偏离。
    # 正式指针仅审批办结后由服务端切换（见 /api/publish-requests/{id}/approve）。
    user = require_user(authorization)
    with connect() as c:
        audit(c, user, "鉴权偏离拦截",
              f"尝试直发启用契约版本 {body.version}，发布鉴权册(乙路径)规定直发入口关闭，已拦下，零写入")
    raise HTTPException(403, "直发入口已关闭：契约版本须提交发布申请，审批办结后由服务端切换正式指针")

@app.post("/api/publish-requests")
def file_request(body: PublishIn, authorization: str | None = Header(default=None)):
    # 乙路径：任何登录用户（含只读）可提申请单；只写申请，不动版本目录
    user = require_user(authorization)
    if not body.version.strip() or not body.subject.strip() or not body.required_fields.strip():
        raise HTTPException(422, "版本、主题、必填字段不能为空")
    if body.mode not in ("严格", "兼容"):
        raise HTTPException(422, "模式仅支持 严格/兼容")
    with connect() as c:
        if c.execute("SELECT 1 FROM contracts WHERE version=?", (body.version,)).fetchone():
            raise HTTPException(409, "版本号已存在于版本目录")
        if c.execute("SELECT 1 FROM publish_requests WHERE version=? AND status='待审批'", (body.version,)).fetchone():
            raise HTTPException(409, "该版本已有待审批申请")
        cur = c.execute("INSERT INTO publish_requests(version,subject,mode,required_fields,applicant,status,created_at) VALUES (?,?,?,?,?,'待审批',?)",
                        (body.version, body.subject, body.mode, body.required_fields, user, now_iso()))
        rid = cur.lastrowid
        audit(c, user, "提交发布申请", f"申请#{rid} {body.version}/{body.subject}/{body.mode} 必填[{body.required_fields}]")
    return {"id": rid, "version": body.version, "status": "待审批"}

@app.get("/api/publish-requests")
def list_requests(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in c.execute("SELECT * FROM publish_requests ORDER BY id DESC").fetchall()]}

@app.post("/api/publish-requests/{rid}/approve")
def approve_request(rid: int, authorization: str | None = Header(default=None)):
    user = require_user(authorization)
    require_admin(user, f"审批通过发布申请#{rid}")
    outcome, payload = "ok", None
    with connect() as c:
        req = c.execute("SELECT * FROM publish_requests WHERE id=?", (rid,)).fetchone()
        if not req:
            outcome = "missing"
        elif req["status"] != "待审批":
            audit(c, user, "审批争用", f"申请#{rid} 已被其他值班处置（{req['status']}），后到审批仅登记争用")
            outcome = "contention"
        elif c.execute("SELECT 1 FROM contracts WHERE version=?", (req["version"],)).fetchone():
            outcome = "version_conflict"
        else:
            # 状态机原子认领：两名值班同时抢审批在此排队，先到办结
            cur = c.execute("UPDATE publish_requests SET status='已通过', decided_by=?, decided_at=? WHERE id=? AND status='待审批'",
                            (user, now_iso(), rid))
            if cur.rowcount == 0:
                audit(c, user, "审批争用", f"申请#{rid} 已被其他值班处置，后到审批仅登记争用")
                outcome = "contention"
            else:
                old = c.execute("SELECT version FROM contracts WHERE subject=? AND track='正式' AND status='启用'", (req["subject"],)).fetchone()
                c.execute("UPDATE contracts SET status='停用' WHERE subject=? AND track='正式' AND status='启用'", (req["subject"],))
                c.execute("INSERT INTO contracts(version,subject,mode,track,status,required_fields) VALUES (?,?,?,'正式','启用',?)",
                          (req["version"], req["subject"], req["mode"], req["required_fields"]))
                audit(c, user, "审批通过",
                      f"申请#{rid} 办结，服务端切换正式指针：{req['version']} 启用" + (f"，{old['version']} 停用" if old else ""))
                payload = {"id": rid, "status": "已通过", "enabled": req["version"], "retired": old["version"] if old else None}
    if outcome == "missing":
        raise HTTPException(404, "申请不存在")
    if outcome == "version_conflict":
        raise HTTPException(409, "版本号已存在于版本目录")
    if outcome == "contention":
        raise HTTPException(409, "审批争用：该申请已被其他值班处置，已登记")
    return payload

@app.post("/api/publish-requests/{rid}/reject")
def reject_request(rid: int, authorization: str | None = Header(default=None)):
    user = require_user(authorization)
    require_admin(user, f"驳回发布申请#{rid}")
    outcome = "ok"
    with connect() as c:
        cur = c.execute("UPDATE publish_requests SET status='已驳回', decided_by=?, decided_at=? WHERE id=? AND status='待审批'",
                        (user, now_iso(), rid))
        if cur.rowcount == 0:
            if c.execute("SELECT 1 FROM publish_requests WHERE id=?", (rid,)).fetchone():
                audit(c, user, "审批争用", f"申请#{rid} 已被其他值班处置，后到驳回仅登记争用")
                outcome = "contention"
            else:
                outcome = "missing"
        else:
            audit(c, user, "审批驳回", f"申请#{rid} 已驳回")
    if outcome == "missing":
        raise HTTPException(404, "申请不存在")
    if outcome == "contention":
        raise HTTPException(409, "审批争用：该申请已被其他值班处置，已登记")
    return {"id": rid, "status": "已驳回"}

@app.get("/api/audit")
def audit_trail(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items": [dict(r) for r in c.execute("SELECT * FROM audit_log ORDER BY id DESC").fetchall()]}

class IngressIn(BaseModel):
    subject: str
    payload_fields: str  # comma fields present

@app.post("/api/ingress/validate")
def validate(body: IngressIn, authorization: str | None = Header(default=None)):
    require_user(authorization)
    fields = {x.strip() for x in body.payload_fields.split(",") if x.strip()}
    with connect() as c:
        ctr = c.execute("SELECT * FROM contracts WHERE subject=? AND track='正式' AND status='启用' ORDER BY id DESC LIMIT 1", (body.subject,)).fetchone()
        if not ctr:
            raise HTTPException(404, "无启用正式契约")
        need = {x.strip() for x in ctr["required_fields"].split(",") if x.strip()}
        missing = sorted(need - fields)
        now = datetime.now().isoformat(timespec="seconds")
        if missing:
            if ctr["mode"] == "兼容":
                cur = c.execute("INSERT INTO ingress_batches(subject,payload_fields,contract_version,result,detail,created_at) VALUES (?,?,?,?,?,?)",
                                (body.subject, body.payload_fields, ctr["version"], "缓冲", "缺字段:"+ ",".join(missing), now))
                c.execute("INSERT INTO buffers(batch_id,reason) VALUES (?,?)", (cur.lastrowid, "缺字段进双写缓冲"))
                return {"result":"缓冲", "version": ctr["version"], "missing": missing, "batch_id": cur.lastrowid}
            cur = c.execute("INSERT INTO ingress_batches(subject,payload_fields,contract_version,result,detail,created_at) VALUES (?,?,?,?,?,?)",
                            (body.subject, body.payload_fields, ctr["version"], "拒收", "缺字段:"+ ",".join(missing), now))
            return {"result":"拒收", "version": ctr["version"], "missing": missing, "batch_id": cur.lastrowid}
        cur = c.execute("INSERT INTO ingress_batches(subject,payload_fields,contract_version,result,detail,created_at) VALUES (?,?,?,?,?,?)",
                        (body.subject, body.payload_fields, ctr["version"], "通过", "字段齐全", now))
        return {"result":"通过", "version": ctr["version"], "batch_id": cur.lastrowid}

@app.get("/api/ingress")
def ingress(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        return {"items":[dict(r) for r in c.execute("SELECT * FROM ingress_batches ORDER BY id DESC").fetchall()]}

@app.get("/api/buffers")
def buffers(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        rows = c.execute("""SELECT b.*, i.subject, i.payload_fields FROM buffers b JOIN ingress_batches i ON i.id=b.batch_id ORDER BY b.id DESC""").fetchall()
        return {"items":[dict(r) for r in rows]}

@app.get("/api/reconcile")
def reconcile(authorization: str | None = Header(default=None)):
    require_user(authorization)
    with connect() as c:
        total = c.execute("SELECT COUNT(*) c FROM ingress_batches").fetchone()["c"]
        passed = c.execute("SELECT COUNT(*) c FROM ingress_batches WHERE result='通过'").fetchone()["c"]
        buffered = c.execute("SELECT COUNT(*) c FROM ingress_batches WHERE result='缓冲'").fetchone()["c"]
        rejected = c.execute("SELECT COUNT(*) c FROM ingress_batches WHERE result='拒收'").fetchone()["c"]
        buf_rows = c.execute("SELECT COUNT(*) c FROM buffers").fetchone()["c"]
    return {"ingress_total": total, "passed": passed, "buffered": buffered, "rejected": rejected, "buffer_rows": buf_rows, "aligned": buffered == buf_rows}

@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")
app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
