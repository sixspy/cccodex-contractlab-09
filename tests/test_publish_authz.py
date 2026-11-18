
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from app import app, init_db

ROOT = Path(__file__).resolve().parents[1]

@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    monkeypatch.setattr("app.DB_PATH", tmp_path/"t.db"); init_db(); yield

def login(c, u, p):
    r = c.post("/api/login", json={"username": u, "password": p})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}

PUB = {"version": "v9", "subject": "订单入站", "mode": "严格",
       "required_fields": "order_id,amount,currency,channel"}

def contracts(c, h):
    return {r["version"]: r for r in c.get("/api/contracts", headers=h).json()["items"]}

def audits(c, h):
    return c.get("/api/audit", headers=h).json()["items"]

def test_readonly_direct_publish_forbidden_zero_write():
    c = TestClient(app)
    viewer = login(c, "viewer", "view123")
    before = contracts(c, viewer)
    r = c.post("/api/contracts/publish", headers=viewer, json=PUB)
    assert r.status_code == 403, r.text
    after = contracts(c, viewer)
    assert after == before, "只读令牌直发产生了写入"
    assert "v9" not in after and after["v3"]["status"] == "启用"
    assert any(a["action"].startswith("鉴权偏离") and a["actor"] == "viewer" for a in audits(c, viewer))

def test_admin_direct_publish_also_closed():
    # 乙路径：直发入口对任何角色关闭，正式指针仅审批后由服务端切换
    c = TestClient(app)
    admin = login(c, "admin", "123456")
    before = contracts(c, admin)
    r = c.post("/api/contracts/publish", headers=admin, json=PUB)
    assert r.status_code == 403, r.text
    assert contracts(c, admin) == before
    assert any(a["action"].startswith("鉴权偏离") for a in audits(c, admin))

def test_anonymous_publish_unauthorized():
    c = TestClient(app)
    assert c.post("/api/contracts/publish", json=PUB).status_code == 401
    assert c.post("/api/publish-requests", json=PUB).status_code == 401

def test_readonly_can_file_application_without_touching_versions():
    c = TestClient(app)
    viewer = login(c, "viewer", "view123")
    before = contracts(c, viewer)
    r = c.post("/api/publish-requests", headers=viewer, json=PUB)
    assert r.status_code == 200, r.text
    items = c.get("/api/publish-requests", headers=viewer).json()["items"]
    assert len(items) == 1 and items[0]["version"] == "v9" and items[0]["status"] == "待审批"
    assert items[0]["applicant"] == "viewer"
    assert contracts(c, viewer) == before, "申请单不得改动版本目录"

def test_approval_switches_pointer_server_side():
    c = TestClient(app)
    viewer = login(c, "viewer", "view123")
    admin = login(c, "admin", "123456")
    rid = c.post("/api/publish-requests", headers=viewer, json=PUB).json()["id"]
    r = c.post(f"/api/publish-requests/{rid}/approve", headers=admin)
    assert r.status_code == 200, r.text
    after = contracts(c, admin)
    assert after["v9"]["status"] == "启用" and after["v9"]["track"] == "正式"
    assert after["v3"]["status"] == "停用", "旧正式版未被服务端停用"
    req = c.get("/api/publish-requests", headers=admin).json()["items"][0]
    assert req["status"] == "已通过" and req["decided_by"] == "admin"
    assert any(a["action"] == "审批通过" for a in audits(c, admin))

def test_readonly_cannot_approve():
    c = TestClient(app)
    viewer = login(c, "viewer", "view123")
    rid = c.post("/api/publish-requests", headers=viewer, json=PUB).json()["id"]
    r = c.post(f"/api/publish-requests/{rid}/approve", headers=viewer)
    assert r.status_code == 403, r.text
    req = c.get("/api/publish-requests", headers=viewer).json()["items"][0]
    assert req["status"] == "待审批"
    assert "v9" not in contracts(c, viewer)
    assert any(a["action"].startswith("鉴权偏离") and a["actor"] == "viewer" for a in audits(c, viewer))

def test_double_approval_contention_registered():
    c = TestClient(app)
    viewer = login(c, "viewer", "view123")
    admin = login(c, "admin", "123456")
    admin2 = login(c, "admin2", "admin123")
    rid = c.post("/api/publish-requests", headers=viewer, json=PUB).json()["id"]
    first = c.post(f"/api/publish-requests/{rid}/approve", headers=admin)
    assert first.status_code == 200, first.text
    second = c.post(f"/api/publish-requests/{rid}/approve", headers=admin2)
    assert second.status_code == 409, second.text
    rows = [a for a in audits(c, admin) if a["action"] == "审批争用"]
    assert len(rows) == 1 and rows[0]["actor"] == "admin2"
    assert contracts(c, admin)["v9"]["status"] == "启用"

def test_concurrent_approval_race_queues():
    c = TestClient(app)
    viewer = login(c, "viewer", "view123")
    rid = c.post("/api/publish-requests", headers=viewer, json=PUB).json()["id"]
    heads = [login(c, "admin", "123456"), login(c, "admin2", "admin123")]
    barrier = threading.Barrier(2)
    results = []
    def race(h):
        barrier.wait()
        results.append(TestClient(app).post(f"/api/publish-requests/{rid}/approve", headers=h).status_code)
    ts = [threading.Thread(target=race, args=(h,)) for h in heads]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert sorted(results) == [200, 409], results
    assert len([a for a in audits(c, heads[0]) if a["action"] == "审批争用"]) == 1

def test_registry_document_recorded():
    doc = (ROOT/"docs"/"publish-authz-registry.md").read_text(encoding="utf-8")
    assert "乙路径" in doc and "2026-11-18" in doc
