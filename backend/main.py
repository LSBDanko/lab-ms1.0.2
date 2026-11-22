"""
实验室管理系统 · FastAPI + SQLite 后端
================================================

启动方式：
    cd backend
    pip install -r requirements.txt
    python main.py

接口文档：
    http://127.0.0.1:8000/docs

数据库：
    默认使用当前目录下的 lab.db，可以通过环境变量 LAB_DB 指定其他路径。
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
from contextlib import asynccontextmanager, contextmanager
from datetime import date, datetime
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import quote

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# 基础配置
# ---------------------------------------------------------------------------

DB_PATH = os.getenv("LAB_DB", "lab.db")
SECRET = os.getenv("LAB_SECRET", "lab-ms-dev-secret-change-me")
TOKEN_TTL_SECONDS = 8 * 60 * 60
PBKDF2_ITERATIONS = 100_000
FRONTEND_DIR = os.getenv(
    "LAB_FRONTEND_DIR",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend")),
)

INSTRUMENT_STATUS_IDLE = "空闲"
INSTRUMENT_STATUS_USING = "使用中"
INSTRUMENT_STATUS_MAINTENANCE = "维护中"

REAGENT_CATEGORIES = [
    "剧毒化学品",
    "易制毒第一类",
    "易制毒第二类",
    "易制毒第三类",
    "易制爆危险化学品",
    "危险化学品（一般）",
    "普通试剂",
]

CONSUMABLE_CATEGORIES = [
    "移液耗材",
    "防护用品",
    "过滤耗材",
    "实验耗材",
    "玻璃器皿",
    "其他耗材",
]

HAZARDOUS_REVIEW_CATEGORIES = {
    "剧毒化学品",
    "易制毒第一类",
    "易制毒第二类",
    "易制毒第三类",
    "易制爆危险化学品",
}

ATTACHMENT_ENTITY_TYPES = {"reagent", "consumable", "instrument"}
ATTACHMENT_MIME_TYPES = {
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/webp",
    "text/plain",
}
MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024


# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------

def now_iso() -> str:
    """本地时区 ISO 字符串，精确到秒。"""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def today_str() -> str:
    return date.today().isoformat()


def normalize_local_datetime(value: str, label: str) -> tuple[str, datetime]:
    raw = (value or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail=f"请填写{label}")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{label}格式不正确")
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    parsed = parsed.astimezone()
    return parsed.isoformat(timespec="seconds"), parsed


def write_audit(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_id: str,
    action: str,
    summary: str,
    user: Dict[str, str],
    before: Optional[Dict[str, Any]] = None,
    after: Optional[Dict[str, Any]] = None,
) -> None:
    conn.execute(
        """
        INSERT INTO audit_logs
            (entity_type, entity_id, action, summary, before_json, after_json,
             user, user_name, time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            entity_type,
            entity_id,
            action,
            summary,
            json.dumps(before or {}, ensure_ascii=False, default=str),
            json.dumps(after or {}, ensure_ascii=False, default=str),
            user["username"],
            user["name"],
            now_iso(),
        ),
    )


REALTIME_SUBSCRIBERS: set = set()
MAIN_EVENT_LOOP: Optional[asyncio.AbstractEventLoop] = None


def publish_realtime_event(path: str) -> None:
    if not MAIN_EVENT_LOOP:
        return
    event = {"type": "data_changed", "path": path, "time": now_iso()}
    for queue in list(REALTIME_SUBSCRIBERS):
        try:
            MAIN_EVENT_LOOP.call_soon_threadsafe(queue.put_nowait, event)
        except RuntimeError:
            pass


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """PBKDF2-HMAC-SHA256，存储格式 salt_hex:hash_hex。"""
    if salt is None:
        salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def create_token(user: Dict[str, Any]) -> str:
    """手写 JWT HS256，payload 包含 sub/name/role/exp。"""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user["username"],
        "name": user["name"],
        "role": user["role"],
        "exp": int(time.time()) + TOKEN_TTL_SECONDS,
    }
    header_part = _b64url_encode(
        json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    payload_part = _b64url_encode(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    signature = hmac.new(SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_part}.{payload_part}.{_b64url_encode(signature)}"


def parse_token(token: str) -> Optional[Dict[str, Any]]:
    """校验 JWT 签名、算法与过期时间，失败返回 None。"""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_part, payload_part, signature_part = parts
        signing_input = f"{header_part}.{payload_part}".encode("ascii")
        expected_signature = hmac.new(
            SECRET.encode("utf-8"), signing_input, hashlib.sha256
        ).digest()
        provided_signature = _b64url_decode(signature_part)
        if not hmac.compare_digest(provided_signature, expected_signature):
            return None

        header = json.loads(_b64url_decode(header_part).decode("utf-8"))
        if header.get("alg") != "HS256":
            return None

        payload = json.loads(_b64url_decode(payload_part).decode("utf-8"))
        if not isinstance(payload, dict):
            return None
        if not payload.get("sub"):
            return None

        exp = int(payload.get("exp", 0))
        if exp <= int(time.time()):
            return None
        return payload
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError, binascii.Error):
        return None


# ---------------------------------------------------------------------------
# 数据库
# ---------------------------------------------------------------------------

def connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


@contextmanager
def db_read() -> Iterator[sqlite3.Connection]:
    conn = connect_db()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def db_transaction() -> Iterator[sqlite3.Connection]:
    """显式事务；任何异常都会回滚。BEGIN IMMEDIATE 用于串行化写操作。"""
    conn = connect_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reagents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    spec TEXT NOT NULL DEFAULT '',
    stock INTEGER NOT NULL DEFAULT 0,
    unit TEXT NOT NULL DEFAULT '',
    threshold INTEGER NOT NULL DEFAULT 0,
    location TEXT NOT NULL DEFAULT '',
    supplier TEXT NOT NULL DEFAULT '',
    expiry TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '普通试剂',
    cas_no TEXT NOT NULL DEFAULT '',
    formula TEXT NOT NULL DEFAULT '',
    molecular_weight TEXT NOT NULL DEFAULT '',
    concentration TEXT NOT NULL DEFAULT '',
    purity TEXT NOT NULL DEFAULT '',
    storage_condition TEXT NOT NULL DEFAULT '',
    archived INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS instruments (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    model TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT '空闲',
    current_user TEXT,
    current_user_id TEXT,
    start_time TEXT
);

CREATE TABLE IF NOT EXISTS reagent_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reagent_id TEXT NOT NULL,
    reagent_name TEXT NOT NULL,
    type TEXT NOT NULL,
    qty INTEGER NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    user TEXT NOT NULL,
    user_name TEXT NOT NULL,
    reviewer TEXT NOT NULL DEFAULT '',
    reviewer_name TEXT NOT NULL DEFAULT '',
    time TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS instrument_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iid TEXT NOT NULL,
    instrument_name TEXT NOT NULL,
    purpose TEXT NOT NULL,
    user TEXT NOT NULL,
    user_name TEXT NOT NULL,
    "start" TEXT NOT NULL,
    "end" TEXT,
    status TEXT NOT NULL DEFAULT 'using',
    note TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS reagent_owners (
    reagent_id TEXT PRIMARY KEY,
    reagent_name TEXT NOT NULL,
    owner_name TEXT NOT NULL,
    owner_account TEXT NOT NULL DEFAULT '',
    department TEXT NOT NULL DEFAULT '',
    contact TEXT NOT NULL DEFAULT '',
    assigned_at TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS instrument_reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    iid TEXT NOT NULL,
    instrument_name TEXT NOT NULL,
    purpose TEXT NOT NULL,
    user TEXT NOT NULL,
    user_name TEXT NOT NULL,
    "start" TEXT NOT NULL,
    "end" TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'reserved',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS consumables (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    spec TEXT NOT NULL DEFAULT '',
    stock INTEGER NOT NULL DEFAULT 0,
    unit TEXT NOT NULL DEFAULT '',
    threshold INTEGER NOT NULL DEFAULT 0,
    location TEXT NOT NULL DEFAULT '',
    supplier TEXT NOT NULL DEFAULT '',
    expiry TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT '其他耗材',
    archived INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS consumable_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    consumable_id TEXT NOT NULL,
    consumable_name TEXT NOT NULL,
    type TEXT NOT NULL,
    qty INTEGER NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    user TEXT NOT NULL,
    user_name TEXT NOT NULL,
    time TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    action TEXT NOT NULL,
    summary TEXT NOT NULL,
    before_json TEXT NOT NULL DEFAULT '{}',
    after_json TEXT NOT NULL DEFAULT '{}',
    user TEXT NOT NULL,
    user_name TEXT NOT NULL,
    time TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    mime TEXT NOT NULL,
    size INTEGER NOT NULL,
    data BLOB NOT NULL,
    user TEXT NOT NULL,
    user_name TEXT NOT NULL,
    time TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reagent_logs_time
    ON reagent_logs(time DESC);
CREATE INDEX IF NOT EXISTS idx_instrument_logs_start
    ON instrument_logs("start" DESC);
CREATE INDEX IF NOT EXISTS idx_instrument_logs_iid_status
    ON instrument_logs(iid, status);
CREATE INDEX IF NOT EXISTS idx_consumable_logs_time
    ON consumable_logs(time DESC);
CREATE INDEX IF NOT EXISTS idx_reagent_owners_owner
    ON reagent_owners(owner_name);
CREATE INDEX IF NOT EXISTS idx_audit_logs_time
    ON audit_logs(time DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity
    ON audit_logs(entity_type, entity_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_reservations_start
    ON instrument_reservations("start");
CREATE INDEX IF NOT EXISTS idx_reservations_iid_status
    ON instrument_reservations(iid, status);
CREATE INDEX IF NOT EXISTS idx_attachments_entity
    ON attachments(entity_type, entity_id, time DESC);
"""


SEED_USERS = [
    ("admin", "123456", "张管理", "管理员"),
    ("liyan", "123456", "李研", "实验员"),
    ("wangbo", "123456", "王博", "实验员"),
]

SEED_REAGENTS = [
    (
        "R001", "无水乙醇", "500mL/瓶·分析纯", 12, "瓶", 5,
        "A区-01柜-2层", "国药集团", "2026-08-01",
        "危险化学品（一般）", "64-17-5", "C2H6O", "46.07", "≥99.7%", "分析纯", "阴凉通风，远离火源",
    ),
    (
        "R002", "盐酸", "500mL/瓶", 3, "瓶", 5,
        "B区-02柜-1层", "西陇科学", "2026-03-15",
        "易制毒第三类", "7647-01-0", "HCl", "36.46", "36%-38%", "分析纯", "通风、耐酸试剂柜",
    ),
    (
        "R003", "氢氧化钠", "500g/瓶", 8, "瓶", 4,
        "A区-03柜-1层", "阿拉丁", "2027-01-20",
        "危险化学品（一般）", "1310-73-2", "NaOH", "40.00", "≥96%", "分析纯", "干燥密封保存",
    ),
    (
        "R004", "硫酸铜", "250g/瓶", 2, "瓶", 3,
        "B区-01柜-2层", "麦克林", "2025-12-30",
        "普通试剂", "7758-98-7", "CuSO4·5H2O", "249.68", "≥99%", "分析纯", "阴凉干燥处密封",
    ),
    (
        "R005", "丙酮", "500mL/瓶·危化品", 6, "瓶", 3,
        "C区-01柜（危化）", "国药集团", "2026-06-10",
        "易制毒第三类", "67-64-1", "C3H6O", "58.08", "≥99.5%", "分析纯", "防爆柜、远离火源",
    ),
    (
        "R006", "甲醇（色谱级）", "4L/瓶", 5, "瓶", 2,
        "C区-02柜", "Merck", "2026-11-05",
        "危险化学品（一般）", "67-56-1", "CH4O", "32.04", "≥99.9%", "色谱级", "防爆柜、避光密封",
    ),
]

SEED_REAGENT_METADATA = {
    "R001": ("危险化学品（一般）", "64-17-5", "C2H6O", "46.07", "≥99.7%", "分析纯", "阴凉通风，远离火源"),
    "R002": ("易制毒第三类", "7647-01-0", "HCl", "36.46", "36%-38%", "分析纯", "通风、耐酸试剂柜"),
    "R003": ("危险化学品（一般）", "1310-73-2", "NaOH", "40.00", "≥96%", "分析纯", "干燥密封保存"),
    "R004": ("普通试剂", "7758-98-7", "CuSO4·5H2O", "249.68", "≥99%", "分析纯", "阴凉干燥处密封"),
    "R005": ("易制毒第三类", "67-64-1", "C3H6O", "58.08", "≥99.5%", "分析纯", "防爆柜、远离火源"),
    "R006": ("危险化学品（一般）", "67-56-1", "CH4O", "32.04", "≥99.9%", "色谱级", "防爆柜、避光密封"),
}

SEED_INSTRUMENTS = [
    ("I001", "高效液相色谱仪", "Agilent 1260", "仪器室101", "空闲"),
    ("I002", "电子分析天平", "ME204E", "天平室", "空闲"),
    ("I003", "紫外分光光度计", "UV-2600", "仪器室102", "空闲"),
    ("I004", "高速离心机", "TGL-16G", "前处理室", "维护中"),
]

SEED_CONSUMABLES = [
    ("C001", "200μL 无菌吸头", "96支/盒", 15, "盒", 5, "A区-耗材柜-1层", "爱思进", "2028-12-31", "移液耗材"),
    ("C002", "丁腈手套（M码）", "100只/盒", 8, "盒", 3, "B区-耗材柜-1层", "英科医疗", "2029-06-30", "防护用品"),
    ("C003", "0.22μm 针式滤器", "100个/盒", 4, "盒", 5, "C区-耗材柜-2层", "密理博", "2027-10-31", "过滤耗材"),
    ("C004", "15mL 离心管", "50支/包", 20, "包", 8, "A区-耗材柜-2层", "康宁", "2029-03-31", "实验耗材"),
    ("C005", "玻璃量筒 100mL", "100mL/个", 6, "个", 2, "玻璃器皿柜", "蜀牛", "", "玻璃器皿"),
    ("C006", "封口膜", "4in×125ft/卷", 2, "卷", 2, "B区-耗材柜-2层", "Parafilm", "2028-01-31", "实验耗材"),
]

SEED_OWNERS = {
    "R001": ("张管理", "admin", "分析检测部", "13800000001"),
    "R002": ("李研", "liyan", "有机合成组", "13800000002"),
    "R003": ("李研", "liyan", "有机合成组", "13800000002"),
    "R004": ("王博", "wangbo", "材料分析组", "13800000003"),
    "R005": ("张管理", "admin", "安全管理部", "13800000001"),
    "R006": ("王博", "wangbo", "色谱分析组", "13800000003"),
}


def init_db() -> None:
    conn = connect_db()
    try:
        conn.executescript(SCHEMA)

        # 兼容旧版数据库：逐列补齐试剂扩展字段。
        reagent_columns = {
            row["name"] for row in conn.execute("PRAGMA table_info(reagents)").fetchall()
        }
        metadata_columns = [
            ("category", "TEXT NOT NULL DEFAULT '普通试剂'"),
            ("cas_no", "TEXT NOT NULL DEFAULT ''"),
            ("formula", "TEXT NOT NULL DEFAULT ''"),
            ("molecular_weight", "TEXT NOT NULL DEFAULT ''"),
            ("concentration", "TEXT NOT NULL DEFAULT ''"),
            ("purity", "TEXT NOT NULL DEFAULT ''"),
            ("storage_condition", "TEXT NOT NULL DEFAULT ''"),
        ]
        metadata_added = False
        for column, definition in metadata_columns:
            if column not in reagent_columns:
                conn.execute(f'ALTER TABLE reagents ADD COLUMN "{column}" {definition}')
                metadata_added = True
        if "archived" not in reagent_columns:
            conn.execute(
                "ALTER TABLE reagents ADD COLUMN archived INTEGER NOT NULL DEFAULT 0"
            )

        consumable_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(consumables)").fetchall()
        }
        if "archived" not in consumable_columns:
            conn.execute(
                "ALTER TABLE consumables ADD COLUMN archived INTEGER NOT NULL DEFAULT 0"
            )

        reagent_log_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(reagent_logs)").fetchall()
        }
        if "reviewer" not in reagent_log_columns:
            conn.execute(
                "ALTER TABLE reagent_logs ADD COLUMN reviewer TEXT NOT NULL DEFAULT ''"
            )
        if "reviewer_name" not in reagent_log_columns:
            conn.execute(
                "ALTER TABLE reagent_logs ADD COLUMN reviewer_name TEXT NOT NULL DEFAULT ''"
            )

        conn.execute("BEGIN IMMEDIATE")
        try:
            user_count = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
            if user_count == 0:
                for username, password, name, role in SEED_USERS:
                    conn.execute(
                        "INSERT INTO users (username, password_hash, name, role) VALUES (?, ?, ?, ?)",
                        (username, hash_password(password), name, role),
                    )
                conn.executemany(
                    """
                    INSERT INTO reagents
                        (id, name, spec, stock, unit, threshold, location, supplier, expiry,
                         category, cas_no, formula, molecular_weight, concentration, purity,
                         storage_condition)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    SEED_REAGENTS,
                )
                conn.executemany(
                    """
                    INSERT INTO instruments
                        (id, name, model, location, status, current_user, current_user_id, start_time)
                    VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL)
                    """,
                    SEED_INSTRUMENTS,
                )

            # 给旧库中的 6 条演示试剂补齐参数与分类（仅在本次迁移新增列时执行）。
            if metadata_added:
                for rid, metadata in SEED_REAGENT_METADATA.items():
                    conn.execute(
                        """
                        UPDATE reagents
                        SET category = ?, cas_no = ?, formula = ?, molecular_weight = ?,
                            concentration = ?, purity = ?, storage_condition = ?
                        WHERE id = ?
                        """,
                        (*metadata, rid),
                    )

            consumable_count = conn.execute(
                "SELECT COUNT(*) AS n FROM consumables"
            ).fetchone()["n"]
            if consumable_count == 0:
                conn.executemany(
                    """
                    INSERT INTO consumables
                        (id, name, spec, stock, unit, threshold, location, supplier, expiry, category)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    SEED_CONSUMABLES,
                )

            owner_count = conn.execute(
                "SELECT COUNT(*) AS n FROM reagent_owners"
            ).fetchone()["n"]
            if owner_count == 0:
                existing_reagents = conn.execute(
                    "SELECT id FROM reagents"
                ).fetchall()
                assigned_at = now_iso()
                for row in existing_reagents:
                    owner = SEED_OWNERS.get(row["id"])
                    if not owner:
                        continue
                    owner_name, owner_account, department, contact = owner
                    conn.execute(
                        """
                        INSERT INTO reagent_owners
                            (reagent_id, reagent_name, owner_name, owner_account,
                             department, contact, assigned_at, note, updated_by)
                        SELECT id, name, ?, ?, ?, ?, ?, '初始负责人', 'admin'
                        FROM reagents WHERE id = ?
                        """,
                        (
                            owner_name,
                            owner_account,
                            department,
                            contact,
                            assigned_at,
                            row["id"],
                        ),
                    )

            initial_user = {"username": "admin", "name": "张管理", "role": "管理员"}
            for owner_row in conn.execute(
                "SELECT reagent_id, reagent_name, owner_name, owner_account, department, contact FROM reagent_owners"
            ).fetchall():
                has_history = conn.execute(
                    """
                    SELECT 1 FROM audit_logs
                    WHERE entity_type = 'reagent_owner' AND entity_id = ?
                    LIMIT 1
                    """,
                    (owner_row["reagent_id"],),
                ).fetchone()
                if has_history:
                    continue
                write_audit(
                    conn,
                    "reagent_owner",
                    owner_row["reagent_id"],
                    "assign_owner",
                    f"初始化负责人：{owner_row['reagent_name']} · {owner_row['owner_name']}",
                    initial_user,
                    before={},
                    after={
                        "ownerName": owner_row["owner_name"],
                        "ownerAccount": owner_row["owner_account"],
                        "department": owner_row["department"],
                        "contact": owner_row["contact"],
                    },
                )

            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 请求模型
# ---------------------------------------------------------------------------

class LoginIn(BaseModel):
    username: str
    password: str


class ReagentIn(BaseModel):
    name: str
    spec: str = ""
    stock: int = Field(default=0, ge=0)
    unit: str = "瓶"
    threshold: int = Field(default=0, ge=0)
    location: str = ""
    supplier: str = ""
    expiry: str = ""
    category: str = "普通试剂"
    cas_no: str = ""
    formula: str = ""
    molecular_weight: str = ""
    concentration: str = ""
    purity: str = ""
    storage_condition: str = ""
    archived: bool = False


class ReagentQtyIn(BaseModel):
    qty: int
    note: str = ""


class ReagentOutIn(ReagentQtyIn):
    reviewer_username: str = ""
    reviewer_password: str = ""


class ReagentOwnerIn(BaseModel):
    owner_name: str
    owner_account: str = ""
    department: str = ""
    contact: str = ""
    note: str = ""


class ConsumableIn(BaseModel):
    name: str
    spec: str = ""
    stock: int = Field(default=0, ge=0)
    unit: str = "件"
    threshold: int = Field(default=0, ge=0)
    location: str = ""
    supplier: str = ""
    expiry: str = ""
    category: str = "其他耗材"
    archived: bool = False


class InstrumentStartIn(BaseModel):
    purpose: str


class InstrumentEndIn(BaseModel):
    note: str = ""


class InstrumentIn(BaseModel):
    name: str
    model: str = ""
    location: str = ""
    status: str = "空闲"


class ReservationIn(BaseModel):
    iid: str
    purpose: str
    start: str
    end: str
    note: str = ""


class AttachmentIn(BaseModel):
    entity_type: str
    entity_id: str
    filename: str
    mime: str = "application/octet-stream"
    data_base64: str


# ---------------------------------------------------------------------------
# 鉴权依赖
# ---------------------------------------------------------------------------

def _unauthorized(detail: str = "未登录或登录已过期") -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def resolve_token_user(token: str) -> Optional[Dict[str, str]]:
    payload = parse_token(token)
    if not payload:
        return None
    with db_read() as conn:
        row = conn.execute(
            "SELECT username, name, role FROM users WHERE username = ?",
            (payload.get("sub"),),
        ).fetchone()
    if not row:
        return None
    return {
        "username": row["username"],
        "name": row["name"],
        "role": row["role"],
    }


def get_current_user(
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, str]:
    if not authorization:
        raise _unauthorized()

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise _unauthorized()

    user = resolve_token_user(token.strip())
    if not user:
        raise _unauthorized()
    return user


# ---------------------------------------------------------------------------
# 应用
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_: FastAPI):
    global MAIN_EVENT_LOOP
    MAIN_EVENT_LOOP = asyncio.get_running_loop()
    init_db()
    yield
    MAIN_EVENT_LOOP = None


app = FastAPI(
    title="实验室管理系统 API",
    description="试剂台账、仪器使用登记与全流程溯源。",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def realtime_write_notifier(request: Request, call_next):
    response = await call_next(request)
    if (
        request.method in {"POST", "PUT", "PATCH", "DELETE"}
        and request.url.path.startswith("/api/")
        and request.url.path not in {"/api/events", "/api/login"}
        and response.status_code < 400
    ):
        publish_realtime_event(request.url.path)
    return response


@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {"ok": True, "service": "lab-ms-api", "time": now_iso()}


if os.path.isdir(FRONTEND_DIR):
    _frontend_assets = os.path.join(FRONTEND_DIR, "assets")
    if os.path.isdir(_frontend_assets):
        app.mount("/assets", StaticFiles(directory=_frontend_assets), name="frontend-assets")

    @app.get("/", include_in_schema=False)
    def frontend_home() -> HTMLResponse:
        with open(os.path.join(FRONTEND_DIR, "index.html"), "r", encoding="utf-8") as handle:
            html = handle.read()
        marker = '<script>window.__LAB_SERVED_BY_BACKEND__ = true;</script></head>'
        html = html.replace("</head>", marker, 1)
        return HTMLResponse(
            content=html,
            headers={"Cache-Control": "no-cache"},
        )

    @app.get("/config.js", include_in_schema=False)
    def frontend_config() -> FileResponse:
        return FileResponse(
            os.path.join(FRONTEND_DIR, "config.js"),
            media_type="application/javascript",
            headers={"Cache-Control": "no-cache"},
        )


# ----------------------------- 登录与当前用户 -----------------------------

@app.post("/api/login")
def login(payload: LoginIn) -> Dict[str, Any]:
    username = payload.username.strip()
    with db_read() as conn:
        row = conn.execute(
            "SELECT username, password_hash, name, role FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if not row or not verify_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="账号或密码错误")

    user = {"username": row["username"], "name": row["name"], "role": row["role"]}
    with db_transaction() as conn:
        write_audit(
            conn,
            "user",
            user["username"],
            "login",
            f"{user['name']} 登录系统",
            user,
            after={"username": user["username"], "role": user["role"]},
        )
    return {"token": create_token(user), "user": user}


@app.get("/api/events")
async def realtime_events(token: Optional[str] = None):
    if not token or not resolve_token_user(token.strip()):
        raise _unauthorized()

    queue: asyncio.Queue = asyncio.Queue(maxsize=32)
    REALTIME_SUBSCRIBERS.add(queue)

    async def generate():
        try:
            yield "retry: 3000\n: connected\n\n"
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=18)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                else:
                    yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
        finally:
            REALTIME_SUBSCRIBERS.discard(queue)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/me")
def me(current_user: Dict[str, str] = Depends(get_current_user)) -> Dict[str, str]:
    return {
        "username": current_user["username"],
        "name": current_user["name"],
        "role": current_user["role"],
    }


# ------------------------------- 试剂台账 --------------------------------

def _reagent_to_api(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "spec": row["spec"],
        "stock": row["stock"],
        "unit": row["unit"],
        "threshold": row["threshold"],
        "location": row["location"],
        "supplier": row["supplier"],
        "expiry": row["expiry"],
        "category": row["category"],
        "casNo": row["cas_no"],
        "formula": row["formula"],
        "molecularWeight": row["molecular_weight"],
        "concentration": row["concentration"],
        "purity": row["purity"],
        "storageCondition": row["storage_condition"],
        "ownerName": row["owner_name"] or "",
        "ownerAccount": row["owner_account"] or "",
        "ownerDepartment": row["owner_department"] or "",
        "ownerContact": row["owner_contact"] or "",
        "ownerAssignedAt": row["owner_assigned_at"],
        "ownerNote": row["owner_note"] or "",
        "archived": bool(row["archived"]),
    }


@app.get("/api/reagents")
def list_reagents(
    _: Dict[str, str] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    with db_read() as conn:
        rows = conn.execute(
            """
            SELECT r.id, r.name, r.spec, r.stock, r.unit, r.threshold,
                   r.location, r.supplier, r.expiry, r.category, r.cas_no,
                   r.formula, r.molecular_weight, r.concentration, r.purity,
                   r.storage_condition, r.archived,
                   o.owner_name, o.owner_account, o.department AS owner_department,
                   o.contact AS owner_contact, o.assigned_at AS owner_assigned_at,
                   o.note AS owner_note
            FROM reagents r
            LEFT JOIN reagent_owners o ON o.reagent_id = r.id
            ORDER BY r.id ASC
            """
        ).fetchall()
    return [_reagent_to_api(row) for row in rows]


@app.post("/api/reagents")
def create_reagent(
    payload: ReagentIn,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, str]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="试剂名称不能为空")
    if payload.stock < 0:
        raise HTTPException(status_code=400, detail="初始库存不能小于 0")
    if payload.threshold < 0:
        raise HTTPException(status_code=400, detail="预警阈值不能小于 0")
    category = payload.category.strip() or "普通试剂"
    if category not in REAGENT_CATEGORIES:
        raise HTTPException(status_code=400, detail="试剂分类不合法")

    with db_transaction() as conn:
        existing_ids = conn.execute("SELECT id FROM reagents").fetchall()
        max_number = 0
        for row in existing_ids:
            match = re.fullmatch(r"R(\d+)", str(row["id"]))
            if match:
                max_number = max(max_number, int(match.group(1)))
        new_id = f"R{max_number + 1:03d}"

        conn.execute(
            """
            INSERT INTO reagents
                (id, name, spec, stock, unit, threshold, location, supplier, expiry,
                 category, cas_no, formula, molecular_weight, concentration, purity,
                 storage_condition)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id,
                name,
                payload.spec.strip(),
                payload.stock,
                payload.unit.strip(),
                payload.threshold,
                payload.location.strip(),
                payload.supplier.strip(),
                payload.expiry.strip(),
                category,
                payload.cas_no.strip(),
                payload.formula.strip(),
                payload.molecular_weight.strip(),
                payload.concentration.strip(),
                payload.purity.strip(),
                payload.storage_condition.strip(),
            ),
        )

        if payload.stock > 0:
            conn.execute(
                """
                INSERT INTO reagent_logs
                    (reagent_id, reagent_name, type, qty, note, user, user_name, time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id,
                    name,
                    "入库",
                    payload.stock,
                    "新增试剂初始入库",
                    current_user["username"],
                    current_user["name"],
                    now_iso(),
                ),
            )

        write_audit(
            conn,
            "reagent",
            new_id,
            "create",
            f"新增试剂 {name}",
            current_user,
            after={
                "name": name,
                "category": category,
                "stock": payload.stock,
                "unit": payload.unit.strip(),
            },
        )

    return {"id": new_id}


@app.put("/api/reagents/{rid}")
def update_reagent(
    rid: str,
    payload: ReagentIn,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, bool]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="试剂名称不能为空")
    category = payload.category.strip() or "普通试剂"
    if category not in REAGENT_CATEGORIES:
        raise HTTPException(status_code=400, detail="试剂分类不合法")

    with db_transaction() as conn:
        row = conn.execute("SELECT * FROM reagents WHERE id = ?", (rid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="试剂不存在")

        before = dict(row)
        if payload.stock != before["stock"]:
            raise HTTPException(
                status_code=400,
                detail="库存数量请通过入库或领用操作调整",
            )
        conn.execute(
            """
            UPDATE reagents
            SET name = ?, spec = ?, stock = ?, unit = ?, threshold = ?,
                location = ?, supplier = ?, expiry = ?, category = ?, cas_no = ?,
                formula = ?, molecular_weight = ?, concentration = ?, purity = ?,
                storage_condition = ?, archived = ?
            WHERE id = ?
            """,
            (
                name,
                payload.spec.strip(),
                payload.stock,
                payload.unit.strip(),
                payload.threshold,
                payload.location.strip(),
                payload.supplier.strip(),
                payload.expiry.strip(),
                category,
                payload.cas_no.strip(),
                payload.formula.strip(),
                payload.molecular_weight.strip(),
                payload.concentration.strip(),
                payload.purity.strip(),
                payload.storage_condition.strip(),
                1 if payload.archived else 0,
                rid,
            ),
        )
        conn.execute(
            "UPDATE reagent_owners SET reagent_name = ? WHERE reagent_id = ?",
            (name, rid),
        )
        action = "archive" if payload.archived and not before["archived"] else (
            "restore" if before["archived"] and not payload.archived else "update"
        )
        action_text = {"archive": "归档", "restore": "恢复", "update": "更新"}[action]
        write_audit(
            conn,
            "reagent",
            rid,
            action,
            f"{action_text}试剂 {name}",
            current_user,
            before={
                "name": before["name"],
                "category": before["category"],
                "stock": before["stock"],
                "location": before["location"],
                "archived": before["archived"],
            },
            after={
                "name": name,
                "category": category,
                "stock": payload.stock,
                "location": payload.location.strip(),
                "archived": 1 if payload.archived else 0,
            },
        )
    return {"ok": True}


@app.post("/api/reagents/{rid}/in")
def reagent_in(
    rid: str,
    payload: ReagentQtyIn,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, bool]:
    if payload.qty <= 0:
        raise HTTPException(status_code=400, detail="入库数量必须大于 0")
    note = (payload.note or "").strip()

    with db_transaction() as conn:
        reagent = conn.execute(
            "SELECT id, name, archived FROM reagents WHERE id = ?", (rid,)
        ).fetchone()
        if not reagent:
            raise HTTPException(status_code=404, detail="试剂不存在")
        if reagent["archived"]:
            raise HTTPException(status_code=400, detail="试剂已归档，请先恢复档案")

        conn.execute(
            "UPDATE reagents SET stock = stock + ? WHERE id = ?",
            (payload.qty, rid),
        )
        conn.execute(
            """
            INSERT INTO reagent_logs
                (reagent_id, reagent_name, type, qty, note, user, user_name, time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rid,
                reagent["name"],
                "入库",
                payload.qty,
                note,
                current_user["username"],
                current_user["name"],
                now_iso(),
            ),
        )
    return {"ok": True}


@app.post("/api/reagents/{rid}/out")
def reagent_out(
    rid: str,
    payload: ReagentOutIn,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, Any]:
    if payload.qty <= 0:
        raise HTTPException(status_code=400, detail="领用数量必须大于 0")
    note = (payload.note or "").strip()
    if not note:
        raise HTTPException(status_code=400, detail="请填写领用用途")

    with db_transaction() as conn:
        reagent = conn.execute(
            "SELECT id, name, category, archived FROM reagents WHERE id = ?", (rid,)
        ).fetchone()
        if not reagent:
            raise HTTPException(status_code=404, detail="试剂不存在")
        if reagent["archived"]:
            raise HTTPException(status_code=400, detail="试剂已归档，请先恢复档案")

        needs_review = reagent["category"] in HAZARDOUS_REVIEW_CATEGORIES
        reviewer_username = ""
        reviewer_name = ""
        if needs_review:
            reviewer_username = (payload.reviewer_username or "").strip()
            reviewer_password = payload.reviewer_password or ""
            if not reviewer_username or not reviewer_password:
                raise HTTPException(
                    status_code=400,
                    detail="该试剂属于管控化学品，领用需要第二位用户复核",
                )
            if reviewer_username == current_user["username"]:
                raise HTTPException(status_code=400, detail="复核人不能与领用人相同")
            reviewer = conn.execute(
                "SELECT username, name, password_hash FROM users WHERE username = ?",
                (reviewer_username,),
            ).fetchone()
            if not reviewer or not verify_password(reviewer_password, reviewer["password_hash"]):
                raise HTTPException(status_code=400, detail="复核人账号或密码错误")
            reviewer_name = reviewer["name"]

        # 条件 UPDATE 保证并发领用不会把库存扣成负数。
        cursor = conn.execute(
            "UPDATE reagents SET stock = stock - ? WHERE id = ? AND stock >= ?",
            (payload.qty, rid, payload.qty),
        )
        if cursor.rowcount == 0:
            stock_row = conn.execute(
                "SELECT stock FROM reagents WHERE id = ?", (rid,)
            ).fetchone()
            if not stock_row:
                raise HTTPException(status_code=404, detail="试剂不存在")
            raise HTTPException(
                status_code=400,
                detail=f"库存不足，当前仅剩 {stock_row['stock']}",
            )

        conn.execute(
            """
            INSERT INTO reagent_logs
                (reagent_id, reagent_name, type, qty, note, user, user_name,
                 reviewer, reviewer_name, time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                rid,
                reagent["name"],
                "领用",
                payload.qty,
                note,
                current_user["username"],
                current_user["name"],
                reviewer_username,
                reviewer_name,
                now_iso(),
            ),
        )
        if needs_review:
            write_audit(
                conn,
                "reagent",
                rid,
                "review_out",
                f"双人复核领用 {reagent['name']} · 复核人 {reviewer_name}",
                current_user,
                after={
                    "qty": payload.qty,
                    "reviewer": reviewer_username,
                    "reviewerName": reviewer_name,
                },
            )
    return {"ok": True, "reviewed": needs_review}


# ----------------------------- 试剂负责人 --------------------------------

@app.get("/api/reagent-owners")
def list_reagent_owners(
    _: Dict[str, str] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    with db_read() as conn:
        rows = conn.execute(
            """
            SELECT o.reagent_id, o.reagent_name, o.owner_name, o.owner_account,
                   o.department, o.contact, o.assigned_at, o.note, o.updated_by,
                   r.category, r.stock, r.unit, r.location, r.archived
            FROM reagent_owners o
            LEFT JOIN reagents r ON r.id = o.reagent_id
            ORDER BY o.reagent_id ASC
            """
        ).fetchall()
    return [
        {
            "reagentId": row["reagent_id"],
            "reagentName": row["reagent_name"],
            "category": row["category"] or "",
            "stock": row["stock"],
            "unit": row["unit"] or "",
            "location": row["location"] or "",
            "ownerName": row["owner_name"],
            "ownerAccount": row["owner_account"],
            "department": row["department"],
            "contact": row["contact"],
            "assignedAt": row["assigned_at"],
            "note": row["note"],
            "updatedBy": row["updated_by"],
            "archived": bool(row["archived"]),
        }
        for row in rows
    ]


@app.post("/api/reagent-owners/{rid}")
def save_reagent_owner(
    rid: str,
    payload: ReagentOwnerIn,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, bool]:
    owner_name = payload.owner_name.strip()
    if not owner_name:
        raise HTTPException(status_code=400, detail="请填写负责人姓名")

    with db_transaction() as conn:
        reagent = conn.execute(
            "SELECT id, name, archived FROM reagents WHERE id = ?", (rid,)
        ).fetchone()
        if not reagent:
            raise HTTPException(status_code=404, detail="试剂不存在")
        if reagent["archived"]:
            raise HTTPException(status_code=400, detail="试剂已归档，请先恢复档案")

        previous_owner = conn.execute(
            "SELECT * FROM reagent_owners WHERE reagent_id = ?", (rid,)
        ).fetchone()

        assigned_at = now_iso()
        conn.execute(
            """
            INSERT INTO reagent_owners
                (reagent_id, reagent_name, owner_name, owner_account,
                 department, contact, assigned_at, note, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(reagent_id) DO UPDATE SET
                reagent_name = excluded.reagent_name,
                owner_name = excluded.owner_name,
                owner_account = excluded.owner_account,
                department = excluded.department,
                contact = excluded.contact,
                assigned_at = excluded.assigned_at,
                note = excluded.note,
                updated_by = excluded.updated_by
            """,
            (
                rid,
                reagent["name"],
                owner_name,
                payload.owner_account.strip(),
                payload.department.strip(),
                payload.contact.strip(),
                assigned_at,
                payload.note.strip(),
                current_user["username"],
            ),
        )
        after_owner = {
            "ownerName": owner_name,
            "ownerAccount": payload.owner_account.strip(),
            "department": payload.department.strip(),
            "contact": payload.contact.strip(),
            "note": payload.note.strip(),
        }
        if previous_owner:
            before_owner = {
                "ownerName": previous_owner["owner_name"],
                "ownerAccount": previous_owner["owner_account"],
                "department": previous_owner["department"],
                "contact": previous_owner["contact"],
                "note": previous_owner["note"],
            }
            summary = f"变更 {reagent['name']} 负责人：{previous_owner['owner_name']} → {owner_name}"
        else:
            before_owner = {}
            summary = f"指定 {reagent['name']} 负责人：{owner_name}"
        write_audit(
            conn,
            "reagent_owner",
            rid,
            "assign_owner",
            summary,
            current_user,
            before=before_owner,
            after=after_owner,
        )
    return {"ok": True}


@app.get("/api/reagent-owners/{rid}/history")
def reagent_owner_history(
    rid: str,
    _: Dict[str, str] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    with db_read() as conn:
        rows = conn.execute(
            """
            SELECT id, action, summary, before_json, after_json, user, user_name, time
            FROM audit_logs
            WHERE entity_type = 'reagent_owner' AND entity_id = ?
            ORDER BY id DESC
            LIMIT 100
            """,
            (rid,),
        ).fetchall()
    return [
        {
            "id": row["id"],
            "action": row["action"],
            "summary": row["summary"],
            "before": json.loads(row["before_json"]),
            "after": json.loads(row["after_json"]),
            "user": row["user"],
            "userName": row["user_name"],
            "time": row["time"],
        }
        for row in rows
    ]


# ------------------------------- 耗材台账 --------------------------------

def _consumable_to_api(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "spec": row["spec"],
        "stock": row["stock"],
        "unit": row["unit"],
        "threshold": row["threshold"],
        "location": row["location"],
        "supplier": row["supplier"],
        "expiry": row["expiry"],
        "category": row["category"],
        "archived": bool(row["archived"]),
    }


@app.get("/api/consumables")
def list_consumables(
    _: Dict[str, str] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    with db_read() as conn:
        rows = conn.execute(
            """
            SELECT id, name, spec, stock, unit, threshold, location,
                   supplier, expiry, category, archived
            FROM consumables
            ORDER BY id ASC
            """
        ).fetchall()
    return [_consumable_to_api(row) for row in rows]


@app.post("/api/consumables")
def create_consumable(
    payload: ConsumableIn,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, str]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="耗材名称不能为空")
    category = payload.category.strip() or "其他耗材"
    if category not in CONSUMABLE_CATEGORIES:
        raise HTTPException(status_code=400, detail="耗材分类不合法")

    with db_transaction() as conn:
        existing_ids = conn.execute("SELECT id FROM consumables").fetchall()
        max_number = 0
        for row in existing_ids:
            match = re.fullmatch(r"C(\d+)", str(row["id"]))
            if match:
                max_number = max(max_number, int(match.group(1)))
        new_id = f"C{max_number + 1:03d}"

        conn.execute(
            """
            INSERT INTO consumables
                (id, name, spec, stock, unit, threshold, location, supplier, expiry, category)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id,
                name,
                payload.spec.strip(),
                payload.stock,
                payload.unit.strip(),
                payload.threshold,
                payload.location.strip(),
                payload.supplier.strip(),
                payload.expiry.strip(),
                category,
            ),
        )

        if payload.stock > 0:
            conn.execute(
                """
                INSERT INTO consumable_logs
                    (consumable_id, consumable_name, type, qty, note, user, user_name, time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id,
                    name,
                    "入库",
                    payload.stock,
                    "新增耗材初始入库",
                    current_user["username"],
                    current_user["name"],
                    now_iso(),
                ),
            )
        write_audit(
            conn,
            "consumable",
            new_id,
            "create",
            f"新增耗材 {name}",
            current_user,
            after={"name": name, "category": category, "stock": payload.stock},
        )
    return {"id": new_id}


@app.put("/api/consumables/{cid}")
def update_consumable(
    cid: str,
    payload: ConsumableIn,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, bool]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="耗材名称不能为空")
    category = payload.category.strip() or "其他耗材"
    if category not in CONSUMABLE_CATEGORIES:
        raise HTTPException(status_code=400, detail="耗材分类不合法")

    with db_transaction() as conn:
        row = conn.execute("SELECT * FROM consumables WHERE id = ?", (cid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="耗材不存在")
        before = dict(row)
        if payload.stock != before["stock"]:
            raise HTTPException(
                status_code=400,
                detail="库存数量请通过入库或领用操作调整",
            )
        conn.execute(
            """
            UPDATE consumables
            SET name = ?, spec = ?, stock = ?, unit = ?, threshold = ?,
                location = ?, supplier = ?, expiry = ?, category = ?, archived = ?
            WHERE id = ?
            """,
            (
                name,
                payload.spec.strip(),
                payload.stock,
                payload.unit.strip(),
                payload.threshold,
                payload.location.strip(),
                payload.supplier.strip(),
                payload.expiry.strip(),
                category,
                1 if payload.archived else 0,
                cid,
            ),
        )
        action = "archive" if payload.archived and not before["archived"] else (
            "restore" if before["archived"] and not payload.archived else "update"
        )
        action_text = {"archive": "归档", "restore": "恢复", "update": "更新"}[action]
        write_audit(
            conn,
            "consumable",
            cid,
            action,
            f"{action_text}耗材 {name}",
            current_user,
            before={
                "name": before["name"],
                "category": before["category"],
                "stock": before["stock"],
                "location": before["location"],
                "archived": before["archived"],
            },
            after={
                "name": name,
                "category": category,
                "stock": payload.stock,
                "location": payload.location.strip(),
                "archived": 1 if payload.archived else 0,
            },
        )
    return {"ok": True}


@app.post("/api/consumables/{cid}/in")
def consumable_in(
    cid: str,
    payload: ReagentQtyIn,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, bool]:
    if payload.qty <= 0:
        raise HTTPException(status_code=400, detail="入库数量必须大于 0")
    note = (payload.note or "").strip()

    with db_transaction() as conn:
        consumable = conn.execute(
            "SELECT id, name, archived FROM consumables WHERE id = ?", (cid,)
        ).fetchone()
        if not consumable:
            raise HTTPException(status_code=404, detail="耗材不存在")
        if consumable["archived"]:
            raise HTTPException(status_code=400, detail="耗材已归档，请先恢复档案")

        conn.execute(
            "UPDATE consumables SET stock = stock + ? WHERE id = ?",
            (payload.qty, cid),
        )
        conn.execute(
            """
            INSERT INTO consumable_logs
                (consumable_id, consumable_name, type, qty, note, user, user_name, time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cid,
                consumable["name"],
                "入库",
                payload.qty,
                note,
                current_user["username"],
                current_user["name"],
                now_iso(),
            ),
        )
    return {"ok": True}


@app.post("/api/consumables/{cid}/out")
def consumable_out(
    cid: str,
    payload: ReagentQtyIn,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, bool]:
    if payload.qty <= 0:
        raise HTTPException(status_code=400, detail="领用数量必须大于 0")
    note = (payload.note or "").strip()
    if not note:
        raise HTTPException(status_code=400, detail="请填写领用用途")

    with db_transaction() as conn:
        consumable = conn.execute(
            "SELECT id, name, archived FROM consumables WHERE id = ?", (cid,)
        ).fetchone()
        if not consumable:
            raise HTTPException(status_code=404, detail="耗材不存在")
        if consumable["archived"]:
            raise HTTPException(status_code=400, detail="耗材已归档，请先恢复档案")

        cursor = conn.execute(
            "UPDATE consumables SET stock = stock - ? WHERE id = ? AND stock >= ?",
            (payload.qty, cid, payload.qty),
        )
        if cursor.rowcount == 0:
            stock_row = conn.execute(
                "SELECT stock FROM consumables WHERE id = ?", (cid,)
            ).fetchone()
            if not stock_row:
                raise HTTPException(status_code=404, detail="耗材不存在")
            raise HTTPException(
                status_code=400,
                detail=f"库存不足，当前仅剩 {stock_row['stock']}",
            )

        conn.execute(
            """
            INSERT INTO consumable_logs
                (consumable_id, consumable_name, type, qty, note, user, user_name, time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cid,
                consumable["name"],
                "领用",
                payload.qty,
                note,
                current_user["username"],
                current_user["name"],
                now_iso(),
            ),
        )
    return {"ok": True}


# ------------------------------- 仪器使用 --------------------------------

def _instrument_to_api(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "model": row["model"],
        "location": row["location"],
        "status": row["status"],
        "currentUser": row["current_user"],
        "currentUserId": row["current_user_id"],
        "startTime": row["start_time"],
    }


@app.get("/api/instruments")
def list_instruments(
    _: Dict[str, str] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    with db_read() as conn:
        rows = conn.execute(
            """
            SELECT id, name, model, location, status,
                   current_user, current_user_id, start_time
            FROM instruments
            ORDER BY id ASC
            """
        ).fetchall()
    return [_instrument_to_api(row) for row in rows]


@app.post("/api/instruments")
def create_instrument(
    payload: InstrumentIn,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, str]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="仪器名称不能为空")
    status = payload.status.strip() or INSTRUMENT_STATUS_IDLE
    if status not in (INSTRUMENT_STATUS_IDLE, INSTRUMENT_STATUS_MAINTENANCE):
        raise HTTPException(status_code=400, detail="新建仪器状态只能是空闲或维护中")

    with db_transaction() as conn:
        existing_ids = conn.execute("SELECT id FROM instruments").fetchall()
        max_number = 0
        for row in existing_ids:
            match = re.fullmatch(r"I(\d+)", str(row["id"]))
            if match:
                max_number = max(max_number, int(match.group(1)))
        new_id = f"I{max_number + 1:03d}"
        conn.execute(
            """
            INSERT INTO instruments
                (id, name, model, location, status, current_user, current_user_id, start_time)
            VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL)
            """,
            (
                new_id,
                name,
                payload.model.strip(),
                payload.location.strip(),
                status,
            ),
        )
        write_audit(
            conn,
            "instrument",
            new_id,
            "create",
            f"新增仪器 {name}",
            current_user,
            after={
                "name": name,
                "model": payload.model.strip(),
                "location": payload.location.strip(),
                "status": status,
            },
        )
    return {"id": new_id}


@app.put("/api/instruments/{iid}")
def update_instrument(
    iid: str,
    payload: InstrumentIn,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, bool]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="仪器名称不能为空")

    with db_transaction() as conn:
        instrument = conn.execute(
            "SELECT id, name, model, location, status FROM instruments WHERE id = ?",
            (iid,),
        ).fetchone()
        if not instrument:
            raise HTTPException(status_code=404, detail="仪器不存在")

        current_status = instrument["status"]
        requested_status = payload.status.strip() or current_status
        if requested_status not in (
            INSTRUMENT_STATUS_IDLE,
            INSTRUMENT_STATUS_USING,
            INSTRUMENT_STATUS_MAINTENANCE,
        ):
            raise HTTPException(status_code=400, detail="仪器状态不合法")
        if current_status == INSTRUMENT_STATUS_USING and requested_status != INSTRUMENT_STATUS_USING:
            raise HTTPException(
                status_code=400,
                detail="使用中的仪器请先结束使用，再修改状态",
            )
        if current_status != INSTRUMENT_STATUS_USING and requested_status == INSTRUMENT_STATUS_USING:
            raise HTTPException(
                status_code=400,
                detail="请通过“开始使用”登记仪器使用状态",
            )

        conn.execute(
            """
            UPDATE instruments
            SET name = ?, model = ?, location = ?, status = ?
            WHERE id = ?
            """,
            (
                name,
                payload.model.strip(),
                payload.location.strip(),
                requested_status,
                iid,
            ),
        )
        changed = current_status != requested_status
        write_audit(
            conn,
            "instrument",
            iid,
            "status_change" if changed else "update",
            f"更新仪器 {name}" + (f"（{current_status} → {requested_status}）" if changed else ""),
            current_user,
            before={
                "name": instrument["name"],
                "model": instrument["model"],
                "location": instrument["location"],
                "status": current_status,
            },
            after={
                "name": name,
                "model": payload.model.strip(),
                "location": payload.location.strip(),
                "status": requested_status,
            },
        )
    return {"ok": True}


# ----------------------------- 仪器预约 ----------------------------------

def _reservation_to_api(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "iid": row["iid"],
        "instrumentName": row["instrument_name"],
        "purpose": row["purpose"],
        "user": row["user"],
        "userName": row["user_name"],
        "start": row["start"],
        "end": row["end"],
        "status": row["status"],
        "note": row["note"],
        "createdAt": row["created_at"],
    }


@app.get("/api/reservations")
def list_reservations(
    _: Dict[str, str] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    with db_read() as conn:
        rows = conn.execute(
            """
            SELECT id, iid, instrument_name, purpose, user, user_name,
                   "start", "end", status, note, created_at
            FROM instrument_reservations
            WHERE status = 'reserved'
            ORDER BY "start" ASC
            LIMIT 200
            """
        ).fetchall()
    return [_reservation_to_api(row) for row in rows]


@app.post("/api/reservations")
def create_reservation(
    payload: ReservationIn,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, Any]:
    purpose = payload.purpose.strip()
    if not purpose:
        raise HTTPException(status_code=400, detail="请填写预约用途")
    start_iso, start_dt = normalize_local_datetime(payload.start, "开始时间")
    end_iso, end_dt = normalize_local_datetime(payload.end, "结束时间")
    if start_dt >= end_dt:
        raise HTTPException(status_code=400, detail="结束时间必须晚于开始时间")
    if end_dt <= datetime.now().astimezone():
        raise HTTPException(status_code=400, detail="预约时间已过去，请选择新的时段")

    with db_transaction() as conn:
        instrument = conn.execute(
            "SELECT id, name, status FROM instruments WHERE id = ?",
            (payload.iid.strip(),),
        ).fetchone()
        if not instrument:
            raise HTTPException(status_code=404, detail="仪器不存在")
        if instrument["status"] == INSTRUMENT_STATUS_MAINTENANCE:
            raise HTTPException(status_code=400, detail="仪器维护中，暂不可预约")
        conflict = conn.execute(
            """
            SELECT id, user_name, "start", "end" FROM instrument_reservations
            WHERE iid = ? AND status = 'reserved'
              AND "start" < ? AND "end" > ?
            LIMIT 1
            """,
            (payload.iid.strip(), end_iso, start_iso),
        ).fetchone()
        if conflict:
            raise HTTPException(
                status_code=409,
                detail=f"该时段已被 {conflict['user_name']} 预约",
            )
        cursor = conn.execute(
            """
            INSERT INTO instrument_reservations
                (iid, instrument_name, purpose, user, user_name,
                 "start", "end", status, note, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?)
            """,
            (
                instrument["id"],
                instrument["name"],
                purpose,
                current_user["username"],
                current_user["name"],
                start_iso,
                end_iso,
                payload.note.strip(),
                now_iso(),
            ),
        )
        reservation_id = cursor.lastrowid
        write_audit(
            conn,
            "reservation",
            str(reservation_id),
            "create",
            f"预约仪器 {instrument['name']}（{start_iso[11:16]}–{end_iso[11:16]}）",
            current_user,
            after={
                "iid": instrument["id"],
                "purpose": purpose,
                "start": start_iso,
                "end": end_iso,
            },
        )
    return {"id": reservation_id}


@app.post("/api/reservations/{reservation_id}/cancel")
def cancel_reservation(
    reservation_id: int,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, bool]:
    with db_transaction() as conn:
        row = conn.execute(
            "SELECT * FROM instrument_reservations WHERE id = ?",
            (reservation_id,),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="预约不存在")
        if row["status"] != "reserved":
            raise HTTPException(status_code=400, detail="该预约已取消")
        if row["user"] != current_user["username"] and current_user["role"] != "管理员":
            raise HTTPException(status_code=403, detail="只能取消自己的预约")
        conn.execute(
            "UPDATE instrument_reservations SET status = 'cancelled' WHERE id = ?",
            (reservation_id,),
        )
        write_audit(
            conn,
            "reservation",
            str(reservation_id),
            "cancel",
            f"取消仪器预约 {row['instrument_name']}",
            current_user,
            before={"start": row["start"], "end": row["end"]},
            after={"status": "cancelled"},
        )
    return {"ok": True}


@app.post("/api/instruments/{iid}/start")
def start_instrument(
    iid: str,
    payload: InstrumentStartIn,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, bool]:
    purpose = payload.purpose.strip()
    if not purpose:
        raise HTTPException(status_code=400, detail="请填写用途/实验项目")

    with db_transaction() as conn:
        instrument = conn.execute(
            "SELECT id, name, status FROM instruments WHERE id = ?", (iid,)
        ).fetchone()
        if not instrument:
            raise HTTPException(status_code=404, detail="仪器不存在")
        if instrument["status"] == INSTRUMENT_STATUS_USING:
            raise HTTPException(status_code=400, detail="仪器正在使用中")
        if instrument["status"] == INSTRUMENT_STATUS_MAINTENANCE:
            raise HTTPException(status_code=400, detail="仪器维护中，暂不可用")

        start_time = now_iso()
        cursor = conn.execute(
            """
            UPDATE instruments
            SET status = ?, current_user = ?, current_user_id = ?, start_time = ?
            WHERE id = ? AND status = ?
            """,
            (
                INSTRUMENT_STATUS_USING,
                current_user["name"],
                current_user["username"],
                start_time,
                iid,
                INSTRUMENT_STATUS_IDLE,
            ),
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=400, detail="仪器状态已变化，请刷新后重试")

        conn.execute(
            """
            INSERT INTO instrument_logs
                (iid, instrument_name, purpose, user, user_name, "start", "end", status, note)
            VALUES (?, ?, ?, ?, ?, ?, NULL, 'using', '')
            """,
            (
                iid,
                instrument["name"],
                purpose,
                current_user["username"],
                current_user["name"],
                start_time,
            ),
        )
    return {"ok": True}


@app.post("/api/instruments/{iid}/end")
def end_instrument(
    iid: str,
    payload: InstrumentEndIn,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, bool]:
    with db_transaction() as conn:
        instrument = conn.execute(
            """
            SELECT id, name, status, current_user, current_user_id, start_time
            FROM instruments WHERE id = ?
            """,
            (iid,),
        ).fetchone()
        if not instrument:
            raise HTTPException(status_code=404, detail="仪器不存在")
        if instrument["status"] != INSTRUMENT_STATUS_USING:
            raise HTTPException(status_code=400, detail="仪器当前不在使用中")

        if (
            instrument["current_user_id"] != current_user["username"]
            and current_user["role"] != "管理员"
        ):
            raise HTTPException(status_code=403, detail="只能结束自己登记的使用")

        end_time = now_iso()
        conn.execute(
            """
            UPDATE instruments
            SET status = ?, current_user = NULL, current_user_id = NULL, start_time = NULL
            WHERE id = ? AND status = ?
            """,
            (INSTRUMENT_STATUS_IDLE, iid, INSTRUMENT_STATUS_USING),
        )

        log = conn.execute(
            """
            SELECT id FROM instrument_logs
            WHERE iid = ? AND status = 'using'
            ORDER BY id DESC LIMIT 1
            """,
            (iid,),
        ).fetchone()
        if log:
            conn.execute(
                """
                UPDATE instrument_logs
                SET "end" = ?, status = 'done', note = ?
                WHERE id = ?
                """,
                (end_time, (payload.note or "").strip(), log["id"]),
            )
    return {"ok": True}


# ------------------------------- 溯源日志 --------------------------------

@app.get("/api/logs")
def list_logs(
    _: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, List[Dict[str, Any]]]:
    with db_read() as conn:
        reagent_rows = conn.execute(
            """
            SELECT reagent_id, reagent_name, type, qty, note, user, user_name,
                   reviewer, reviewer_name, time
            FROM reagent_logs
            ORDER BY time DESC, id DESC
            LIMIT 200
            """
        ).fetchall()
        instrument_rows = conn.execute(
            """
            SELECT iid, instrument_name, purpose, user, user_name,
                   "start", "end", status, note
            FROM instrument_logs
            ORDER BY "start" DESC, id DESC
            LIMIT 200
            """
        ).fetchall()
        consumable_rows = conn.execute(
            """
            SELECT consumable_id, consumable_name, type, qty, note, user, user_name, time
            FROM consumable_logs
            ORDER BY time DESC, id DESC
            LIMIT 200
            """
        ).fetchall()

    reagent_logs = [
        {
            "reagentId": row["reagent_id"],
            "reagentName": row["reagent_name"],
            "type": row["type"],
            "qty": row["qty"],
            "note": row["note"],
            "user": row["user"],
            "userName": row["user_name"],
            "reviewer": row["reviewer"],
            "reviewerName": row["reviewer_name"],
            "time": row["time"],
        }
        for row in reagent_rows
    ]

    instrument_logs = [
        {
            "iid": row["iid"],
            "instrumentName": row["instrument_name"],
            "purpose": row["purpose"],
            "user": row["user"],
            "userName": row["user_name"],
            "start": row["start"],
            "end": row["end"],
            "status": row["status"],
            "note": row["note"],
        }
        for row in instrument_rows
    ]

    consumable_logs = [
        {
            "consumableId": row["consumable_id"],
            "consumableName": row["consumable_name"],
            "type": row["type"],
            "qty": row["qty"],
            "note": row["note"],
            "user": row["user"],
            "userName": row["user_name"],
            "time": row["time"],
        }
        for row in consumable_rows
    ]

    return {
        "reagentLogs": reagent_logs,
        "instrumentLogs": instrument_logs,
        "consumableLogs": consumable_logs,
    }


# --------------------------------- 审计 ----------------------------------

@app.get("/api/audit-logs")
def list_audit_logs(
    entity_type: Optional[str] = None,
    limit: int = 250,
    _: Dict[str, str] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    capped = max(1, min(int(limit), 500))
    with db_read() as conn:
        if entity_type:
            rows = conn.execute(
                """
                SELECT id, entity_type, entity_id, action, summary, before_json,
                       after_json, user, user_name, time
                FROM audit_logs
                WHERE entity_type = ?
                ORDER BY id DESC LIMIT ?
                """,
                (entity_type, capped),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, entity_type, entity_id, action, summary, before_json,
                       after_json, user, user_name, time
                FROM audit_logs
                ORDER BY id DESC LIMIT ?
                """,
                (capped,),
            ).fetchall()

    def parse_json(value: str) -> Dict[str, Any]:
        try:
            parsed = json.loads(value or "{}")
            return parsed if isinstance(parsed, dict) else {}
        except (TypeError, json.JSONDecodeError):
            return {}

    return [
        {
            "id": row["id"],
            "entityType": row["entity_type"],
            "entityId": row["entity_id"],
            "action": row["action"],
            "summary": row["summary"],
            "before": parse_json(row["before_json"]),
            "after": parse_json(row["after_json"]),
            "user": row["user"],
            "userName": row["user_name"],
            "time": row["time"],
        }
        for row in rows
    ]


# ------------------------------- 附件 ------------------------------------

def _attachment_entity_name(conn: sqlite3.Connection, entity_type: str, entity_id: str) -> Optional[str]:
    table = {
        "reagent": "reagents",
        "consumable": "consumables",
        "instrument": "instruments",
    }.get(entity_type)
    if not table:
        return None
    row = conn.execute(f"SELECT name FROM {table} WHERE id = ?", (entity_id,)).fetchone()
    return row["name"] if row else None


def _attachment_to_api(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "entityType": row["entity_type"],
        "entityId": row["entity_id"],
        "filename": row["filename"],
        "mime": row["mime"],
        "size": row["size"],
        "user": row["user"],
        "userName": row["user_name"],
        "time": row["time"],
    }


@app.get("/api/attachments")
def list_attachments(
    entity_type: str,
    entity_id: str,
    _: Dict[str, str] = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    if entity_type not in ATTACHMENT_ENTITY_TYPES:
        raise HTTPException(status_code=400, detail="附件对象类型不合法")
    with db_read() as conn:
        rows = conn.execute(
            """
            SELECT id, entity_type, entity_id, filename, mime, size,
                   user, user_name, time
            FROM attachments
            WHERE entity_type = ? AND entity_id = ?
            ORDER BY id DESC
            """,
            (entity_type, entity_id),
        ).fetchall()
    return [_attachment_to_api(row) for row in rows]


@app.post("/api/attachments")
def upload_attachment(
    payload: AttachmentIn,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, Any]:
    entity_type = (payload.entity_type or "").strip()
    entity_id = (payload.entity_id or "").strip()
    filename = os.path.basename((payload.filename or "").strip())[:180]
    mime = (payload.mime or "").strip().lower()
    if entity_type not in ATTACHMENT_ENTITY_TYPES:
        raise HTTPException(status_code=400, detail="附件对象类型不合法")
    if not filename:
        raise HTTPException(status_code=400, detail="请选择要上传的文件")
    if mime not in ATTACHMENT_MIME_TYPES:
        raise HTTPException(status_code=400, detail="仅支持 PDF、PNG、JPG、WEBP 或 TXT 文件")
    raw_base64 = payload.data_base64 or ""
    if "," in raw_base64 and raw_base64.strip().lower().startswith("data:"):
        raw_base64 = raw_base64.split(",", 1)[1]
    try:
        data = base64.b64decode(raw_base64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(status_code=400, detail="文件内容编码不正确")
    if not data:
        raise HTTPException(status_code=400, detail="文件内容为空")
    if len(data) > MAX_ATTACHMENT_BYTES:
        raise HTTPException(status_code=400, detail="附件不能超过 5MB")

    with db_transaction() as conn:
        entity_name = _attachment_entity_name(conn, entity_type, entity_id)
        if not entity_name:
            raise HTTPException(status_code=404, detail="附件关联档案不存在")
        cursor = conn.execute(
            """
            INSERT INTO attachments
                (entity_type, entity_id, filename, mime, size, data,
                 user, user_name, time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entity_type,
                entity_id,
                filename,
                mime,
                len(data),
                data,
                current_user["username"],
                current_user["name"],
                now_iso(),
            ),
        )
        attachment_id = cursor.lastrowid
        write_audit(
            conn,
            entity_type,
            entity_id,
            "attachment_add",
            f"上传附件 {filename} · {entity_name}",
            current_user,
            after={"filename": filename, "mime": mime, "size": len(data)},
        )
    return {"id": attachment_id}


@app.get("/api/attachments/{attachment_id}")
def download_attachment(
    attachment_id: int,
    _: Dict[str, str] = Depends(get_current_user),
) -> Response:
    with db_read() as conn:
        row = conn.execute("SELECT * FROM attachments WHERE id = ?", (attachment_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="附件不存在")
    encoded_name = quote(row["filename"])
    return Response(
        content=row["data"],
        media_type=row["mime"],
        headers={
            "Content-Disposition": f"inline; filename*=UTF-8''{encoded_name}",
            "Cache-Control": "private, max-age=60",
        },
    )


@app.delete("/api/attachments/{attachment_id}")
def delete_attachment(
    attachment_id: int,
    current_user: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, bool]:
    with db_transaction() as conn:
        row = conn.execute("SELECT * FROM attachments WHERE id = ?", (attachment_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="附件不存在")
        if row["user"] != current_user["username"] and current_user["role"] != "管理员":
            raise HTTPException(status_code=403, detail="只能删除自己上传的附件")
        conn.execute("DELETE FROM attachments WHERE id = ?", (attachment_id,))
        write_audit(
            conn,
            row["entity_type"],
            row["entity_id"],
            "attachment_delete",
            f"删除附件 {row['filename']}",
            current_user,
            before={"filename": row["filename"]},
        )
    return {"ok": True}


# --------------------------------- 概览 ----------------------------------

@app.get("/api/dashboard")
def dashboard(
    _: Dict[str, str] = Depends(get_current_user),
) -> Dict[str, int]:
    today = today_str()
    with db_read() as conn:
        reagent_count = conn.execute(
            "SELECT COUNT(*) AS n FROM reagents WHERE archived = 0"
        ).fetchone()["n"]
        low_stock = conn.execute(
            "SELECT COUNT(*) AS n FROM reagents WHERE archived = 0 AND stock <= threshold"
        ).fetchone()["n"]
        consumable_count = conn.execute(
            "SELECT COUNT(*) AS n FROM consumables WHERE archived = 0"
        ).fetchone()["n"]
        low_consumable = conn.execute(
            "SELECT COUNT(*) AS n FROM consumables WHERE archived = 0 AND stock <= threshold"
        ).fetchone()["n"]
        instrument_count = conn.execute(
            "SELECT COUNT(*) AS n FROM instruments"
        ).fetchone()["n"]
        in_use = conn.execute(
            "SELECT COUNT(*) AS n FROM instruments WHERE status = '使用中'"
        ).fetchone()["n"]
        reagent_ops = conn.execute(
            "SELECT COUNT(*) AS n FROM reagent_logs WHERE substr(time, 1, 10) = ?",
            (today,),
        ).fetchone()["n"]
        instrument_ops = conn.execute(
            "SELECT COUNT(*) AS n FROM instrument_logs WHERE substr(\"start\", 1, 10) = ?",
            (today,),
        ).fetchone()["n"]
        consumable_ops = conn.execute(
            "SELECT COUNT(*) AS n FROM consumable_logs WHERE substr(time, 1, 10) = ?",
            (today,),
        ).fetchone()["n"]

    return {
        "reagentCount": reagent_count,
        "lowStock": low_stock,
        "consumableCount": consumable_count,
        "lowConsumable": low_consumable,
        "instrumentCount": instrument_count,
        "inUse": in_use,
        "consumableOps": consumable_ops,
        "todayOps": reagent_ops + instrument_ops + consumable_ops,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
