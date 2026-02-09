#!/usr/bin/env python3
"""
Server Monitor - Dashboard
Main server: receives agent data, stores to SQLite, serves the web UI.
主服务端程序：接收 Agent 数据、存储到 SQLite、提供 Web 界面。
"""

import os
import json
import time
import hmac
import hashlib
import re
import secrets
import string
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

import yaml
from werkzeug.security import generate_password_hash as _gen_pw_hash, check_password_hash


def generate_password_hash(password):
    """Wrapper that uses pbkdf2 for broader compatibility.
    使用 pbkdf2 以获得更好的兼容性。"""
    return _gen_pw_hash(password, method='pbkdf2:sha256')
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, flash, g
)

# ---------------------------------------------------------------------------
# Configuration / 配置
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_config():
    config_path = os.path.join(BASE_DIR, 'config.yaml')
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


CONFIG = load_config()

app = Flask(__name__)
app.secret_key = CONFIG['server']['secret_key']
app.permanent_session_lifetime = timedelta(hours=24)

DATABASE = os.path.join(BASE_DIR, 'monitor.db')

# ---------------------------------------------------------------------------
# Database helpers / 数据库辅助
# ---------------------------------------------------------------------------


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys = ON')

    # --- Existing tables ---
    db.execute('''CREATE TABLE IF NOT EXISTS servers (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname    TEXT NOT NULL,
        mac_address TEXT UNIQUE,
        display_name TEXT DEFAULT '',
        ip          TEXT,
        os_info     TEXT,
        last_seen   TIMESTAMP,
        status      TEXT DEFAULT 'offline'
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS metrics (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id       INTEGER NOT NULL,
        timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        cpu_percent     REAL,
        cpu_count       INTEGER,
        memory_total    REAL,
        memory_used     REAL,
        memory_percent  REAL,
        disk_total      REAL,
        disk_used       REAL,
        disk_percent    REAL,
        gpu_data        TEXT,
        network_sent    REAL,
        network_recv    REAL,
        FOREIGN KEY (server_id) REFERENCES servers(id)
    )''')
    db.execute('''CREATE INDEX IF NOT EXISTS idx_metrics_server_time
                  ON metrics(server_id, timestamp)''')

    # --- New tables: users, access control, invites ---
    db.execute('''CREATE TABLE IF NOT EXISTS users (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        username            TEXT NOT NULL UNIQUE,
        email               TEXT DEFAULT '',
        password_hash       TEXT NOT NULL,
        role                TEXT NOT NULL DEFAULT 'user',
        can_view_processes  INTEGER DEFAULT 0,
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by          INTEGER
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS user_server_access (
        user_id     INTEGER NOT NULL,
        server_id   INTEGER NOT NULL,
        PRIMARY KEY (user_id, server_id),
        FOREIGN KEY (user_id)   REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS user_gpu_access (
        user_id     INTEGER NOT NULL,
        server_id   INTEGER NOT NULL,
        gpu_bus_id  TEXT NOT NULL,
        PRIMARY KEY (user_id, server_id, gpu_bus_id),
        FOREIGN KEY (user_id)   REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS user_server_preferences (
        user_id     INTEGER NOT NULL,
        server_id   INTEGER NOT NULL,
        alias_name  TEXT DEFAULT '',
        PRIMARY KEY (user_id, server_id),
        FOREIGN KEY (user_id)   REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS invites (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        token               TEXT NOT NULL UNIQUE,
        role                TEXT NOT NULL DEFAULT 'user',
        can_view_processes  INTEGER DEFAULT 0,
        server_ids          TEXT,
        max_uses            INTEGER NOT NULL DEFAULT 1,
        used_count          INTEGER NOT NULL DEFAULT 0,
        created_by          INTEGER,
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at          TIMESTAMP,
        used_by             INTEGER
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS user_agent_tokens (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id             INTEGER NOT NULL,
        token_hash          TEXT NOT NULL UNIQUE,
        token_name          TEXT DEFAULT '',
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used_at        TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )''')
    db.execute('''CREATE INDEX IF NOT EXISTS idx_user_agent_tokens_user
                  ON user_agent_tokens(user_id)''')
    db.execute('''CREATE TABLE IF NOT EXISTS app_settings (
        key         TEXT PRIMARY KEY,
        value       TEXT NOT NULL DEFAULT ''
    )''')
    db.execute('''CREATE TABLE IF NOT EXISTS gpu_admin_status (
        server_id            INTEGER NOT NULL,
        gpu_bus_id           TEXT NOT NULL,
        admin_status         TEXT NOT NULL DEFAULT 'normal',
        admin_status_note    TEXT DEFAULT '',
        updated_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (server_id, gpu_bus_id),
        FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
    )''')

    # --- Schema migration: servers hostname unique -> mac unique ---
    _migrate_servers_table_for_mac_identity(db)

    # --- Schema migration: add new columns if missing ---
    # metrics.errors
    cols = [r[1] for r in db.execute('PRAGMA table_info(metrics)').fetchall()]
    if 'errors' not in cols:
        db.execute('ALTER TABLE metrics ADD COLUMN errors TEXT')
    # servers.admin_status / admin_status_note
    scols = [r[1] for r in db.execute('PRAGMA table_info(servers)').fetchall()]
    if 'admin_status' not in scols:
        db.execute("ALTER TABLE servers ADD COLUMN admin_status TEXT DEFAULT 'normal'")
    if 'admin_status_note' not in scols:
        db.execute("ALTER TABLE servers ADD COLUMN admin_status_note TEXT DEFAULT ''")
    if 'display_name' not in scols:
        db.execute("ALTER TABLE servers ADD COLUMN display_name TEXT DEFAULT ''")
    if 'mac_address' not in scols:
        db.execute("ALTER TABLE servers ADD COLUMN mac_address TEXT")
    db.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_servers_mac_address '
               'ON servers(mac_address) WHERE mac_address IS NOT NULL AND mac_address != ""')
    db.execute('CREATE INDEX IF NOT EXISTS idx_servers_hostname ON servers(hostname)')
    ucols = [r[1] for r in db.execute('PRAGMA table_info(users)').fetchall()]
    if 'email' not in ucols:
        db.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''")
    db.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    icols = [r[1] for r in db.execute('PRAGMA table_info(invites)').fetchall()]
    if 'max_uses' not in icols:
        db.execute('ALTER TABLE invites ADD COLUMN max_uses INTEGER NOT NULL DEFAULT 1')
    if 'used_count' not in icols:
        db.execute('ALTER TABLE invites ADD COLUMN used_count INTEGER NOT NULL DEFAULT 0')
    db.execute('CREATE INDEX IF NOT EXISTS idx_user_gpu_access_user_server '
               'ON user_gpu_access(user_id, server_id)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_gpu_admin_status_server '
               'ON gpu_admin_status(server_id)')
    _set_setting(db, 'registration_email_suffix_enabled',
                 _get_setting(db, 'registration_email_suffix_enabled', '0'))
    _set_setting(db, 'registration_email_allowed_suffixes',
                 _get_setting(db, 'registration_email_allowed_suffixes', ''))

    # --- Announcements table ---
    db.execute('''CREATE TABLE IF NOT EXISTS announcements (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        content     TEXT NOT NULL,
        level       TEXT NOT NULL DEFAULT 'info',
        created_by  INTEGER,
        created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        active      INTEGER DEFAULT 1
    )''')

    # --- Bootstrap admin from config.yaml if no users exist ---
    count = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    if count == 0:
        auth_cfg = CONFIG.get('auth', {})
        admin_user = auth_cfg.get('username', 'admin')
        admin_pass = auth_cfg.get('password', 'admin123')
        pw_hash = generate_password_hash(admin_pass)
        db.execute(
            'INSERT INTO users (username, password_hash, role, can_view_processes) '
            'VALUES (?, ?, ?, ?)',
            (admin_user, pw_hash, 'admin', 1)
        )
        print(f"[INIT] Admin user '{admin_user}' created from config.yaml bootstrap / "
              f"管理员用户 '{admin_user}' 已从 config.yaml 引导创建")

    db.commit()
    db.close()


def _migrate_servers_table_for_mac_identity(db):
    """Migrate old servers table from unique hostname to unique mac_address.
    将旧 servers 表从 hostname 唯一迁移为 mac_address 唯一。"""
    # Old schema had UNIQUE(hostname); this blocks same-hostname machines.
    has_unique_hostname = False
    indexes = db.execute("PRAGMA index_list('servers')").fetchall()
    for idx in indexes:
        # PRAGMA index_list columns: seq, name, unique, origin, partial
        if int(idx[2]) != 1:
            continue
        idx_name = idx[1]
        cols = db.execute(f"PRAGMA index_info('{idx_name}')").fetchall()
        col_names = [c[2] for c in cols]
        if col_names == ['hostname']:
            has_unique_hostname = True
            break

    if not has_unique_hostname:
        return

    db.execute('PRAGMA foreign_keys = OFF')
    db.execute('''CREATE TABLE IF NOT EXISTS servers_new (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname         TEXT NOT NULL,
        mac_address      TEXT UNIQUE,
        display_name     TEXT DEFAULT '',
        ip               TEXT,
        os_info          TEXT,
        last_seen        TIMESTAMP,
        status           TEXT DEFAULT 'offline',
        admin_status     TEXT DEFAULT 'normal',
        admin_status_note TEXT DEFAULT ''
    )''')
    db.execute('''INSERT INTO servers_new
                  (id, hostname, ip, os_info, last_seen, status, admin_status, admin_status_note, display_name)
                  SELECT id, hostname, ip, os_info, last_seen, status,
                         COALESCE(admin_status, 'normal'),
                         COALESCE(admin_status_note, ''),
                         ''
                  FROM servers''')
    db.execute('DROP TABLE servers')
    db.execute('ALTER TABLE servers_new RENAME TO servers')
    db.execute('PRAGMA foreign_keys = ON')


# ---------------------------------------------------------------------------
# Auth helpers / 认证辅助
# ---------------------------------------------------------------------------
login_attempts: dict = {}  # ip -> [timestamp, ...]
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def _generate_password(length=12):
    """Generate a random password / 生成随机密码"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _normalize_email(email):
    return (email or '').strip().lower()


def _is_valid_email(email):
    return bool(EMAIL_RE.match(email or ''))


def _parse_allowed_suffixes(raw):
    parts = re.split(r'[\s,;]+', raw or '')
    suffixes = []
    for p in parts:
        s = p.strip().lower()
        if not s:
            continue
        if not s.startswith('@'):
            s = '@' + s
        suffixes.append(s)
    return sorted(set(suffixes))


def _normalize_bus_id(bus_id):
    return (bus_id or '').strip().lower()


def _get_setting(db, key, default=''):
    row = db.execute('SELECT value FROM app_settings WHERE key=?', (key,)).fetchone()
    if not row:
        return default
    if isinstance(row, sqlite3.Row):
        return row['value']
    return row[0]


def _set_setting(db, key, value):
    db.execute(
        '''INSERT INTO app_settings (key, value) VALUES (?, ?)
           ON CONFLICT(key) DO UPDATE SET value=excluded.value''',
        (key, str(value))
    )


def _registration_email_policy(db):
    enabled = _get_setting(db, 'registration_email_suffix_enabled', '0') == '1'
    raw = _get_setting(db, 'registration_email_allowed_suffixes', '')
    return enabled, _parse_allowed_suffixes(raw), raw


def _load_gpu_admin_status_map(db, server_ids):
    if not server_ids:
        return {}
    placeholders = ','.join(['?'] * len(server_ids))
    rows = db.execute(
        f'''SELECT server_id, gpu_bus_id, admin_status, admin_status_note
            FROM gpu_admin_status
            WHERE server_id IN ({placeholders})''',
        tuple(server_ids)
    ).fetchall()
    return {
        (r['server_id'], _normalize_bus_id(r['gpu_bus_id'])): (
            r['admin_status'] or 'normal',
            r['admin_status_note'] or ''
        )
        for r in rows
    }


def _load_user_gpu_access_map(db, user_id):
    rows = db.execute(
        'SELECT server_id, gpu_bus_id FROM user_gpu_access WHERE user_id = ?',
        (user_id,)
    ).fetchall()
    gpu_map = {}
    for r in rows:
        sid = r['server_id']
        gpu_map.setdefault(sid, set()).add(_normalize_bus_id(r['gpu_bus_id']))
    return gpu_map


def _latest_server_gpu_inventory(db, server_id):
    row = db.execute(
        'SELECT gpu_data FROM metrics WHERE server_id=? ORDER BY timestamp DESC LIMIT 1',
        (server_id,)
    ).fetchone()
    if not row or not row['gpu_data']:
        return []
    try:
        raw = json.loads(row['gpu_data'])
    except json.JSONDecodeError:
        return []
    inventory = []
    for g in raw:
        bus_id = _normalize_bus_id(g.get('bus_id'))
        if not bus_id:
            continue
        inventory.append({
            'bus_id': bus_id,
            'name': g.get('name') or 'GPU',
            'index': g.get('index'),
        })
    # Deduplicate by bus_id
    dedup = {}
    for g in inventory:
        dedup[g['bus_id']] = g
    return [dedup[k] for k in sorted(dedup.keys())]


def _hash_user_agent_token(token):
    """Hash user-generated agent token before storage / 用户 token 入库前哈希"""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def _normalize_mac_address(mac):
    """Normalize MAC address to aa:bb:cc:dd:ee:ff format.
    规范化 MAC 地址为 aa:bb:cc:dd:ee:ff。"""
    if not mac:
        return None
    cleaned = re.sub(r'[^0-9a-fA-F]', '', str(mac))
    if len(cleaned) != 12:
        return None
    return ':'.join(cleaned[i:i + 2] for i in range(0, 12, 2)).lower()


def _load_session_user():
    """Load current user info into g.user from session / 从 session 加载当前用户"""
    g.user = None
    uid = session.get('user_id')
    if uid is not None:
        g.user = {
            'id':                 uid,
            'username':           session.get('username'),
            'role':               session.get('role'),
            'can_view_processes': session.get('can_view_processes', 0),
        }


@app.before_request
def before_request():
    _load_session_user()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        if g.user['role'] != 'admin':
            return jsonify({'error': 'Forbidden'}), 403
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Web Routes / Web 路由
# ---------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr
        now = time.time()

        # Clean up expired attempt records / 清理过期的尝试记录
        login_attempts[ip] = [t for t in login_attempts.get(ip, []) if now - t < 300]

        # Rate limit: max 5 attempts within 5 minutes / 速率限制
        if len(login_attempts.get(ip, [])) >= 5:
            flash('Too many attempts, please try again in 5 minutes / 尝试次数过多，请 5 分钟后再试', 'error')
            return render_template('login.html')

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['can_view_processes'] = user['can_view_processes']
            login_attempts.pop(ip, None)
            return redirect(url_for('dashboard'))
        else:
            login_attempts.setdefault(ip, []).append(now)
            flash('Incorrect username or password / 用户名或密码错误', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def dashboard():
    server_data = _build_server_data(g.user)
    return render_template('dashboard.html', servers=server_data, current_user=g.user)


@app.route('/panel')
@login_required
def user_panel():
    return render_template('user.html', current_user=g.user)


# ---------------------------------------------------------------------------
# Registration via invite / 邀请注册
# ---------------------------------------------------------------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    token = request.args.get('token', '') or request.form.get('token', '')

    if not token:
        flash('Invalid or missing invite token / 无效或缺失的邀请令牌', 'error')
        return redirect(url_for('login'))

    db = get_db()
    invite = db.execute('SELECT * FROM invites WHERE token = ?', (token,)).fetchone()

    if not invite:
        flash('Invalid invite link / 无效的邀请链接', 'error')
        return redirect(url_for('login'))
    try:
        max_uses = int(invite['max_uses'] or 1)
    except (TypeError, ValueError):
        max_uses = 1
    try:
        used_count = int(invite['used_count'] or 0)
    except (TypeError, ValueError):
        used_count = 0
    if used_count >= max_uses:
        flash('This invite has reached max users / 该邀请链接使用人数已满', 'error')
        return redirect(url_for('login'))
    if invite['expires_at'] and datetime.fromisoformat(invite['expires_at']) < datetime.now():
        flash('This invite has expired / 该邀请链接已过期', 'error')
        return redirect(url_for('login'))
    policy_enabled, allowed_suffixes, _ = _registration_email_policy(db)

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = _normalize_email(request.form.get('email', ''))
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        errors = []
        if not username or len(username) < 2:
            errors.append('Username must be at least 2 characters / 用户名至少 2 个字符')
        if not email:
            errors.append('Email is required / 邮箱为必填项')
        elif not _is_valid_email(email):
            errors.append('Invalid email format / 邮箱格式不正确')
        if not password or len(password) < 6:
            errors.append('Password must be at least 6 characters / 密码至少 6 个字符')
        if password != confirm:
            errors.append('Passwords do not match / 两次密码不一致')

        if policy_enabled and allowed_suffixes:
            if not any(email.endswith(s) for s in allowed_suffixes):
                errors.append(
                    'Email domain is not allowed / 邮箱后缀不在允许范围: '
                    + ', '.join(allowed_suffixes)
                )

        # Check username uniqueness
        existing = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing:
            errors.append('Username already taken / 用户名已被使用')
        existing_email = db.execute(
            'SELECT id FROM users WHERE email = ? AND email != ""',
            (email,)
        ).fetchone()
        if existing_email:
            errors.append('Email already used / 邮箱已被使用')

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template(
                'register.html',
                token=token,
                email_suffix_enabled=policy_enabled,
                allowed_suffixes=allowed_suffixes
            )

        # Create user with invite permissions
        pw_hash = generate_password_hash(password)
        cursor = db.execute(
            'INSERT INTO users (username, email, password_hash, role, can_view_processes, created_by) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (username, email, pw_hash, invite['role'], invite['can_view_processes'],
             invite['created_by'])
        )
        new_user_id = cursor.lastrowid

        # Apply server access from invite
        server_ids = json.loads(invite['server_ids']) if invite['server_ids'] else []
        for sid in server_ids:
            db.execute(
                'INSERT OR IGNORE INTO user_server_access (user_id, server_id) VALUES (?, ?)',
                (new_user_id, sid)
            )

        # Update invite usage count
        db.execute(
            '''UPDATE invites
               SET used_count = COALESCE(used_count, 0) + 1,
                   used_by = CASE WHEN used_by IS NULL THEN ? ELSE used_by END
               WHERE id = ?''',
            (new_user_id, invite['id'])
        )
        db.commit()

        flash('Registration successful! Please log in. / 注册成功！请登录。', 'success')
        return redirect(url_for('login'))

    return render_template(
        'register.html',
        token=token,
        email_suffix_enabled=policy_enabled,
        allowed_suffixes=allowed_suffixes
    )


# ---------------------------------------------------------------------------
# API Routes — Dashboard (session auth) / 仪表盘 API
# ---------------------------------------------------------------------------

@app.route('/api/servers')
@login_required
def api_servers():
    return jsonify(_build_server_data(g.user))


@app.route('/api/servers/<int:server_id>/history')
@login_required
def api_server_history(server_id):
    # Check access for non-admin users / 非管理员检查访问权限
    if g.user['role'] != 'admin':
        db = get_db()
        access = db.execute(
            'SELECT 1 FROM user_server_access WHERE user_id=? AND server_id=?',
            (g.user['id'], server_id)
        ).fetchone()
        if not access:
            return jsonify({'error': 'Forbidden'}), 403

    hours = request.args.get('hours', 24, type=int)
    db = get_db()
    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
    rows = db.execute(
        '''SELECT timestamp, cpu_percent, memory_percent, disk_percent, gpu_data
           FROM metrics WHERE server_id = ? AND timestamp > ?
           ORDER BY timestamp''',
        (server_id, cutoff)
    ).fetchall()
    gpu_status_map = _load_gpu_admin_status_map(db, [server_id])
    allowed_gpu_bus_ids = None
    if g.user['role'] != 'admin':
        user_gpu_map = _load_user_gpu_access_map(db, g.user['id'])
        if server_id in user_gpu_map:
            allowed_gpu_bus_ids = user_gpu_map[server_id]

    result = []
    for m in rows:
        gpu_data = json.loads(m['gpu_data']) if m['gpu_data'] else []
        normalized_gpu_data = []
        for gpu in gpu_data:
            bus_id = _normalize_bus_id(gpu.get('bus_id'))
            if allowed_gpu_bus_ids is not None and bus_id not in allowed_gpu_bus_ids:
                continue
            st, note = gpu_status_map.get((server_id, bus_id), ('normal', ''))
            gpu['bus_id'] = bus_id or gpu.get('bus_id')
            gpu['admin_status'] = st
            gpu['admin_status_note'] = note
            normalized_gpu_data.append(gpu)
        gpu_data = normalized_gpu_data
        if not g.user.get('can_view_processes'):
            for gpu in gpu_data:
                gpu.pop('processes', None)
        result.append({
            'timestamp':      m['timestamp'],
            'cpu_percent':    m['cpu_percent'],
            'memory_percent': m['memory_percent'],
            'disk_percent':   m['disk_percent'],
            'gpu_data':       gpu_data,
        })
    return jsonify(result)


@app.route('/api/servers/<int:server_id>', methods=['DELETE'])
@admin_required
def api_delete_server(server_id):
    db = get_db()
    db.execute('DELETE FROM user_server_access WHERE server_id = ?', (server_id,))
    db.execute('DELETE FROM metrics WHERE server_id = ?', (server_id,))
    db.execute('DELETE FROM servers WHERE id = ?', (server_id,))
    db.commit()
    return jsonify({'status': 'ok'})


# ---------------------------------------------------------------------------
# User Panel API / 用户面板 API
# ---------------------------------------------------------------------------

@app.route('/api/user/tokens')
@login_required
def api_user_list_tokens():
    db = get_db()
    rows = db.execute(
        '''SELECT id, token_name, created_at, last_used_at
           FROM user_agent_tokens
           WHERE user_id = ?
           ORDER BY created_at DESC''',
        (g.user['id'],)
    ).fetchall()
    return jsonify([{
        'id': r['id'],
        'token_name': r['token_name'] or '',
        'created_at': r['created_at'],
        'last_used_at': r['last_used_at'],
    } for r in rows])


@app.route('/api/user/tokens', methods=['POST'])
@login_required
def api_user_create_token():
    data = request.get_json(silent=True) or {}
    token_name = (data.get('token_name') or '').strip()[:64]
    raw_token = f"smu_{secrets.token_urlsafe(32)}"
    token_hash = _hash_user_agent_token(raw_token)

    db = get_db()
    cursor = db.execute(
        'INSERT INTO user_agent_tokens (user_id, token_hash, token_name) VALUES (?, ?, ?)',
        (g.user['id'], token_hash, token_name)
    )
    db.commit()
    return jsonify({
        'id': cursor.lastrowid,
        'token': raw_token,  # Shown once / 仅显示一次
        'token_name': token_name,
    })


@app.route('/api/user/tokens/<int:token_id>', methods=['DELETE'])
@login_required
def api_user_delete_token(token_id):
    db = get_db()
    row = db.execute(
        'SELECT id FROM user_agent_tokens WHERE id=? AND user_id=?',
        (token_id, g.user['id'])
    ).fetchone()
    if not row:
        return jsonify({'error': 'Token not found'}), 404
    db.execute('DELETE FROM user_agent_tokens WHERE id=?', (token_id,))
    db.commit()
    return jsonify({'status': 'ok'})


@app.route('/api/user/password', methods=['POST'])
@login_required
def api_user_change_password():
    data = request.get_json(silent=True) or {}
    old_password = data.get('old_password', '')
    new_password = (data.get('new_password') or '').strip()

    if not old_password:
        return jsonify({'error': 'Current password is required / 请输入当前密码'}), 400
    if len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters / 密码至少 6 个字符'}), 400

    db = get_db()
    user = db.execute(
        'SELECT id, password_hash FROM users WHERE id = ?',
        (g.user['id'],)
    ).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    if not check_password_hash(user['password_hash'], old_password):
        return jsonify({'error': 'Current password is incorrect / 当前密码错误'}), 400

    pw_hash = generate_password_hash(new_password)
    db.execute('UPDATE users SET password_hash=? WHERE id=?', (pw_hash, g.user['id']))
    db.commit()
    return jsonify({'status': 'ok'})


@app.route('/api/user/profile')
@login_required
def api_user_profile():
    db = get_db()
    row = db.execute(
        'SELECT username, email FROM users WHERE id=?',
        (g.user['id'],)
    ).fetchone()
    if not row:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'username': row['username'],
        'email': row['email'] or '',
    })


@app.route('/api/user/profile', methods=['PUT'])
@login_required
def api_user_update_profile():
    data = request.get_json(silent=True) or {}
    email = _normalize_email(data.get('email', ''))
    if not email:
        return jsonify({'error': 'Email is required / 邮箱为必填项'}), 400
    if not _is_valid_email(email):
        return jsonify({'error': 'Invalid email format / 邮箱格式不正确'}), 400

    db = get_db()
    existing = db.execute(
        'SELECT id FROM users WHERE email=? AND id != ? AND email != ""',
        (email, g.user['id'])
    ).fetchone()
    if existing:
        return jsonify({'error': 'Email already used / 邮箱已被使用'}), 409

    policy_enabled, allowed_suffixes, _ = _registration_email_policy(db)
    if policy_enabled and allowed_suffixes:
        if not any(email.endswith(s) for s in allowed_suffixes):
            return jsonify({
                'error': 'Email domain is not allowed / 邮箱后缀不在允许范围: '
                         + ', '.join(allowed_suffixes)
            }), 400

    db.execute('UPDATE users SET email=? WHERE id=?', (email, g.user['id']))
    db.commit()
    return jsonify({'status': 'ok'})


@app.route('/api/user/servers/<int:server_id>/alias', methods=['PUT'])
@login_required
def api_user_set_server_alias(server_id):
    data = request.get_json(silent=True) or {}
    alias_name = (data.get('alias_name') or '').strip()
    if len(alias_name) > 128:
        return jsonify({'error': 'Alias is too long / 别名过长'}), 400

    db = get_db()
    server = db.execute('SELECT id FROM servers WHERE id=?', (server_id,)).fetchone()
    if not server:
        return jsonify({'error': 'Server not found'}), 404

    if g.user['role'] != 'admin':
        access = db.execute(
            'SELECT 1 FROM user_server_access WHERE user_id=? AND server_id=?',
            (g.user['id'], server_id)
        ).fetchone()
        if not access:
            return jsonify({'error': 'Forbidden'}), 403

    if alias_name:
        db.execute(
            '''INSERT INTO user_server_preferences (user_id, server_id, alias_name)
               VALUES (?, ?, ?)
               ON CONFLICT(user_id, server_id) DO UPDATE SET alias_name=excluded.alias_name''',
            (g.user['id'], server_id, alias_name)
        )
    else:
        db.execute(
            'DELETE FROM user_server_preferences WHERE user_id=? AND server_id=?',
            (g.user['id'], server_id)
        )
    db.commit()
    return jsonify({'status': 'ok'})


# ---------------------------------------------------------------------------
# Admin page / 管理页面
# ---------------------------------------------------------------------------

@app.route('/admin')
@admin_required
def admin_page():
    return render_template('admin.html', current_user=g.user)


# ---------------------------------------------------------------------------
# Admin API — Registration settings / 注册设置
# ---------------------------------------------------------------------------

@app.route('/api/admin/settings/registration')
@admin_required
def api_admin_get_registration_settings():
    db = get_db()
    enabled, suffixes, raw = _registration_email_policy(db)
    return jsonify({
        'email_suffix_enabled': enabled,
        'allowed_suffixes': suffixes,
        'allowed_suffixes_raw': raw,
    })


@app.route('/api/admin/settings/registration', methods=['PUT'])
@admin_required
def api_admin_set_registration_settings():
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get('email_suffix_enabled'))
    raw = (data.get('allowed_suffixes_raw') or '').strip().lower()
    suffixes = _parse_allowed_suffixes(raw)
    if enabled and not suffixes:
        return jsonify({'error': 'Please provide at least one allowed suffix / 请至少填写一个后缀'}), 400

    db = get_db()
    _set_setting(db, 'registration_email_suffix_enabled', '1' if enabled else '0')
    _set_setting(db, 'registration_email_allowed_suffixes', ','.join(suffixes))
    db.commit()
    return jsonify({'status': 'ok', 'allowed_suffixes': suffixes})


# ---------------------------------------------------------------------------
# Admin API — Users / 管理 API — 用户
# ---------------------------------------------------------------------------

@app.route('/api/admin/users')
@admin_required
def api_admin_list_users():
    db = get_db()
    users = db.execute(
        'SELECT id, username, email, role, can_view_processes, created_at FROM users ORDER BY id'
    ).fetchall()

    result = []
    for u in users:
        # Get server access list
        access = db.execute(
            'SELECT server_id FROM user_server_access WHERE user_id = ?', (u['id'],)
        ).fetchall()
        server_ids = [a['server_id'] for a in access]
        gpu_rows = db.execute(
            'SELECT server_id, gpu_bus_id FROM user_gpu_access WHERE user_id = ? ORDER BY server_id, gpu_bus_id',
            (u['id'],)
        ).fetchall()
        gpu_access = {}
        for g in gpu_rows:
            sid = str(g['server_id'])
            gpu_access.setdefault(sid, []).append(_normalize_bus_id(g['gpu_bus_id']))

        result.append({
            'id':                 u['id'],
            'username':           u['username'],
            'email':              u['email'] or '',
            'role':               u['role'],
            'can_view_processes': u['can_view_processes'],
            'server_ids':         server_ids,
            'gpu_access':         gpu_access,
            'created_at':         u['created_at'],
        })
    return jsonify(result)


@app.route('/api/admin/users', methods=['POST'])
@admin_required
def api_admin_create_user():
    data = request.get_json()
    if not data or not data.get('username', '').strip():
        return jsonify({'error': 'Username is required'}), 400

    username = data['username'].strip()
    email = _normalize_email(data.get('email', ''))
    role = data.get('role', 'user')
    can_view = 1 if data.get('can_view_processes') else 0
    server_ids = data.get('server_ids', [])
    gpu_access = data.get('gpu_access', {}) or {}
    if not email:
        return jsonify({'error': 'Email is required / 邮箱为必填项'}), 400
    if not _is_valid_email(email):
        return jsonify({'error': 'Invalid email format / 邮箱格式不正确'}), 400

    db = get_db()
    existing = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if existing:
        return jsonify({'error': 'Username already exists / 用户名已存在'}), 409
    existing_email = db.execute(
        'SELECT id FROM users WHERE email = ? AND email != ""',
        (email,)
    ).fetchone()
    if existing_email:
        return jsonify({'error': 'Email already exists / 邮箱已存在'}), 409

    password = _generate_password()
    pw_hash = generate_password_hash(password)

    cursor = db.execute(
        'INSERT INTO users (username, email, password_hash, role, can_view_processes, created_by) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (username, email, pw_hash, role, can_view, g.user['id'])
    )
    new_id = cursor.lastrowid

    for sid in server_ids:
        db.execute(
            'INSERT OR IGNORE INTO user_server_access (user_id, server_id) VALUES (?, ?)',
            (new_id, sid)
        )
    # Optional per-server GPU restrictions: if absent for a server => all GPUs visible
    if isinstance(gpu_access, dict):
        allowed_servers = set()
        for s in server_ids:
            try:
                allowed_servers.add(int(s))
            except (TypeError, ValueError):
                continue
        for sid_raw, bus_list in gpu_access.items():
            try:
                sid = int(sid_raw)
            except (TypeError, ValueError):
                continue
            if sid not in allowed_servers or not isinstance(bus_list, list):
                continue
            for bus in bus_list:
                bus_id = _normalize_bus_id(bus)
                if not bus_id:
                    continue
                db.execute(
                    '''INSERT OR IGNORE INTO user_gpu_access (user_id, server_id, gpu_bus_id)
                       VALUES (?, ?, ?)''',
                    (new_id, sid, bus_id)
                )
    db.commit()

    return jsonify({
        'id': new_id,
        'username': username,
        'password': password,  # Shown once / 仅显示一次
        'role': role,
    })


@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def api_admin_update_user(user_id):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Prevent demoting the last admin / 防止移除最后一个管理员
    if user['role'] == 'admin' and data.get('role') != 'admin':
        admin_count = db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
        if admin_count <= 1:
            return jsonify({'error': 'Cannot remove the last admin / 不能移除最后一个管理员'}), 400

    role = data.get('role', user['role'])
    can_view = 1 if data.get('can_view_processes') else 0

    db.execute(
        'UPDATE users SET role=?, can_view_processes=? WHERE id=?',
        (role, can_view, user_id)
    )

    # Update server access
    if 'server_ids' in data:
        db.execute('DELETE FROM user_server_access WHERE user_id = ?', (user_id,))
        for sid in data['server_ids']:
            db.execute(
                'INSERT OR IGNORE INTO user_server_access (user_id, server_id) VALUES (?, ?)',
                (user_id, sid)
            )
        # Server list changed -> reset all GPU restrictions, then re-apply from payload.
        db.execute('DELETE FROM user_gpu_access WHERE user_id = ?', (user_id,))
        gpu_access = data.get('gpu_access', {}) or {}
        if isinstance(gpu_access, dict):
            allowed_servers = set()
            for s in data['server_ids']:
                try:
                    allowed_servers.add(int(s))
                except (TypeError, ValueError):
                    continue
            for sid_raw, bus_list in gpu_access.items():
                try:
                    sid = int(sid_raw)
                except (TypeError, ValueError):
                    continue
                if sid not in allowed_servers or not isinstance(bus_list, list):
                    continue
                for bus in bus_list:
                    bus_id = _normalize_bus_id(bus)
                    if not bus_id:
                        continue
                    db.execute(
                        '''INSERT OR IGNORE INTO user_gpu_access (user_id, server_id, gpu_bus_id)
                           VALUES (?, ?, ?)''',
                        (user_id, sid, bus_id)
                    )

    db.commit()
    return jsonify({'status': 'ok'})


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_user(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Prevent deleting self or last admin
    if user_id == g.user['id']:
        return jsonify({'error': 'Cannot delete yourself / 不能删除自己'}), 400
    if user['role'] == 'admin':
        admin_count = db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
        if admin_count <= 1:
            return jsonify({'error': 'Cannot delete the last admin / 不能删除最后一个管理员'}), 400

    db.execute('DELETE FROM user_server_access WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM user_gpu_access WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    return jsonify({'status': 'ok'})


@app.route('/api/admin/users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def api_admin_reset_password(user_id):
    db = get_db()
    user = db.execute('SELECT id FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json(silent=True) or {}
    password = (data.get('password') or '').strip()
    if password and len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters / 密码至少 6 个字符'}), 400
    if not password:
        password = _generate_password()

    pw_hash = generate_password_hash(password)
    db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (pw_hash, user_id))
    db.commit()

    return jsonify({'password': password})  # Shown once / 仅显示一次


# ---------------------------------------------------------------------------
# Admin API — Invites / 管理 API — 邀请
# ---------------------------------------------------------------------------

@app.route('/api/admin/invites')
@admin_required
def api_admin_list_invites():
    db = get_db()
    invites = db.execute(
        'SELECT * FROM invites ORDER BY created_at DESC'
    ).fetchall()

    result = []
    for inv in invites:
        used_by_name = None
        if inv['used_by']:
            u = db.execute('SELECT username FROM users WHERE id=?', (inv['used_by'],)).fetchone()
            used_by_name = u['username'] if u else None
        max_uses = int(inv['max_uses'] or 1)
        used_count = int(inv['used_count'] or 0)

        result.append({
            'id':                 inv['id'],
            'token':              inv['token'],
            'role':               inv['role'],
            'can_view_processes': inv['can_view_processes'],
            'server_ids':         json.loads(inv['server_ids']) if inv['server_ids'] else [],
            'created_at':         inv['created_at'],
            'expires_at':         inv['expires_at'],
            'max_uses':           max_uses,
            'used_count':         used_count,
            'used_by':            inv['used_by'],
            'used_by_name':       used_by_name,
        })
    return jsonify(result)


@app.route('/api/admin/invites', methods=['POST'])
@admin_required
def api_admin_create_invite():
    data = request.get_json() or {}
    role = data.get('role', 'user')
    can_view = 1 if data.get('can_view_processes') else 0
    server_ids = data.get('server_ids', [])
    expire_hours = data.get('expire_hours', 72)
    try:
        max_uses = int(data.get('max_uses', 1) or 1)
    except (TypeError, ValueError):
        return jsonify({'error': 'max_uses must be an integer'}), 400
    if max_uses < 1:
        return jsonify({'error': 'max_uses must be >= 1'}), 400

    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(hours=expire_hours)).isoformat()

    db = get_db()
    db.execute(
        '''INSERT INTO invites
           (token, role, can_view_processes, server_ids, max_uses, used_count, created_by, expires_at)
           VALUES (?, ?, ?, ?, ?, 0, ?, ?)''',
        (token, role, can_view, json.dumps(server_ids), max_uses, g.user['id'], expires_at)
    )
    db.commit()

    # Build full URL
    invite_url = f"{request.scheme}://{request.host}/register?token={token}"

    return jsonify({'token': token, 'url': invite_url, 'expires_at': expires_at, 'max_uses': max_uses})


@app.route('/api/admin/invites/<int:invite_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_invite(invite_id):
    db = get_db()
    db.execute('DELETE FROM invites WHERE id = ?', (invite_id,))
    db.commit()
    return jsonify({'status': 'ok'})


# ---------------------------------------------------------------------------
# Admin API — Servers list & status / 服务器列表 & 状态管理
# ---------------------------------------------------------------------------

@app.route('/api/admin/servers')
@admin_required
def api_admin_servers():
    db = get_db()
    servers = db.execute(
        '''SELECT id, hostname, display_name, mac_address, ip, admin_status, admin_status_note
           FROM servers
           ORDER BY COALESCE(NULLIF(display_name, ''), hostname)'''
    ).fetchall()
    server_ids = [s['id'] for s in servers]
    gpu_status_map = _load_gpu_admin_status_map(db, server_ids)
    result = []
    for s in servers:
        inventory = _latest_server_gpu_inventory(db, s['id'])
        gpus = []
        for g in inventory:
            st, note = gpu_status_map.get((s['id'], g['bus_id']), ('normal', ''))
            gpus.append({
                'bus_id': g['bus_id'],
                'name': g['name'],
                'index': g['index'],
                'admin_status': st,
                'admin_status_note': note,
            })
        result.append({
            'id': s['id'],
            'hostname': s['display_name'] or s['hostname'],
            'raw_hostname': s['hostname'],
            'display_name': s['display_name'] or '',
            'mac_address': s['mac_address'] or '',
            'ip': s['ip'],
            'admin_status': s['admin_status'] or 'normal',
            'admin_status_note': s['admin_status_note'] or '',
            'gpus': gpus,
        })
    return jsonify(result)


@app.route('/api/admin/servers/<int:server_id>/gpus')
@admin_required
def api_admin_server_gpus(server_id):
    db = get_db()
    srv = db.execute(
        'SELECT id, hostname, display_name FROM servers WHERE id=?',
        (server_id,)
    ).fetchone()
    if not srv:
        return jsonify({'error': 'Server not found'}), 404
    inventory = _latest_server_gpu_inventory(db, server_id)
    gpu_status_map = _load_gpu_admin_status_map(db, [server_id])
    gpus = []
    for g in inventory:
        st, note = gpu_status_map.get((server_id, g['bus_id']), ('normal', ''))
        gpus.append({
            'bus_id': g['bus_id'],
            'name': g['name'],
            'index': g['index'],
            'admin_status': st,
            'admin_status_note': note,
        })
    return jsonify({
        'server_id': server_id,
        'hostname': srv['display_name'] or srv['hostname'],
        'gpus': gpus,
    })


@app.route('/api/admin/servers/<int:server_id>/gpus/status', methods=['PUT'])
@admin_required
def api_admin_set_gpu_status(server_id):
    data = request.get_json(silent=True) or {}
    bus_id = _normalize_bus_id(data.get('gpu_bus_id'))
    admin_status = (data.get('admin_status') or 'normal').strip()
    admin_note = (data.get('admin_status_note') or '').strip()
    if not bus_id:
        return jsonify({'error': 'gpu_bus_id is required'}), 400
    if admin_status not in ('normal', 'maintenance', 'fault'):
        return jsonify({'error': 'Invalid status'}), 400
    db = get_db()
    srv = db.execute('SELECT id FROM servers WHERE id=?', (server_id,)).fetchone()
    if not srv:
        return jsonify({'error': 'Server not found'}), 404
    if admin_status == 'normal' and not admin_note:
        db.execute(
            'DELETE FROM gpu_admin_status WHERE server_id=? AND gpu_bus_id=?',
            (server_id, bus_id)
        )
    else:
        db.execute(
            '''INSERT INTO gpu_admin_status (server_id, gpu_bus_id, admin_status, admin_status_note, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(server_id, gpu_bus_id) DO UPDATE
               SET admin_status=excluded.admin_status,
                   admin_status_note=excluded.admin_status_note,
                   updated_at=excluded.updated_at''',
            (server_id, bus_id, admin_status, admin_note, datetime.now().isoformat())
        )
    db.commit()
    return jsonify({'status': 'ok'})


@app.route('/api/admin/servers/<int:server_id>/name', methods=['PUT'])
@admin_required
def api_admin_set_server_name(server_id):
    data = request.get_json(silent=True) or {}
    display_name = (data.get('display_name') or '').strip()
    if len(display_name) > 128:
        return jsonify({'error': 'Display name is too long / 显示名过长'}), 400
    db = get_db()
    row = db.execute('SELECT id FROM servers WHERE id=?', (server_id,)).fetchone()
    if not row:
        return jsonify({'error': 'Server not found'}), 404
    db.execute('UPDATE servers SET display_name=? WHERE id=?', (display_name, server_id))
    db.commit()
    return jsonify({'status': 'ok'})


@app.route('/api/admin/servers/<int:server_id>/status', methods=['PUT'])
@admin_required
def api_admin_set_server_status(server_id):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400
    admin_status = data.get('admin_status', 'normal')
    admin_note = data.get('admin_status_note', '')
    if admin_status not in ('normal', 'fault', 'maintenance'):
        return jsonify({'error': 'Invalid status'}), 400
    db = get_db()
    db.execute('UPDATE servers SET admin_status=?, admin_status_note=? WHERE id=?',
               (admin_status, admin_note, server_id))
    db.commit()
    return jsonify({'status': 'ok'})


# ---------------------------------------------------------------------------
# Admin API — Announcements / 管理 API — 公告
# ---------------------------------------------------------------------------

@app.route('/api/announcements')
@login_required
def api_announcements():
    """List active announcements (for all logged-in users).
    列出活跃公告（所有登录用户可见）。"""
    db = get_db()
    rows = db.execute(
        'SELECT id, content, level, created_at FROM announcements WHERE active=1 ORDER BY created_at DESC'
    ).fetchall()
    return jsonify([{
        'id': r['id'], 'content': r['content'],
        'level': r['level'], 'created_at': r['created_at'],
    } for r in rows])


@app.route('/api/admin/announcements')
@admin_required
def api_admin_list_announcements():
    db = get_db()
    rows = db.execute('SELECT * FROM announcements ORDER BY created_at DESC').fetchall()
    return jsonify([{
        'id': r['id'], 'content': r['content'], 'level': r['level'],
        'active': r['active'], 'created_at': r['created_at'],
    } for r in rows])


@app.route('/api/admin/announcements', methods=['POST'])
@admin_required
def api_admin_create_announcement():
    data = request.get_json()
    if not data or not data.get('content', '').strip():
        return jsonify({'error': 'Content is required'}), 400
    level = data.get('level', 'info')
    if level not in ('info', 'warning', 'critical'):
        level = 'info'
    db = get_db()
    cursor = db.execute(
        'INSERT INTO announcements (content, level, created_by) VALUES (?,?,?)',
        (data['content'].strip(), level, g.user['id'])
    )
    db.commit()
    return jsonify({'id': cursor.lastrowid, 'status': 'ok'})


@app.route('/api/admin/announcements/<int:ann_id>', methods=['PUT'])
@admin_required
def api_admin_update_announcement(ann_id):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400
    db = get_db()
    ann = db.execute('SELECT * FROM announcements WHERE id=?', (ann_id,)).fetchone()
    if not ann:
        return jsonify({'error': 'Not found'}), 404
    content = data.get('content', ann['content'])
    level = data.get('level', ann['level'])
    active = data.get('active', ann['active'])
    db.execute('UPDATE announcements SET content=?, level=?, active=? WHERE id=?',
               (content, level, int(active), ann_id))
    db.commit()
    return jsonify({'status': 'ok'})


@app.route('/api/admin/announcements/<int:ann_id>', methods=['DELETE'])
@admin_required
def api_admin_delete_announcement(ann_id):
    db = get_db()
    db.execute('DELETE FROM announcements WHERE id=?', (ann_id,))
    db.commit()
    return jsonify({'status': 'ok'})


# ---------------------------------------------------------------------------
# API Routes — Agent (token auth) / Agent API（令牌认证）
# ---------------------------------------------------------------------------

@app.route('/api/report', methods=['POST'])
def api_report():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({'error': 'Unauthorized'}), 401

    db = get_db()
    report_user_id = None
    if not hmac.compare_digest(token, CONFIG['agent']['token']):
        token_hash = _hash_user_agent_token(token)
        token_row = db.execute(
            'SELECT id, user_id FROM user_agent_tokens WHERE token_hash = ?',
            (token_hash,)
        ).fetchone()
        if not token_row:
            return jsonify({'error': 'Unauthorized'}), 401
        report_user_id = token_row['user_id']
        db.execute(
            'UPDATE user_agent_tokens SET last_used_at = ? WHERE id = ?',
            (datetime.now().isoformat(), token_row['id'])
        )

    data = request.get_json()
    if not data or 'hostname' not in data:
        return jsonify({'error': 'Invalid data'}), 400

    now = datetime.now().isoformat()
    hostname = str(data.get('hostname', '')).strip() or 'unknown'
    mac_address = _normalize_mac_address(data.get('mac_address'))

    # Upsert server / 更新或插入服务器记录（优先按 MAC）
    server = None
    if mac_address:
        server = db.execute(
            'SELECT id FROM servers WHERE mac_address = ?',
            (mac_address,)
        ).fetchone()

        # Backfill MAC for legacy rows that were keyed by hostname only.
        if not server:
            legacy = db.execute(
                '''SELECT id FROM servers
                   WHERE hostname = ?
                     AND (mac_address IS NULL OR mac_address = '')
                   ORDER BY id LIMIT 1''',
                (hostname,)
            ).fetchone()
            if legacy:
                db.execute(
                    'UPDATE servers SET mac_address = ? WHERE id = ?',
                    (mac_address, legacy['id'])
                )
                server = legacy

    if not server and not mac_address:
        server = db.execute(
            'SELECT id FROM servers WHERE hostname = ? ORDER BY id LIMIT 1',
            (hostname,)
        ).fetchone()

    if server:
        server_id = server['id']
        if report_user_id is not None:
            access = db.execute(
                'SELECT 1 FROM user_server_access WHERE user_id=? AND server_id=?',
                (report_user_id, server_id)
            ).fetchone()
            if not access:
                return jsonify({
                    'error': 'Hostname already exists and is not assigned to this user'
                }), 403
        db.execute(
            'UPDATE servers SET hostname=?, mac_address=COALESCE(mac_address, ?), ip=?, os_info=?, last_seen=?, status=? WHERE id=?',
            (hostname, mac_address, data.get('ip'), data.get('os_info'), now, 'online', server_id)
        )
    else:
        cursor = db.execute(
            'INSERT INTO servers (hostname, mac_address, ip, os_info, last_seen, status) VALUES (?,?,?,?,?,?)',
            (hostname, mac_address, data.get('ip'), data.get('os_info'), now, 'online')
        )
        server_id = cursor.lastrowid
        if report_user_id is not None:
            db.execute(
                'INSERT OR IGNORE INTO user_server_access (user_id, server_id) VALUES (?, ?)',
                (report_user_id, server_id)
            )

    # Insert metric / 插入指标数据
    db.execute(
        '''INSERT INTO metrics
           (server_id, timestamp, cpu_percent, cpu_count,
            memory_total, memory_used, memory_percent,
            disk_total, disk_used, disk_percent,
            gpu_data, network_sent, network_recv, errors)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (server_id, now,
         data.get('cpu_percent'), data.get('cpu_count'),
         data.get('memory_total'), data.get('memory_used'), data.get('memory_percent'),
         data.get('disk_total'), data.get('disk_used'), data.get('disk_percent'),
         json.dumps(data.get('gpu_data', [])),
         data.get('network_sent'), data.get('network_recv'),
         json.dumps(data.get('errors', [])))
    )
    db.commit()

    # Clean up expired data / 清理过期数据
    cutoff = (datetime.now() - timedelta(days=CONFIG['data']['retention_days'])).isoformat()
    db.execute('DELETE FROM metrics WHERE timestamp < ?', (cutoff,))
    db.commit()

    return jsonify({'status': 'ok'})


# ---------------------------------------------------------------------------
# Helpers / 辅助函数
# ---------------------------------------------------------------------------

def _build_server_data(user):
    """Build server data list filtered by user permissions.
    构建按用户权限过滤的服务器数据列表。"""
    db = get_db()

    if user['role'] == 'admin':
        servers = db.execute(
            '''SELECT * FROM servers
               ORDER BY COALESCE(NULLIF(display_name, ''), hostname)'''
        ).fetchall()
    else:
        servers = db.execute(
            '''SELECT s.* FROM servers s
               JOIN user_server_access usa ON s.id = usa.server_id
               WHERE usa.user_id = ?
               ORDER BY COALESCE(NULLIF(s.display_name, ''), s.hostname)''',
            (user['id'],)
        ).fetchall()

    can_view_procs = bool(user.get('can_view_processes'))
    server_ids = [s['id'] for s in servers]
    gpu_status_map = _load_gpu_admin_status_map(db, server_ids)
    user_gpu_map = {}
    if user['role'] != 'admin':
        user_gpu_map = _load_user_gpu_access_map(db, user['id'])
    alias_rows = db.execute(
        'SELECT server_id, alias_name FROM user_server_preferences WHERE user_id = ?',
        (user['id'],)
    ).fetchall()
    alias_map = {r['server_id']: r['alias_name'] for r in alias_rows if r['alias_name']}
    result = []

    for s in servers:
        latest = db.execute(
            'SELECT * FROM metrics WHERE server_id = ? ORDER BY timestamp DESC LIMIT 1',
            (s['id'],)
        ).fetchone()

        # Determine effective status / 计算有效状态
        admin_status = s['admin_status'] if 'admin_status' in s.keys() else 'normal'
        admin_note = s['admin_status_note'] if 'admin_status_note' in s.keys() else ''

        last_seen = None
        agent_online = False
        if s['last_seen']:
            try:
                last_seen = datetime.fromisoformat(s['last_seen'])
                agent_online = (datetime.now() - last_seen).total_seconds() < 120
            except ValueError:
                pass

        # Parse errors from latest metric
        errors = []
        if latest:
            try:
                errors = json.loads(latest['errors']) if latest['errors'] else []
            except (json.JSONDecodeError, KeyError):
                pass

        # Status priority: admin override > offline > warning > online
        if admin_status in ('maintenance', 'fault'):
            effective_status = admin_status
        elif not agent_online:
            effective_status = 'offline'
        elif errors:
            effective_status = 'warning'
        else:
            effective_status = 'online'

        user_alias = alias_map.get(s['id'], '')
        display_name = s['display_name'] or ''
        display_hostname = user_alias or display_name or s['hostname']

        info = {
            'id':                s['id'],
            'hostname':          display_hostname,
            'display_hostname':  display_hostname,
            'raw_hostname':      s['hostname'],
            'display_name':      display_name,
            'user_alias':        user_alias,
            'mac_address':       s['mac_address'] if 'mac_address' in s.keys() else None,
            'ip':                s['ip'],
            'os_info':           s['os_info'],
            'status':            effective_status,
            'admin_status':      admin_status,
            'admin_status_note': admin_note,
            'last_seen':         s['last_seen'],
            'errors':            errors,
            'metrics':           None,
        }

        if latest:
            gpu_data = json.loads(latest['gpu_data']) if latest['gpu_data'] else []
            allowed_gpu_bus_ids = None
            if user['role'] != 'admin' and s['id'] in user_gpu_map:
                allowed_gpu_bus_ids = user_gpu_map[s['id']]
            merged_gpu_data = []
            for gpu in gpu_data:
                bus_id = _normalize_bus_id(gpu.get('bus_id'))
                if allowed_gpu_bus_ids is not None and bus_id not in allowed_gpu_bus_ids:
                    continue
                st, note = gpu_status_map.get((s['id'], bus_id), ('normal', ''))
                gpu['bus_id'] = bus_id or gpu.get('bus_id')
                gpu['admin_status'] = st
                gpu['admin_status_note'] = note
                merged_gpu_data.append(gpu)
            gpu_data = merged_gpu_data

            # Strip processes if user lacks permission / 无权限时去除进程列表
            if not can_view_procs:
                for gpu in gpu_data:
                    gpu.pop('processes', None)

            info['metrics'] = {
                'cpu_percent':    latest['cpu_percent'],
                'cpu_count':      latest['cpu_count'],
                'memory_total':   latest['memory_total'],
                'memory_used':    latest['memory_used'],
                'memory_percent': latest['memory_percent'],
                'disk_total':     latest['disk_total'],
                'disk_used':      latest['disk_used'],
                'disk_percent':   latest['disk_percent'],
                'gpu_data':       gpu_data,
                'network_sent':   latest['network_sent'],
                'network_recv':   latest['network_recv'],
                'timestamp':      latest['timestamp'],
            }

        result.append(info)
    return result


# ---------------------------------------------------------------------------
# Entry point / 入口
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    app.run(
        host=CONFIG['server']['host'],
        port=CONFIG['server']['port'],
        debug=CONFIG['server'].get('debug', False)
    )
