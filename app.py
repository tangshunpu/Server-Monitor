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
    db.execute('PRAGMA foreign_keys = ON')

    # --- Existing tables ---
    db.execute('''CREATE TABLE IF NOT EXISTS servers (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname    TEXT NOT NULL UNIQUE,
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
    db.execute('''CREATE TABLE IF NOT EXISTS invites (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        token               TEXT NOT NULL UNIQUE,
        role                TEXT NOT NULL DEFAULT 'user',
        can_view_processes  INTEGER DEFAULT 0,
        server_ids          TEXT,
        created_by          INTEGER,
        created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at          TIMESTAMP,
        used_by             INTEGER
    )''')

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


# ---------------------------------------------------------------------------
# Auth helpers / 认证辅助
# ---------------------------------------------------------------------------
login_attempts: dict = {}  # ip -> [timestamp, ...]


def _generate_password(length=12):
    """Generate a random password / 生成随机密码"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


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
    if invite['used_by'] is not None:
        flash('This invite has already been used / 该邀请链接已被使用', 'error')
        return redirect(url_for('login'))
    if invite['expires_at'] and datetime.fromisoformat(invite['expires_at']) < datetime.now():
        flash('This invite has expired / 该邀请链接已过期', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        errors = []
        if not username or len(username) < 2:
            errors.append('Username must be at least 2 characters / 用户名至少 2 个字符')
        if not password or len(password) < 6:
            errors.append('Password must be at least 6 characters / 密码至少 6 个字符')
        if password != confirm:
            errors.append('Passwords do not match / 两次密码不一致')

        # Check username uniqueness
        existing = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing:
            errors.append('Username already taken / 用户名已被使用')

        if errors:
            for e in errors:
                flash(e, 'error')
            return render_template('register.html', token=token)

        # Create user with invite permissions
        pw_hash = generate_password_hash(password)
        cursor = db.execute(
            'INSERT INTO users (username, password_hash, role, can_view_processes, created_by) '
            'VALUES (?, ?, ?, ?, ?)',
            (username, pw_hash, invite['role'], invite['can_view_processes'],
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

        # Mark invite as used
        db.execute('UPDATE invites SET used_by = ? WHERE id = ?', (new_user_id, invite['id']))
        db.commit()

        flash('Registration successful! Please log in. / 注册成功！请登录。', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', token=token)


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

    result = []
    for m in rows:
        gpu_data = json.loads(m['gpu_data']) if m['gpu_data'] else []
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
# Admin page / 管理页面
# ---------------------------------------------------------------------------

@app.route('/admin')
@admin_required
def admin_page():
    return render_template('admin.html', current_user=g.user)


# ---------------------------------------------------------------------------
# Admin API — Users / 管理 API — 用户
# ---------------------------------------------------------------------------

@app.route('/api/admin/users')
@admin_required
def api_admin_list_users():
    db = get_db()
    users = db.execute(
        'SELECT id, username, role, can_view_processes, created_at FROM users ORDER BY id'
    ).fetchall()

    result = []
    for u in users:
        # Get server access list
        access = db.execute(
            'SELECT server_id FROM user_server_access WHERE user_id = ?', (u['id'],)
        ).fetchall()
        server_ids = [a['server_id'] for a in access]

        result.append({
            'id':                 u['id'],
            'username':           u['username'],
            'role':               u['role'],
            'can_view_processes': u['can_view_processes'],
            'server_ids':         server_ids,
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
    role = data.get('role', 'user')
    can_view = 1 if data.get('can_view_processes') else 0
    server_ids = data.get('server_ids', [])

    db = get_db()
    existing = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    if existing:
        return jsonify({'error': 'Username already exists / 用户名已存在'}), 409

    password = _generate_password()
    pw_hash = generate_password_hash(password)

    cursor = db.execute(
        'INSERT INTO users (username, password_hash, role, can_view_processes, created_by) '
        'VALUES (?, ?, ?, ?, ?)',
        (username, pw_hash, role, can_view, g.user['id'])
    )
    new_id = cursor.lastrowid

    for sid in server_ids:
        db.execute(
            'INSERT OR IGNORE INTO user_server_access (user_id, server_id) VALUES (?, ?)',
            (new_id, sid)
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

        result.append({
            'id':                 inv['id'],
            'token':              inv['token'],
            'role':               inv['role'],
            'can_view_processes': inv['can_view_processes'],
            'server_ids':         json.loads(inv['server_ids']) if inv['server_ids'] else [],
            'created_at':         inv['created_at'],
            'expires_at':         inv['expires_at'],
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

    token = secrets.token_urlsafe(32)
    expires_at = (datetime.now() + timedelta(hours=expire_hours)).isoformat()

    db = get_db()
    db.execute(
        'INSERT INTO invites (token, role, can_view_processes, server_ids, created_by, expires_at) '
        'VALUES (?, ?, ?, ?, ?, ?)',
        (token, role, can_view, json.dumps(server_ids), g.user['id'], expires_at)
    )
    db.commit()

    # Build full URL
    invite_url = f"{request.scheme}://{request.host}/register?token={token}"

    return jsonify({'token': token, 'url': invite_url, 'expires_at': expires_at})


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
    servers = db.execute('SELECT id, hostname, ip, admin_status, admin_status_note FROM servers ORDER BY hostname').fetchall()
    return jsonify([{
        'id': s['id'], 'hostname': s['hostname'], 'ip': s['ip'],
        'admin_status': s['admin_status'] or 'normal',
        'admin_status_note': s['admin_status_note'] or '',
    } for s in servers])


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
    if not hmac.compare_digest(token, CONFIG['agent']['token']):
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    if not data or 'hostname' not in data:
        return jsonify({'error': 'Invalid data'}), 400

    db = get_db()
    now = datetime.now().isoformat()

    # Upsert server / 更新或插入服务器记录
    server = db.execute(
        'SELECT id FROM servers WHERE hostname = ?',
        (data['hostname'],)
    ).fetchone()

    if server:
        server_id = server['id']
        db.execute(
            'UPDATE servers SET ip=?, os_info=?, last_seen=?, status=? WHERE id=?',
            (data.get('ip'), data.get('os_info'), now, 'online', server_id)
        )
    else:
        cursor = db.execute(
            'INSERT INTO servers (hostname, ip, os_info, last_seen, status) VALUES (?,?,?,?,?)',
            (data['hostname'], data.get('ip'), data.get('os_info'), now, 'online')
        )
        server_id = cursor.lastrowid

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
        servers = db.execute('SELECT * FROM servers ORDER BY hostname').fetchall()
    else:
        servers = db.execute(
            '''SELECT s.* FROM servers s
               JOIN user_server_access usa ON s.id = usa.server_id
               WHERE usa.user_id = ?
               ORDER BY s.hostname''',
            (user['id'],)
        ).fetchall()

    can_view_procs = bool(user.get('can_view_processes'))
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

        info = {
            'id':                s['id'],
            'hostname':          s['hostname'],
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
