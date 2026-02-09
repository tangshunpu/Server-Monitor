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
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

import yaml
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
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
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
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Auth helpers / 认证辅助
# ---------------------------------------------------------------------------
login_attempts: dict = {}  # ip -> [timestamp, ...]


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
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

        # Rate limit: max 5 attempts within 5 minutes / 速率限制：5 分钟内最多 5 次
        if len(login_attempts.get(ip, [])) >= 5:
            flash('Too many attempts, please try again in 5 minutes / 尝试次数过多，请 5 分钟后再试', 'error')
            return render_template('login.html')

        password = request.form.get('password', '')
        if hmac.compare_digest(password, CONFIG['auth']['password']):
            session.permanent = True
            session['logged_in'] = True
            login_attempts.pop(ip, None)
            return redirect(url_for('dashboard'))
        else:
            login_attempts.setdefault(ip, []).append(now)
            flash('Incorrect password / 密码错误', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def dashboard():
    server_data = _build_server_data()
    return render_template('dashboard.html', servers=server_data)


# ---------------------------------------------------------------------------
# API Routes — Dashboard (session auth) / 仪表盘 API（会话认证）
# ---------------------------------------------------------------------------

@app.route('/api/servers')
@login_required
def api_servers():
    return jsonify(_build_server_data())


@app.route('/api/servers/<int:server_id>/history')
@login_required
def api_server_history(server_id):
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
        result.append({
            'timestamp':      m['timestamp'],
            'cpu_percent':    m['cpu_percent'],
            'memory_percent': m['memory_percent'],
            'disk_percent':   m['disk_percent'],
            'gpu_data':       gpu_data,
        })
    return jsonify(result)


@app.route('/api/servers/<int:server_id>', methods=['DELETE'])
@login_required
def api_delete_server(server_id):
    db = get_db()
    db.execute('DELETE FROM metrics WHERE server_id = ?', (server_id,))
    db.execute('DELETE FROM servers WHERE id = ?', (server_id,))
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
            gpu_data, network_sent, network_recv)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (server_id, now,
         data.get('cpu_percent'), data.get('cpu_count'),
         data.get('memory_total'), data.get('memory_used'), data.get('memory_percent'),
         data.get('disk_total'), data.get('disk_used'), data.get('disk_percent'),
         json.dumps(data.get('gpu_data', [])),
         data.get('network_sent'), data.get('network_recv'))
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

def _build_server_data():
    db = get_db()
    servers = db.execute('SELECT * FROM servers ORDER BY hostname').fetchall()
    result = []

    for s in servers:
        latest = db.execute(
            'SELECT * FROM metrics WHERE server_id = ? ORDER BY timestamp DESC LIMIT 1',
            (s['id'],)
        ).fetchone()

        last_seen = None
        is_online = False
        if s['last_seen']:
            try:
                last_seen = datetime.fromisoformat(s['last_seen'])
                is_online = (datetime.now() - last_seen).total_seconds() < 120
            except ValueError:
                pass

        info = {
            'id':        s['id'],
            'hostname':  s['hostname'],
            'ip':        s['ip'],
            'os_info':   s['os_info'],
            'status':    'online' if is_online else 'offline',
            'last_seen': s['last_seen'],
            'metrics':   None,
        }

        if latest:
            gpu_data = json.loads(latest['gpu_data']) if latest['gpu_data'] else []
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
