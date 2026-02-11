#!/usr/bin/env python3
"""
Server Monitor Agent
Run this script on each monitored server to periodically report system status
to the central monitor server.
在每台被监控的服务器上运行此脚本，定期将系统状态上报到监控主服务器。

Usage / 用法:
    python agent.py -c agent_config.yaml
    python agent.py --config agent_config.yaml --interval 60
"""

import os
import sys
import time
import json
import socket
import platform
import subprocess
import argparse
import logging
import threading
import re

import psutil
import requests
import yaml

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger(__name__)
AGENT_VERSION = 'beta1.1'
GLOBAL_HTTP_PROXY = None
NETWORK_HEALTH_LOCK = threading.Lock()
NETWORK_HEALTH_CACHE = {
    'network_cn_ok': None,
    'network_cn_detail': 'pending',
    'network_global_ok': None,
    'network_global_detail': 'pending',
}
NETWORK_TEST_RETRY_SECONDS = 30
NETWORK_TEST_SUCCESS_PAUSE_SECONDS = 300
DEFAULT_GLOBAL_HTTP_PROXY = 'http://127.0.0.1:7890'


# ---------------------------------------------------------------------------
# Helper / 辅助函数
# ---------------------------------------------------------------------------

def safe_float(val):
    """Safely convert nvidia-smi output to float, handling [N/A] etc.
    将 nvidia-smi 输出的值安全转换为 float，处理 [N/A] 等情况"""
    if val is None:
        return None
    val = str(val).strip()
    if val in ('[N/A]', 'N/A', '[Not Supported]', 'Not Supported', ''):
        return None
    try:
        return float(val)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Process owner detection (user & container) / 进程归属检测（用户 & 容器）
# ---------------------------------------------------------------------------

def _get_process_owner(pid):
    """Get the username and LXC/Incus container name for a process.
    获取进程的用户名和 LXC/Incus 容器名。
    Returns (username, container) where container may be None.
    返回 (用户名, 容器名)，容器名可能为 None。"""
    username = 'unknown'
    container = None

    # 1) Get username via ps / 通过 ps 获取用户名
    try:
        result = subprocess.run(
            ['ps', '-o', 'user=', '-p', str(pid)],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            username = result.stdout.strip()
    except Exception:
        pass

    # 2) Detect LXC/Incus container via cgroup / 通过 cgroup 检测 LXC/Incus 容器
    try:
        cgroup_path = f'/proc/{pid}/cgroup'
        with open(cgroup_path, 'r') as f:
            content = f.read()

        # Common cgroup paths seen in LXC/Incus:
        # - /incus.payload/<name>/...
        # - /lxc.payload/<name>/...
        # - /incus.payload.<name>/...
        # - /lxc.payload.<name>/...
        # - /incus/<name>/..., /lxc/<name>/...
        # - /machine.slice/incus-<name>.scope (systemd style)
        patterns = (
            r'/(?:incus|lxc)\.payload/([^/\n]+)',
            r'/(?:incus|lxc)\.payload\.([^/\n]+)',
            r'/(?:incus|lxc)/([^/\n]+)',
            r'/incus-([^/\n.]+)\.scope',
            r'/lxc-([^/\n.]+)\.scope',
        )

        for line in content.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            for pattern in patterns:
                m = re.search(pattern, line)
                if m:
                    candidate = m.group(1).strip()
                    if candidate and candidate not in ('init.scope',):
                        container = candidate
                        break
            if container:
                break
    except (FileNotFoundError, PermissionError):
        pass
    except Exception:
        pass

    return username, container


# ---------------------------------------------------------------------------
# GPU Info Collection (via nvidia-smi) / GPU 信息采集（通过 nvidia-smi）
# ---------------------------------------------------------------------------

def get_gpu_info():
    """Get GPU info and process list via nvidia-smi.
    通过 nvidia-smi 获取 GPU 信息和进程列表。
    Returns (gpus_list, nvidia_smi_error_or_None)."""
    gpus = []
    try:
        # 1) Basic GPU info / GPU 基本信息
        result = subprocess.run(
            [
                'nvidia-smi',
                '--query-gpu=index,name,temperature.gpu,utilization.gpu,'
                'memory.total,memory.used,memory.free,utilization.memory,'
                'power.draw,power.limit,gpu_bus_id',
                '--format=csv,noheader,nounits',
            ],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return gpus, {'type': 'gpu', 'index': -1,
                          'message': f'nvidia-smi failed (exit {result.returncode}): {result.stderr.strip()[:200]}'}

        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 11:
                gpus.append({
                    'index':              int(parts[0]),
                    'name':               parts[1],
                    'temperature':        safe_float(parts[2]),
                    'gpu_utilization':    safe_float(parts[3]),
                    'memory_total':       safe_float(parts[4]),
                    'memory_used':        safe_float(parts[5]),
                    'memory_free':        safe_float(parts[6]),
                    'memory_utilization': safe_float(parts[7]),
                    'power_draw':         safe_float(parts[8]),
                    'power_limit':        safe_float(parts[9]),
                    'bus_id':             parts[10],
                    'processes':          [],
                })

        # 2) Processes running on GPU / GPU 上运行的进程
        result2 = subprocess.run(
            [
                'nvidia-smi',
                '--query-compute-apps=gpu_bus_id,pid,used_memory,process_name',
                '--format=csv,noheader,nounits',
            ],
            capture_output=True, text=True, timeout=10,
        )
        if result2.returncode == 0 and result2.stdout.strip():
            bus_id_map = {g['bus_id']: i for i, g in enumerate(gpus)}
            for line in result2.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 4:
                    idx = bus_id_map.get(parts[0])
                    if idx is not None:
                        pid = int(parts[1])
                        username, container = _get_process_owner(pid)
                        gpus[idx]['processes'].append({
                            'pid':          pid,
                            'memory_used':  safe_float(parts[2]),
                            'process_name': parts[3],
                            'username':     username,
                            'container':    container,
                        })

    except FileNotFoundError:
        # nvidia-smi not found, skip GPU monitoring
        # nvidia-smi 未找到，跳过 GPU 监控
        logger.info("nvidia-smi not found, skipping GPU monitoring / nvidia-smi 未找到，跳过 GPU 监控")
        return gpus, None
    except subprocess.TimeoutExpired:
        logger.warning("nvidia-smi timed out / nvidia-smi 超时")
        return gpus, {'type': 'gpu', 'index': -1, 'message': 'nvidia-smi timed out'}
    except Exception as e:
        logger.warning(f"GPU info collection error / GPU 信息采集异常: {e}")
        return gpus, {'type': 'gpu', 'index': -1, 'message': f'nvidia-smi error: {e}'}

    return gpus, None


# ---------------------------------------------------------------------------
# Network helpers / 网络辅助
# ---------------------------------------------------------------------------

def _is_private_ip(addr):
    """Check if an IP address is a private/internal address.
    判断 IP 是否为内网地址。"""
    parts = addr.split('.')
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    return (a == 10
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168))


def _get_private_ip():
    """Get the private/internal IP address of this machine.
    获取本机内网 IP 地址。优先返回 10.x 开头的地址。"""
    candidates = []
    try:
        # Collect all interface addresses / 收集所有网卡地址
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address != '127.0.0.1':
                    if _is_private_ip(addr.address):
                        candidates.append(addr.address)
    except Exception:
        pass

    if candidates:
        # Prefer 10.x addresses / 优先 10.x 地址
        for c in candidates:
            if c.startswith('10.'):
                return c
        return candidates[0]

    # Fallback: use default route / 兜底：通过默认路由获取
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return 'unknown'


def _normalize_mac(mac):
    """Normalize MAC address string to aa:bb:cc:dd:ee:ff.
    规范化 MAC 地址为 aa:bb:cc:dd:ee:ff。"""
    if not mac:
        return None
    hex_digits = ''.join(ch for ch in str(mac) if ch.isalnum()).lower()
    if len(hex_digits) != 12 or any(ch not in '0123456789abcdef' for ch in hex_digits):
        return None
    return ':'.join(hex_digits[i:i + 2] for i in range(0, 12, 2))


def _get_primary_mac():
    """Get primary MAC address from active non-loopback interfaces.
    获取活跃非回环网卡的主 MAC 地址。"""
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        af_link = getattr(psutil, 'AF_LINK', None)
        candidates = []
        for if_name, if_addrs in addrs.items():
            iface_stat = stats.get(if_name)
            if iface_stat and not iface_stat.isup:
                continue
            if if_name.lower().startswith(('lo', 'docker', 'veth', 'br-')):
                continue
            for addr in if_addrs:
                if af_link is not None and addr.family == af_link:
                    mac = _normalize_mac(addr.address)
                    if mac and mac != '00:00:00:00:00:00':
                        candidates.append((if_name, mac))
        if candidates:
            candidates.sort(key=lambda x: (0 if x[0].startswith(('eth', 'en')) else 1, x[0]))
            return candidates[0][1]
    except Exception:
        pass
    return None


def _check_network_connectivity():
    """Check domestic/international connectivity using curl only.
    使用 curl 检查国内/国际网络连通性。"""
    result = {
        'network_cn_ok': None,
        'network_cn_detail': '',
        'network_global_ok': None,
        'network_global_detail': '',
    }

    # Domestic check: curl baidu.com / 国内检测：curl baidu.com
    cn_cmd = [
        'curl', '-L', '--max-time', '5', '-o', '/dev/null', '-sS',
        '-w', '%{http_code}', 'https://www.baidu.com'
    ]
    try:
        out = subprocess.run(cn_cmd, capture_output=True, text=True, timeout=7)
        http_code = (out.stdout or '').strip()
        code_num = int(http_code) if http_code.isdigit() else None
        # Prefer curl exit code; use HTTP code as auxiliary signal.
        cn_ok = (out.returncode == 0) and (code_num is None or code_num < 500)
        result['network_cn_ok'] = cn_ok
        if cn_ok:
            result['network_cn_detail'] = f'HTTP {http_code or "N/A"}'
        else:
            err = (out.stderr or '').strip()
            result['network_cn_detail'] = (err or f'curl exit {out.returncode}, HTTP {http_code or "N/A"}')[:160]
    except FileNotFoundError:
        result['network_cn_ok'] = False
        result['network_cn_detail'] = 'curl command not found'
    except subprocess.TimeoutExpired:
        result['network_cn_ok'] = False
        result['network_cn_detail'] = 'curl timed out'

    # Global check: try multiple sites directly; if all fail, retry via proxy.
    # 国际检测：先直连多个站点；若都失败则自动走代理重试。
    global_urls = [
        'https://www.google.com/generate_204',
        'https://www.cloudflare.com/cdn-cgi/trace',
        'https://www.wikipedia.org',
    ]

    def _run_global_round(proxy=None):
        mode = f'proxy({proxy})' if proxy else 'direct'
        last_err = ''
        for url in global_urls:
            cmd = [
                'curl', '-L', '--max-time', '6', '-o', '/dev/null', '-sS',
                '-w', '%{http_code}',
            ]
            if proxy:
                cmd.extend(['-x', proxy])
            cmd.append(url)
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            except FileNotFoundError:
                return False, 'curl command not found'
            except subprocess.TimeoutExpired:
                last_err = f'{mode} {url}: curl timed out'
                continue

            http_code = (out.stdout or '').strip()
            code_num = int(http_code) if http_code.isdigit() else None
            ok = (out.returncode == 0) and (code_num is None or code_num < 500)
            if ok:
                return True, f'{mode} {url}: HTTP {http_code or "N/A"}'
            err = (out.stderr or '').strip()
            fallback_err = f'curl exit {out.returncode}, HTTP {http_code or "N/A"}'
            last_err = f'{mode} {url}: {(err or fallback_err)[:80]}'
        return False, last_err or f'{mode}: all targets failed'

    global_ok, global_detail = _run_global_round(proxy=None)
    if not global_ok:
        retry_proxy = (GLOBAL_HTTP_PROXY or DEFAULT_GLOBAL_HTTP_PROXY).strip()
        proxy_ok, proxy_detail = _run_global_round(proxy=retry_proxy)
        global_ok = proxy_ok
        global_detail = proxy_detail if proxy_ok else f'{global_detail}; retry failed: {proxy_detail}'

    result['network_global_ok'] = global_ok
    result['network_global_detail'] = global_detail[:160]

    return result


def _set_network_health_cache(net_health):
    """Update shared network health cache.
    更新共享网络连通性缓存。"""
    with NETWORK_HEALTH_LOCK:
        NETWORK_HEALTH_CACHE.update({
            'network_cn_ok': net_health.get('network_cn_ok'),
            'network_cn_detail': net_health.get('network_cn_detail', ''),
            'network_global_ok': net_health.get('network_global_ok'),
            'network_global_detail': net_health.get('network_global_detail', ''),
        })


def _get_network_health_cache():
    """Read shared network health cache.
    读取共享网络连通性缓存。"""
    with NETWORK_HEALTH_LOCK:
        return {
            'network_cn_ok': NETWORK_HEALTH_CACHE.get('network_cn_ok'),
            'network_cn_detail': NETWORK_HEALTH_CACHE.get('network_cn_detail', ''),
            'network_global_ok': NETWORK_HEALTH_CACHE.get('network_global_ok'),
            'network_global_detail': NETWORK_HEALTH_CACHE.get('network_global_detail', ''),
        }


def _network_test_worker(stop_event):
    """Run network tests in background, independent from report loop.
    在后台执行网络测试，与上报循环解耦。"""
    while not stop_event.is_set():
        net_health = _check_network_connectivity()
        _set_network_health_cache(net_health)

        both_ok = (net_health.get('network_cn_ok') is True
                   and net_health.get('network_global_ok') is True)
        sleep_seconds = (NETWORK_TEST_SUCCESS_PAUSE_SECONDS
                         if both_ok else NETWORK_TEST_RETRY_SECONDS)
        stop_event.wait(sleep_seconds)


# ---------------------------------------------------------------------------
# Disk helpers (ZFS-aware) / 磁盘辅助（ZFS 感知）
# ---------------------------------------------------------------------------

def _get_disk_usage():
    """Get total disk usage, preferring ZFS pool if available.
    获取总磁盘使用量，优先使用 ZFS 池。"""
    try:
        result = subprocess.run(
            ['zpool', 'list', '-Hp', '-o', 'name,size,alloc,free,cap'],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            total_bytes, used_bytes = 0, 0
            for line in result.stdout.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) >= 4:
                    total_bytes += int(parts[1])
                    used_bytes += int(parts[2])
            if total_bytes > 0:
                pct = round(used_bytes / total_bytes * 100, 1)
                return (round(total_bytes / (1024 ** 3), 2),
                        round(used_bytes / (1024 ** 3), 2),
                        pct)
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.warning(f"ZFS detection error / ZFS 检测异常: {e}")

    # Fallback to root partition / 回退到根分区
    disk = psutil.disk_usage('/')
    return (round(disk.total / (1024 ** 3), 2),
            round(disk.used / (1024 ** 3), 2),
            disk.percent)


def _check_zfs_health():
    """Check ZFS pool health status, return errors list.
    检查 ZFS 池健康状态，返回错误列表。"""
    errors = []
    try:
        result = subprocess.run(
            ['zpool', 'status', '-x'],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            output = result.stdout.strip()
            # "all pools are healthy" means no issues
            if 'all pools are healthy' not in output.lower():
                # Parse degraded / faulted pools
                for line in output.split('\n'):
                    line = line.strip()
                    if line.startswith('pool:'):
                        pool_name = line.split(':', 1)[1].strip()
                    elif line.startswith('state:'):
                        state = line.split(':', 1)[1].strip()
                        if state.upper() in ('DEGRADED', 'FAULTED', 'UNAVAIL'):
                            errors.append({
                                'type': 'disk',
                                'message': f'ZFS pool "{pool_name}": {state}',
                            })
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return errors


# ---------------------------------------------------------------------------
# Container listing (LXC / Incus) / 容器列表（LXC / Incus）
# ---------------------------------------------------------------------------

def _list_containers():
    """List LXC/Incus containers, trying lxc first, then incus if empty.
    列出 LXC/Incus 容器，优先使用 lxc，若为空则尝试 incus。
    Returns (containers_list, engine_name_or_None)."""

    def _try_list(cmd_prefix):
        """Run `<cmd_prefix> list --format json` and parse the result."""
        try:
            result = subprocess.run(
                [cmd_prefix, 'list', '--format', 'json'],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return None  # command failed
            raw = result.stdout.strip()
            if not raw or raw == '[]':
                return []  # empty list
            data = json.loads(raw)
            containers = []
            for ct in data:
                # Extract IPv4 addresses from network state
                ipv4_addrs = []
                net_state = ct.get('state', {}).get('network') or {}
                for _iface_name, iface in net_state.items():
                    for addr in iface.get('addresses', []):
                        if (addr.get('family') == 'inet'
                                and addr.get('scope') == 'global'):
                            ipv4_addrs.append(addr.get('address'))
                state = ct.get('state', {}) or {}
                memory = state.get('memory', {}) or {}
                disk = state.get('disk', {}) or {}
                root_disk = disk.get('root', {}) if isinstance(disk.get('root', {}), dict) else {}
                cpu_state = state.get('cpu', {}) or {}
                ct_name = ct.get('name', '')
                containers.append({
                    'name':   ct_name,
                    'status': ct.get('status', ''),
                    'type':   ct.get('type', ''),
                    'ipv4':   ipv4_addrs,
                    'process_count': state.get('processes'),
                    'memory_usage_bytes': memory.get('usage'),
                    'memory_total_bytes': memory.get('usage_peak'),
                    'disk_usage_bytes': root_disk.get('usage'),
                    'disk_total_bytes': root_disk.get('total'),
                    'cpu_usage_ns': cpu_state.get('usage'),
                })
            return containers
        except FileNotFoundError:
            return None  # command not found
        except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception) as e:
            logger.debug(f"{cmd_prefix} list error: {e}")
            return None

    # 1) Try lxc first / 先尝试 lxc
    containers = _try_list('lxc')
    if containers:
        return containers, 'lxc'

    # 2) If lxc is empty or unavailable, try incus / 若 lxc 为空或不可用，尝试 incus
    containers = _try_list('incus')
    if containers:
        return containers, 'incus'

    # 3) Neither worked or both are empty / 都不可用或都为空
    return [], None


# ---------------------------------------------------------------------------
# Fault detection / 故障检测
# ---------------------------------------------------------------------------

def _detect_gpu_errors(gpus):
    """Detect GPU faults: critical temperature, nvidia-smi failures.
    检测 GPU 故障：过高温度、nvidia-smi 失败等。"""
    errors = []
    for gpu in gpus:
        temp = gpu.get('temperature')
        if temp is not None and temp >= 95:
            errors.append({
                'type': 'gpu',
                'index': gpu['index'],
                'message': f"GPU {gpu['index']}: temperature critical ({temp}°C)",
            })
    return errors


# ---------------------------------------------------------------------------
# System Metrics Collection / 系统指标采集
# ---------------------------------------------------------------------------

def collect_metrics():
    """Collect all system metrics from the current server.
    采集当前服务器的全部系统指标。"""
    errors = []

    # CPU
    cpu_percent = psutil.cpu_percent(interval=1)
    cpu_count = psutil.cpu_count()

    # Memory / 内存
    mem = psutil.virtual_memory()

    # Disk (ZFS-aware) / 磁盘（ZFS 感知）
    disk_total, disk_used, disk_percent = _get_disk_usage()

    # ZFS health check / ZFS 健康检查
    errors.extend(_check_zfs_health())

    # Network / 网络
    net = psutil.net_io_counters()
    net_health = _get_network_health_cache()

    # GPU
    gpu_data, gpu_err = get_gpu_info()
    if gpu_err:
        errors.append(gpu_err)

    # GPU error detection (temperature etc.) / GPU 错误检测（温度等）
    errors.extend(_detect_gpu_errors(gpu_data))

    # Containers (LXC / Incus) / 容器列表
    containers, container_engine = _list_containers()

    # Operating system / 操作系统
    os_info = f"{platform.system()} {platform.release()}"

    # Local IP (prefer private/internal address) / 本机 IP（优先内网地址）
    ip = _get_private_ip()

    return {
        'hostname':       socket.gethostname(),
        'mac_address':    _get_primary_mac(),
        'agent_version':  AGENT_VERSION,
        'ip':             ip,
        'os_info':        os_info,
        'cpu_percent':    cpu_percent,
        'cpu_count':      cpu_count,
        'memory_total':   round(mem.total / (1024 ** 3), 2),
        'memory_used':    round(mem.used / (1024 ** 3), 2),
        'memory_percent': mem.percent,
        'disk_total':     disk_total,
        'disk_used':      disk_used,
        'disk_percent':   disk_percent,
        'gpu_data':       gpu_data,
        'containers':     containers,
        'container_engine': container_engine,
        'network_sent':   round(net.bytes_sent / (1024 ** 3), 2),
        'network_recv':   round(net.bytes_recv / (1024 ** 3), 2),
        'network_cn_ok':          net_health['network_cn_ok'],
        'network_cn_detail':      net_health['network_cn_detail'],
        'network_global_ok':      net_health['network_global_ok'],
        'network_global_detail':  net_health['network_global_detail'],
        'errors':         errors,
    }


# ---------------------------------------------------------------------------
# Main loop / 主循环
# ---------------------------------------------------------------------------

def main():
    global GLOBAL_HTTP_PROXY
    parser = argparse.ArgumentParser(description='Server Monitor Agent')
    parser.add_argument('-c', '--config', default='agent_config.yaml',
                        help='Config file path (default: agent_config.yaml) / '
                             '配置文件路径（默认: agent_config.yaml）')
    parser.add_argument('-i', '--interval', type=int, default=None,
                        help='Reporting interval in seconds (overrides config) / '
                             '上报间隔秒数（覆盖配置文件）')
    args = parser.parse_args()

    # Load config / 加载配置
    config_path = args.config
    if not os.path.isabs(config_path):
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), config_path)

    with open(config_path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    server_url = config['server_url'].rstrip('/')
    token = config['token']
    interval = args.interval or config.get('interval', 30)
    GLOBAL_HTTP_PROXY = (config.get('global_http_proxy') or '').strip() or None

    logger.info(f"Agent started — reporting to: {server_url}, interval: {interval}s / "
                f"Agent 启动 — 上报地址: {server_url}, 间隔: {interval}s")
    if GLOBAL_HTTP_PROXY:
        logger.info(f"Global connectivity check proxy enabled: {GLOBAL_HTTP_PROXY}")

    network_stop_event = threading.Event()
    network_worker = threading.Thread(
        target=_network_test_worker,
        args=(network_stop_event,),
        daemon=True,
    )
    network_worker.start()
    logger.info(
        "Background network test started (retry: %ss, success pause: %ss)",
        NETWORK_TEST_RETRY_SECONDS,
        NETWORK_TEST_SUCCESS_PAUSE_SECONDS,
    )

    try:
        while True:
            try:
                metrics = collect_metrics()
                resp = requests.post(
                    f"{server_url}/api/report",
                    json=metrics,
                    headers={'Authorization': f'Bearer {token}'},
                    timeout=15,
                )
                if resp.status_code == 200:
                    logger.info(f"Report OK (CPU: {metrics['cpu_percent']}%, "
                                f"MEM: {metrics['memory_percent']}%, "
                                f"GPUs: {len(metrics['gpu_data'])}) / 上报成功")
                else:
                    logger.warning(f"Report failed / 上报失败: HTTP {resp.status_code} — {resp.text}")
            except requests.ConnectionError:
                logger.error(f"Cannot connect to {server_url} / 无法连接到 {server_url}")
            except Exception as e:
                logger.error(f"Report error / 上报异常: {e}")

            time.sleep(interval)
    finally:
        network_stop_event.set()


if __name__ == '__main__':
    main()
