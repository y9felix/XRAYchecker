import argparse, tempfile, sys, os, shutil, logging, random, time, json, socket, subprocess, platform, base64, requests, psutil, re, urllib3, urllib.parse
from datetime import datetime
from http.client import BadStatusLine, RemoteDisconnected
from concurrent.futures import ThreadPoolExecutor, as_completed
from types import SimpleNamespace
from threading import Lock, Semaphore
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.prompt import Prompt, Confirm
from rich.logging import RichHandler
from rich import box
from rich.text import Text

# cfg
text2art = None
AGGREGATOR_AVAILABLE = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
CONFIG_FILE = ""
SOURCES_FILE = ""
console = Console()
DEFAULT_SOURCES_DATA = {}
PROTO_HINTS = ("vless://", "vmess://", "trojan://", "hysteria2://", "hy2://", "ss://")
BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")
URL_FINDER = re.compile(
    r'(?:vless|vmess|trojan|hysteria2|hy2)://[^\s"\'<>]+|(?<![A-Za-z0-9+])ss://[^\s"\'<>]+',
    re.IGNORECASE)

DEFAULT_CONFIG = {
    "core_path": "/home/felix/Documents/Scripts/xray",  # путь до ядра, просто xray если лежит в обнимку с скриптом
    "threads": 500,        # Потоки
    "timeout": 4,         # Таймаут (повышать в случае огромного пинга)
    "local_port_start": 1080, # Отвечает за то, с какого конкретно порта будут запускаться ядра, 1080 > 1081 > 1082 = три потока(три ядра)
    "test_domain": "https://www.google.com/generate_204", # Ссылка по которой будут чекаться прокси, можно использовать другие в случае блокировок в разных странах.(http://cp.cloudflare.com/generate_204)
    "output_file": "/home/felix/Documents/Scripts/yo.txt", # имя файла с отфильтрованными проксями
    "core_startup_timeout": 2.5, # Максимальное время ожидания старта ядра(ну если тупит)
    "core_kill_delay": 0.05,     # Задержка после УБИЙСТВА
    "shuffle": False,
    "check_speed": False,
    "sort_by": "ping",           # ping | speed

    "speed_check_threads": 3, 
    "speed_test_url": "https://speed.cloudflare.com/__down?bytes=10000000", # Ссылка для скачивания
    "speed_download_timeout": 10, # Макс. время (сек) на скачивание файла (Чем больше - Тем точнее замеры.)
    "speed_connect_timeout": 5,   # Макс. время (сек) на подключение перед скачиванием (пинг 4000мс, скрипт ждёт 5000мс, значит скорость будет замеряна.)
    "speed_max_mb": 10,           # Лимит скачивания в МБ (чтобы не тратить трафик)
    "speed_min_kb": 1,            # Минимальный порог данных (в Килобайтах). Если прокси скачал меньше этого, скорость будет равной 0.0
    "sources": {}, # Переезд в отделный .json
    "speed_targets": [
        "https://speed.cloudflare.com/__down?bytes=20000000",              # Cloudflare (Global)
        "https://proof.ovh.net/files/100Mb.dat",                           # OVH (Europe/Global)
        "http://speedtest.tele2.net/100MB.zip",                            # Tele2 (Very stable)
        "https://speed.hetzner.de/100MB.bin",                              # Hetzner (Germany)
        "https://mirror.leaseweb.com/speedtest/100mb.bin",                 # Leaseweb (NL)
        "http://speedtest-ny.turnkeyinternet.net/100mb.bin",               # USA
        "https://yandex.ru/internet/api/v0/measure/download?size=10000000" # Yandex (RU/CIS)
    ],}

def load_sources():
    if os.path.exists(SOURCES_FILE):
        try:
            with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception as e:
            print(f"Error loading {SOURCES_FILE}: {e}")
    
    try:
        with open(SOURCES_FILE, 'w', encoding='utf-8') as f:
            json.dump(DEFAULT_SOURCES_DATA, f, indent=4)
        print(f"Created default {SOURCES_FILE}")
    except Exception as e:
        print(f"Error creating {SOURCES_FILE}: {e}")
    
    return DEFAULT_SOURCES_DATA

def load_config():
    loaded_sources = load_sources()

    if not os.path.exists(CONFIG_FILE):
        try:
            config_to_write = DEFAULT_CONFIG.copy()
            del config_to_write["sources"] 
            
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config_to_write, f, indent=4)
            print(f"Created default {CONFIG_FILE}")
        except: pass
        cfg = DEFAULT_CONFIG.copy()
        cfg["sources"] = loaded_sources
        return cfg
    
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            user_config = json.load(f)
        
        config = DEFAULT_CONFIG.copy()
        config.update(user_config)
        
        config["sources"] = loaded_sources
        
        has_new_keys = False
        keys_to_check = [k for k in DEFAULT_CONFIG.keys() if k != "sources"]
        
        for key in keys_to_check:
            if key not in user_config:
                has_new_keys = True
                break
        
        if has_new_keys:
            try:
                print(f">> Обновление {CONFIG_FILE}: добавлены новые параметры...")
                save_cfg = config.copy()
                if "sources" in save_cfg: del save_cfg["sources"]
                
                with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                    json.dump(save_cfg, f, indent=4)
            except Exception as e:
                print(f"Warning: Не удалось обновить конфиг файл: {e}")

        return config
    except Exception as e:
        print(f"Error loading config: {e}")
        cfg = DEFAULT_CONFIG.copy()
        cfg["sources"] = loaded_sources
        return cfg

GLOBAL_CFG = load_config()
class Fore:
    CYAN = "[cyan]"
    GREEN = "[green]"
    RED = "[red]"
    YELLOW = "[yellow]"
    MAGENTA = "[magenta]"
    BLUE = "[blue]"
    WHITE = "[white]"
    LIGHTBLACK_EX = "[dim]"
    LIGHTGREEN_EX = "[bold green]"
    LIGHTRED_EX = "[bold red]"
    RESET = "[/]"

class Style:
    BRIGHT = "[bold]"
    RESET_ALL = "[/]"

def clean_url(url):
    url = url.strip()
    url = url.replace('\ufeff', '').replace('\u200b', '')
    url = url.replace('\n', '').replace('\r', '')
    return url

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    
class SmartLogger:
    def __init__(self, filename=""):
        self.filename = filename
        self.lock = Lock()
        try:
            with open(self.filename, 'a', encoding='utf-8') as f:
                pass
        except Exception as e:
            pass

    def log(self, msg, style=None):
        with self.lock:
            console.print(msg, style=style, highlight=False)

            try:
                text_obj = Text.from_markup(str(msg))
                clean_msg = text_obj.plain.strip()
                
                if clean_msg:
                    timestamp = datetime.now().strftime("[%H:%M:%S]")
                    log_line = f"{timestamp} {clean_msg}\n"
                    
                    with open(self.filename, 'a', encoding='utf-8') as f:
                        pass
            except Exception:
                pass

MAIN_LOGGER = SmartLogger("")

logging.basicConfig(format="%(asctime)s - %(message)s", level=logging.INFO, datefmt='%H:%M:%S')

def safe_print(msg):
    MAIN_LOGGER.log(msg)

TEMP_DIR = tempfile.mkdtemp()
OS_SYSTEM = platform.system().lower()
CORE_PATH = ""
CTRL_C = False

LOGO_FONTS = [
    "cybermedium",
    "4Max"
]

BACKUP_LOGO = r""""""

# ------------------------------ ДАЛЬШЕ БОГА НЕТ ------------------------------

def is_port_in_use(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            return s.connect_ex(('127.0.0.1', port)) == 0
    except:
        return False


def wait_for_core_start(port, max_wait):
    start_time = time.time()
    while time.time() - start_time < max_wait:
        if is_port_in_use(port):
            return True
        time.sleep(0.05) 
    return False


def split_list(lst, n):
    if n <= 0: return []
    k, m = divmod(len(lst), n)
    return (lst[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n))

def try_decode_base64(text):
    raw = text.strip()
    if not raw:
        return raw

    if any(marker in raw for marker in PROTO_HINTS):
        return raw

    compact = re.sub(r'\s+', '', raw)
    if not compact or not set(compact) <= BASE64_CHARS:
        return raw

    missing_padding = len(compact) % 4
    if missing_padding:
        compact += "=" * (4 - missing_padding)

    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(compact).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if any(marker in decoded for marker in PROTO_HINTS):
            return decoded
    return raw

def _payload_variants(blob):
    clean_blob = blob.strip()
    if not clean_blob:
        return set()

    variants = {clean_blob}
    
    decoded_blob = try_decode_base64(clean_blob)
    
    if decoded_blob and decoded_blob != clean_blob:
        variants.add(decoded_blob)
    for line in clean_blob.splitlines():
        line = line.strip()
        if not line:
            continue
        maybe_decoded = try_decode_base64(line)
        if maybe_decoded and maybe_decoded != line:
            variants.add(maybe_decoded)
            
    return variants

def parse_content(text):
    unique_links = set()
    raw_hits = 0

    for payload in _payload_variants(text):
        matches = URL_FINDER.findall(payload)
        raw_hits += len(matches)
        for item in matches:
            cleaned = clean_url(item.rstrip(';,)]}'))
            if cleaned and len(cleaned) > 15:
                unique_links.add(cleaned)

    return list(unique_links), raw_hits or len(unique_links)

def fetch_url(url):
    try:
        safe_print(f"{Fore.CYAN}>> Загрузка URL: {url}{Style.RESET_ALL}")
        resp = requests.get(url, timeout=15, verify=False)
        if resp.status_code == 200:
            links, count = parse_content(resp.text)
            return links
        else:
            safe_print(f"{Fore.RED}>> Ошибка скачивания: HTTP {resp.status_code}{Style.RESET_ALL}")
    except Exception as e:
        safe_print(f"{Fore.RED}>> Ошибка URL: {e}{Style.RESET_ALL}")
    return []
    
    
    
def parse_vless(url):
    try:
        url = clean_url(url)
        if not url.startswith("vless://"): return None

        if '#' in url:
            main_part, tag = url.split('#', 1)
            tag = urllib.parse.unquote(tag).strip()
        else:
            main_part = url
            tag = "vless"

        match = re.search(r'vless://([^@]+)@([^:]+):(\d+)', main_part)
        
        if not match:
            return None

        uuid = match.group(1).strip()
        address = match.group(2).strip()
        port = int(match.group(3))

        params = {}
        if '?' in main_part:
            query = main_part.split('?', 1)[1]
            params = urllib.parse.parse_qs(query)

        def get_p(key, default=""):
            val = params.get(key, [default])
            return val[0] if val else default

        sec = get_p("security", "none")
        pbk_val = get_p("pbk", "")
        
        if pbk_val and sec == "tls":
            sec = "reality"

        return {
            "protocol": "vless",
            "uuid": uuid,
            "address": address,
            "port": port,
            "encryption": get_p("encryption", "none"),
            "type": get_p("type", "tcp"),
            "security": sec,
            "path": urllib.parse.unquote(get_p("path", "")),
            "host": get_p("host", ""),
            "sni": get_p("sni", ""),
            "fp": get_p("fp", ""),
            "alpn": get_p("alpn", ""),
            "serviceName": get_p("serviceName", ""),
            "mode": get_p("mode", ""),
            "pbk": get_p("pbk", ""),
            "sid": get_p("sid", ""),
            "flow": get_p("flow", ""),
            "tag": tag
        }
    except Exception as e:
        safe_print(f"{Fore.RED}[VLESS ERROR] {e}{Style.RESET_ALL}")
        return None

def parse_vmess(url):
    try:
        url = clean_url(url)
        if not url.startswith("vmess://"): return None

        if '@' in url:
            if '#' in url:
                main_part, tag = url.split('#', 1)
                tag = urllib.parse.unquote(tag).strip()
            else:
                main_part = url
                tag = "vmess"

            match = re.search(r'vmess://([^@]+)@([^:]+):(\d+)', main_part)
            if match:
                uuid = match.group(1).strip()
                address = match.group(2).strip()
                port = int(match.group(3))

                params = {}
                if '?' in main_part:
                    query = main_part.split('?', 1)[1]
                    params = urllib.parse.parse_qs(query)

                def get_p(key, default=""):
                    val = params.get(key, [default])
                    return val[0] if val else default
                
                try: aid = int(get_p("aid", "0"))
                except: aid = 0
                
                raw_path = get_p("path", "")
                final_path = urllib.parse.unquote(raw_path)

                return {
                    "protocol": "vmess",
                    "uuid": uuid,
                    "address": address,
                    "port": port,
                    "type": get_p("type", "tcp"),
                    "security": get_p("security", "none"),
                    "path": final_path,
                    "host": get_p("host", ""),
                    "sni": get_p("sni", ""),
                    "fp": get_p("fp", ""),
                    "alpn": get_p("alpn", ""),
                    "serviceName": get_p("serviceName", ""),
                    "aid": aid,
                    "scy": get_p("encryption", "auto"),
                    "tag": tag
                }

        content = url[8:]
        if '#' in content:
            b64, tag = content.rsplit('#', 1)
            tag = urllib.parse.unquote(tag).strip()
        else:
            b64 = content
            tag = "vmess"
            
        missing_padding = len(b64) % 4
        if missing_padding: b64 += '=' * (4 - missing_padding)
        
        try:
            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
            data = json.loads(decoded)
            return {
                "protocol": "vmess",
                "uuid": data.get("id"),
                "address": data.get("add"),
                "port": int(data.get("port", 0)),
                "aid": int(data.get("aid", 0)),
                "type": data.get("net", "tcp"),
                "security": data.get("tls", "") if data.get("tls") else "none",
                "path": data.get("path", ""),
                "host": data.get("host", ""),
                "sni": data.get("sni", ""),
                "fp": data.get("fp", ""),
                "alpn": data.get("alpn", ""),
                "scy": data.get("scy", "auto"),
                "tag": data.get("ps", tag)
            }
        except:
            pass

        return None
    except Exception as e:
        safe_print(f"{Fore.RED}[VMESS ERROR] {e}{Style.RESET_ALL}")
        return None
    
def parse_trojan(url):
    try:
        if '#' in url:
            url_clean, tag = url.split('#', 1)
        else:
            url_clean = url
            tag = "trojan"
        
        parsed = urllib.parse.urlparse(url_clean)
        params = urllib.parse.parse_qs(parsed.query)
        
        return {
            "protocol": "trojan",
            "uuid": parsed.username,
            "address": parsed.hostname,
            "port": parsed.port,
            "security": params.get("security", ["tls"])[0],
            "sni": params.get("sni", [""])[0] or params.get("peer", [""])[0],
            "type": params.get("type", ["tcp"])[0],
            "path": params.get("path", [""])[0],
            "host": params.get("host", [""])[0],
            "tag": urllib.parse.unquote(tag).strip()
        }
    except: return None

def parse_ss(url):
    try:
        if '#' in url:
            url_clean, tag = url.split('#', 1)
        else:
            url_clean = url
            tag = "ss"
        
        parsed = urllib.parse.urlparse(url_clean)
        
        if '@' in url_clean:
            userinfo = parsed.username
            try:
                if ':' not in userinfo:
                    missing_padding = len(userinfo) % 4
                    if missing_padding: userinfo += '=' * (4 - missing_padding)
                    decoded_info = base64.b64decode(userinfo).decode('utf-8')
                else:
                    decoded_info = userinfo
            except:
                decoded_info = userinfo
            
            method, password = decoded_info.split(':', 1)
            address = parsed.hostname
            port = parsed.port
        else:
            b64 = url_clean.replace("ss://", "")
            missing_padding = len(b64) % 4
            if missing_padding: b64 += '=' * (4 - missing_padding)
            decoded = base64.b64decode(b64).decode('utf-8')
            method_pass, addr_port = decoded.rsplit('@', 1)
            method, password = method_pass.split(':', 1)
            address, port = addr_port.rsplit(':', 1)
            port = int(port)

        return {
            "protocol": "shadowsocks",
            "address": address,
            "port": port,
            "method": method,
            "password": password,
            "tag": urllib.parse.unquote(tag).strip()
        }
    except: return None

def parse_hysteria2(url):
    try:
        url = url.replace("hy2://", "hysteria2://")
        if '#' in url:
            url_clean, tag = url.split('#', 1)
        else:
            url_clean = url
            tag = "hy2"
            
        parsed = urllib.parse.urlparse(url_clean)
        params = urllib.parse.parse_qs(parsed.query)
        
        return {
            "protocol": "hysteria2",
            "uuid": parsed.username,
            "address": parsed.hostname,
            "port": parsed.port,
            "sni": params.get("sni", [""])[0],
            "insecure": params.get("insecure", ["0"])[0] == "1",
            "obfs": params.get("obfs", ["none"])[0],
            "obfs_password": params.get("obfs-password", [""])[0],
            "tag": urllib.parse.unquote(tag).strip()
        }
    except: return None

def get_proxy_tag(url):
    try:
        url = clean_url(url)
        if '#' in url:
            _, tag = url.rsplit('#', 1)
            return urllib.parse.unquote(tag).strip()
    except: 
        pass
    
    try:
        if url.startswith("vmess"): 
            res = parse_vmess(url)
            if res: return res.get('tag', 'vmess')
    except: pass
    
    return "proxy"

def create_config_file(proxy_url, local_port, work_dir):
    proxy_url = clean_url(proxy_url)
    proxy_conf = None
    
    if proxy_url.startswith("vless://"): proxy_conf = parse_vless(proxy_url)
    elif proxy_url.startswith("vmess://"): proxy_conf = parse_vmess(proxy_url)
    elif proxy_url.startswith("trojan://"): proxy_conf = parse_trojan(proxy_url)
    elif proxy_url.startswith("ss://"): proxy_conf = parse_ss(proxy_url)
    elif proxy_url.startswith("hy"): proxy_conf = parse_hysteria2(proxy_url)
    
    if not proxy_conf: 
        return None, "Parsing Failed"

    if not proxy_conf.get("port") or not proxy_conf.get("address"):
        return None, "Port or Address missing"

    streamSettings = {}

    streamSettings = {}
    
    if proxy_conf["protocol"] in ["vless", "vmess", "trojan"]:
        streamSettings = {
            "network": proxy_conf.get("type", "tcp"),
            "security": proxy_conf.get("security", "none")
        }
        
        if streamSettings["security"] == "tls":
            streamSettings["tlsSettings"] = {
                "serverName": proxy_conf.get("sni") or proxy_conf.get("host"),
                "allowInsecure": True,
                "fingerprint": proxy_conf.get("fp", "")
            }
        elif streamSettings["security"] == "reality":
             if "xray" not in CORE_PATH.lower(): return None, "Reality requires Xray"
             streamSettings["realitySettings"] = {
                "publicKey": proxy_conf.get("pbk"),
                "shortId": proxy_conf.get("sid"),
                "serverName": proxy_conf.get("sni"),
                "fingerprint": proxy_conf.get("fp", "chrome")
            }

        if streamSettings["network"] == "ws":
            streamSettings["wsSettings"] = {
                "path": proxy_conf.get("path", "/"),
                "headers": {"Host": proxy_conf.get("host", "")}
            }
            
        elif streamSettings["network"] == "grpc":
            svc_name = proxy_conf.get("serviceName", "")
            if not svc_name:
                svc_name = proxy_conf.get("path", "")
            if not svc_name:
                svc_name = "grpc" # Заглушка, впринцепе ваще похуй че туда писать.
            
            streamSettings["grpcSettings"] = {
                "serviceName": svc_name,
                "multiMode": False
            }

    if proxy_conf["protocol"] == "hysteria2":
        streamSettings = {
            "security": "tls",
            "tlsSettings": {
                "serverName": proxy_conf.get("sni", ""),
                "allowInsecure": proxy_conf.get("insecure", False)
            }
        }

    outbound = {
        "protocol": proxy_conf["protocol"],
        "streamSettings": streamSettings
    }

    if proxy_conf["protocol"] == "shadowsocks":
        legacy_methods = ["chacha20-ietf", "chacha20", "rc4-md5", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb"]
        curr_method = proxy_conf["method"].lower()
        if curr_method == "chacha20-ietf": curr_method = "chacha20-ietf-poly1305" 
        
        outbound["settings"] = {
            "servers": [{
                "address": proxy_conf["address"],
                "port": int(proxy_conf["port"]),
                "method": curr_method,
                "password": proxy_conf["password"]
            }]
        }
        outbound.pop("streamSettings", None)

    elif proxy_conf["protocol"] == "trojan":
        outbound["settings"] = {
            "servers": [{
                "address": proxy_conf["address"],
                "port": int(proxy_conf["port"]),
                "password": proxy_conf["uuid"]
            }]
        }
        
    elif proxy_conf["protocol"] == "hysteria2":
        hy2_settings = {
            "address": proxy_conf["address"],
            "port": int(proxy_conf["port"]),
            "users": [{"password": proxy_conf["uuid"]}]
        }
        if proxy_conf.get("obfs") and proxy_conf.get("obfs") != "none":
             hy2_settings["obfs"] = {
                 "type": proxy_conf["obfs"],
                 "password": proxy_conf.get("obfs_password", "")
             }

        outbound["settings"] = {
            "vnext": [hy2_settings]
        }

    else:
        outbound["settings"] = {
            "vnext": [{
                "address": proxy_conf["address"],
                "port": int(proxy_conf["port"]),
                "users": [{
                    "id": proxy_conf["uuid"],
                    "alterId": proxy_conf.get("aid", 0),
                    "encryption": "none",
                    "flow": proxy_conf.get("flow", "") 
                }]
            }]
        }

    full_config = {
        "log": {"loglevel": "none"}, 
        "inbounds": [{
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [outbound]
    }

    filename = os.path.join(work_dir, f"config_{local_port}.json")
    try:
        with open(filename, 'w') as f:
            json.dump(full_config, f, indent=2)
    except Exception as e:
        return None, str(e)
    return filename, None

def run_core(core_path, config_path):
    cmd = [core_path, "run", "-c", config_path] if "xray" in core_path.lower() else [core_path, "-c", config_path]
    startupinfo = None
    if OS_SYSTEM == "windows":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    try:
        return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, startupinfo=startupinfo)
    except: return None

def kill_core(proc):
    if not proc: return
    try:
        if psutil:
            parent = psutil.Process(proc.pid)
            for child in parent.children(recursive=True):
                try: child.kill() 
                except: pass
            parent.kill()
        else:
            proc.terminate()
            try: proc.wait(timeout=0.2)
            except: proc.kill()
    except: pass

def check_connection(local_port, domain, timeout):
    proxies = {
        'http': f'socks5://127.0.0.1:{local_port}',
        'https': f'socks5://127.0.0.1:{local_port}'
    }
    try:
        start = time.time()
        resp = requests.get(domain, proxies=proxies, timeout=timeout, verify=False)
        end = time.time()
        if resp.status_code < 400:
            return round((end - start) * 1000), None
        else:
            return False, f"HTTP {resp.status_code}"
    except (BadStatusLine, RemoteDisconnected):
        return False, "Handshake Fail"
    except Exception as e:
        return False, str(e)
    
def check_speed_download(local_port, url_file, timeout=10, conn_timeout=5, max_mb=5, min_kb=1):
    # Получаем список целей из конфига или используем переданный url_file как приоритет
    targets = GLOBAL_CFG.get("speed_targets", [])
    
    # Если передан конкретный URL (через аргументы), ставим его первым
    pool = [url_file] + targets if url_file else list(targets)
    # Перемешиваем дефолтный пул, чтобы потоки не долбили один сервер (кроме первого, если он задан)
    if not url_file: random.shuffle(pool)
    
    # Очищаем пустые
    pool = [u for u in pool if u]
    if not pool: return 0.0

    proxies = {
        'http': f'socks5://127.0.0.1:{local_port}',
        'https': f'socks5://127.0.0.1:{local_port}'
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Connection": "keep-alive"
    }

    limit_bytes = max_mb * 1024 * 1024
    
    for target_url in pool:
        try:
            with requests.get(target_url, proxies=proxies, headers=headers, stream=True, 
                              timeout=(conn_timeout, timeout), verify=False) as r:
                
                if r.status_code >= 400:
                    continue

                start_time = time.time()
                total_bytes = 0
                
                for chunk in r.iter_content(chunk_size=32768):
                    if chunk:
                        total_bytes += len(chunk)
                    
                    curr_time = time.time()
                    if (curr_time - start_time) > timeout or total_bytes >= limit_bytes:
                        break
                
                duration = time.time() - start_time
                if duration <= 0.1: duration = 0.1

                if total_bytes < (min_kb * 1024):
                    if duration > (timeout * 0.8):
                        return 0.0
                    continue

                speed_bps = total_bytes / duration
                speed_mbps = speed_bps / 125000
                
                return round(speed_mbps, 2)

        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
            continue
        except Exception:
            pass

def Checker(proxyList, localPort, testDomain, timeOut, t2exec, t2kill, checkSpeed=False, speedUrl="", sortBy="ping", speedCfg=None, speedSemaphore=None):
    liveProxy = []
    
    if speedCfg is None:
        speedCfg = {"timeout": 10, "conn_timeout": 5, "max_mb": 5, "min_kb": 1}

    for url in proxyList:
        if CTRL_C: break
        
        tag = get_proxy_tag(url)
        configName, err_msg = create_config_file(url, localPort, TEMP_DIR)
        
        if not configName:
            safe_print(f"{Fore.RED}[Skip] {tag[:15]}.. -> {err_msg}{Style.RESET_ALL}")
            continue

        proc = run_core(CORE_PATH, configName)
        if not proc:
            safe_print(f"{Fore.RED}[Err] Core start fail{Style.RESET_ALL}")
            try: os.remove(configName)
            except: pass
            continue

        is_ready = wait_for_core_start(localPort, t2exec)
        
        if not is_ready:
            if proc.poll() is not None:
                safe_print(f"{Fore.RED}[Dead] {tag[:15]}.. -> Core crashed{Style.RESET_ALL}")
            else:
                safe_print(f"{Fore.RED}[Dead] {tag[:15]}.. -> Core timeout{Style.RESET_ALL}")
            
            kill_core(proc)
            try: os.remove(configName)
            except: pass
            continue
            
        ping, error_reason = check_connection(localPort, testDomain, timeOut)
        speed = 0.0

        if ping:
            if checkSpeed:
                safe_print(f"[blue][TEST][/] Measuring speed for {tag[:15]}...")
                
                if speedSemaphore:
                    with speedSemaphore:
                        speed = check_speed_download(
                            localPort, speedUrl, 
                            timeout=speedCfg['timeout'],
                            conn_timeout=speedCfg['conn_timeout'],
                            max_mb=speedCfg['max_mb'],
                            min_kb=speedCfg['min_kb']
                        )
                else:
                    speed = check_speed_download(
                        localPort, speedUrl, 
                        timeout=speedCfg['timeout'],
                        conn_timeout=speedCfg['conn_timeout'],
                        max_mb=speedCfg['max_mb'],
                        min_kb=speedCfg['min_kb']
                    )
                
                sp_color = "red"
                if speed > 5: sp_color = "yellow"
                if speed > 15: sp_color = "green"
                if speed > 50: sp_color = "bold cyan"

                safe_print(f"[green][LIVE][/] {ping}ms | [{sp_color}]{speed} Mbps[/] | {tag}")
            else:
                safe_print(f"[green][LIVE][/] {ping}ms | {tag}")
            
            liveProxy.append((url, ping, speed))
        else:
            short_err = str(error_reason)
            if "SOCKSHTTPSConnectionPool" in short_err: short_err = "Conn Error"
            elif "Read timed out" in short_err: short_err = "Timeout"
            safe_print(f"[yellow][Dead][/] {tag[:15]}.. -> [dim]{short_err}[/]")

        kill_core(proc)
        time.sleep(t2kill)
        try: os.remove(configName)
        except: pass

    return liveProxy

def run_logic(args):
    global CORE_PATH, CTRL_C
    
    CORE_PATH = shutil.which(args.core)
    if not CORE_PATH:
        candidates = ["xray.exe", "xray", "v2ray.exe", "v2ray", "bin/xray.exe", "bin/xray"]
        for c in candidates:
             if os.path.exists(c):
                 CORE_PATH = os.path.abspath(c)
                 break
    
    if not CORE_PATH:
        safe_print(f"[bold red]\n[ERROR] Ядро (xray/v2ray) не найдено! Убедитесь, что файл рядом.[/]")
        return
        
    safe_print(f"[dim]Core detected: {CORE_PATH}[/]")

    safe_print(f"[yellow]>> Очистка зависших процессов ядра...[/]")
    killed_count = 0
    target_names = [os.path.basename(CORE_PATH).lower(), "xray.exe", "v2ray.exe", "xray", "v2ray"]
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in target_names:
                proc.kill()
                killed_count += 1
        except: pass
    
    if killed_count > 0:
        safe_print(f"[green]>> Убито старых процессов: {killed_count}[/]")
    
    time.sleep(0.5)
    
    lines = set()
    total_found_raw = 0
    
    if args.file:
        fpath = args.file.strip('"')
        if os.path.exists(fpath):
            safe_print(f"[cyan]>> Чтение файла: {fpath}[/]")
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                parsed, count = parse_content(f.read())
                total_found_raw += count
                lines.update(parsed)
        else:
            safe_print(f"[bold red]Файл не найден: {fpath}[/]")

    if args.url:
        links = fetch_url(args.url)
        lines.update(links)

    if AGGREGATOR_AVAILABLE and getattr(args, 'agg', False):
        safe_print(f"[cyan]>> Запуск агрегатора через CLI...[/]")
        sources_map = GLOBAL_CFG.get("sources", {})
        cats = args.agg_cats if args.agg_cats else list(sources_map.keys())
        kws = args.agg_filter if args.agg_filter else []
        
        try:
            try:
                agg_links = aggregator.get_aggregated_links(sources_map, cats, kws, log_func=safe_print, console=console)
            except TypeError:
                agg_links = aggregator.get_aggregated_links(sources_map, cats, kws, log_func=safe_print)
                
            lines.update(agg_links)
        except Exception as e:
            safe_print(f"[bold red]Ошибка агрегатора CLI: {e}[/]")

    if hasattr(args, 'direct_list') and args.direct_list:
        safe_print(f"[cyan]>> Получено из агрегатора: {len(args.direct_list)} шт.[/]")
        parsed_agg, _ = parse_content("\n".join(args.direct_list))
        lines.update(parsed_agg)

    if args.reuse and os.path.exists(args.output):
        with open(args.output, 'r', encoding='utf-8') as f:
            parsed, count = parse_content(f.read())
            lines.update(parsed)

    full = list(lines)
    
    if total_found_raw > 0:
        duplicates = total_found_raw - len(full)
        if duplicates > 0:
            safe_print(f"[yellow]Найдено: {total_found_raw}. Дубликатов: {duplicates}. К проверке: {len(full)}[/]")
        else:
             safe_print(f"[cyan]Загружено прокси: {len(full)}[/]")
    
    if not full:
        safe_print(f"[bold red]Нет прокси для проверки.[/]")
        return

    if args.shuffle: random.shuffle(full)
    if args.number: full = full[:args.number]

    threads = min(args.threads, len(full))
    ports = []
    p = args.lport
    while len(ports) < threads:
        if not is_port_in_use(p):
            ports.append(p)
        p += 1
    
    chunks = list(split_list(full, threads))
    results = []
    
    console.print(f"\n[magenta]Запуск {threads} потоков... (SpeedCheck: {args.speed_check}, Sort: {args.sort_by})[/]")

    progress_columns = [
        SpinnerColumn(style="bold yellow"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style="dim", complete_style="green", finished_style="bold green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        TextColumn("•"),
        TimeRemainingColumn(),
    ]

    with Progress(*progress_columns, console=console, transient=False) as progress:
        task_id = progress.add_task("[cyan]Checking proxies...", total=len(full))
        
    speed_config_map = {
        "timeout": GLOBAL_CFG.get("speed_download_timeout", 10),
        "conn_timeout": GLOBAL_CFG.get("speed_connect_timeout", 5),
        "max_mb": GLOBAL_CFG.get("speed_max_mb", 5),
        "min_kb": GLOBAL_CFG.get("speed_min_kb", 1)
    }
    
    max_speed_threads = GLOBAL_CFG.get("speed_check_threads", 3)
    speed_semaphore = Semaphore(max_speed_threads)
    
    if args.speed_check:
        safe_print(f"[magenta]>> Ограничение потоков спидтеста: {max_speed_threads}[/]")

    with Progress(*progress_columns, console=console, transient=False) as progress:
        task_id = progress.add_task("[cyan]Checking proxies...", total=len(full))
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_count = {}
            
            for i in range(threads):
                if i < len(chunks) and chunks[i]:
                    ft = executor.submit(
                        Checker, chunks[i], ports[i], args.domain, args.timeout, 
                        args.t2exec, args.t2kill, args.speed_check, args.speed_test_url, args.sort_by,
                        speed_config_map,
                        speed_semaphore
                    )
                    future_to_count[ft] = len(chunks[i])
            
            try:
                for f in as_completed(future_to_count):
                    chunk_result = f.result()
                    results.extend(chunk_result)
                    
                    processed_count = future_to_count[f]
                    progress.advance(task_id, advance=processed_count)
                    
            except KeyboardInterrupt:
                CTRL_C = True
                safe_print(f"\n[bold red]!!! Остановка по CTRL+C !!![/]")
                executor.shutdown(wait=False)

    if args.sort_by == "speed":
        results.sort(key=lambda x: x[2], reverse=True)
        safe_print(f"\n[cyan]>> Отсортировано по СКОРОСТИ (по убыванию)[/]")
    else:
        results.sort(key=lambda x: x[1])
        safe_print(f"\n[cyan]>> Отсортировано по ПИНГУ (по возрастанию)[/]")
    
    with open(args.output, 'w', encoding='utf-8') as f:
        for r in results:
            f.write(r[0] + '\n')

    if results:
        table = Table(title=f"Результаты (Топ 15 из {len(results)})", box=box.ROUNDED)
        table.add_column("Ping", justify="right", style="green")
        
        if args.speed_check:
            table.add_column("Speed (Mbps)", justify="right", style="bold cyan")
            
        table.add_column("Tag / Protocol", justify="left", overflow="fold")

        for r in results[:15]:
            tag_display = get_proxy_tag(r[0])
            if len(tag_display) > 50: tag_display = tag_display[:47] + "..."
            
            if args.speed_check:
                table.add_row(f"{r[1]} ms", f"{r[2]}", tag_display)
            else:
                table.add_row(f"{r[1]} ms", tag_display)

        console.print(table)
            
    safe_print(f"\n[bold green]Готово! Рабочих: {len(results)}[/]")
    safe_print(f"[bold green]Результат сохранен в: [white]{args.output}[/]")

def print_banner():
    console.clear()
    
    logo_str = BACKUP_LOGO
    font_name = "default"

    if text2art:
        try:
            font_name = random.choice(LOGO_FONTS)
            logo_str = text2art("Xchecker", font=font_name, chr_ignore=True)
        except Exception:
            logo_str = BACKUP_LOGO

    if not logo_str or not logo_str.strip():
        logo_str = BACKUP_LOGO

    logo_text = Text(logo_str, style="cyan bold", no_wrap=True, overflow="crop")
    
    panel = Panel(
        logo_text,
        title=f"[bold magenta]MK_XRAYchecker[/] [dim](font: {font_name})[/]",
        subtitle="[bold red]by mkultra69 with HATE[/]",
        border_style="cyan",
        box=box.DOUBLE,
        expand=False, 
        padding=(1, 2)
    )
    
    console.print(panel, justify="center")
    console.print("[dim]GitHub: https://github.com/MKultra6969 | Telegram: https://t.me/MKextera[/]", justify="center")
    console.print("─"*75, style="dim", justify="center")
    
    try:
        MAIN_LOGGER.log("MK_XRAYchecker by mkultra69 with HATE")
        MAIN_LOGGER.log("https://t.me/MKextera")
    except: pass

def kill_all_cores_manual():
    console.print("[yellow]>> Поиск и принудительная остановка процессов ядра...[/]")
    killed_count = 0
    target_names = ["xray.exe", "v2ray.exe", "xray", "v2ray", "wxray.exe", "wxray"]
    
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() in target_names:
                proc.kill()
                killed_count += 1
        except: pass
    
    if killed_count > 0:
        console.print(f"[bold green]>> Успешно убито {killed_count} зависших процессов.[/]")
    else:
        console.print("[dim]>> Активных процессов ядра не найдено.[/]")
    time.sleep(1.5)

def interactive_menu():
    while True:
        print_banner()
        
        table = Table(show_header=True, header_style="bold magenta", box=box.ROUNDED, expand=True)
        table.add_column("№", style="cyan", width=4, justify="center")
        table.add_column("Действие", style="white")
        table.add_column("Описание", style="dim")

        table.add_row("1", "Файл", "Загрузить прокси из .txt файла")
        table.add_row("2", "Ссылка", "Загрузить прокси по URL")
        table.add_row("3", "Перепроверка", f"Проверить заново {GLOBAL_CFG['output_file']}")
        
        if AGGREGATOR_AVAILABLE:
            table.add_row("4", "Агрегатор", "Скачать базы, объединить и проверить")
        
        table.add_row("5", "Сброс ядер", "Убить все процессы xray")
        table.add_row("0", "Выход", "Закрыть программу")
        
        console.print(table)
        
        valid_choices = ["0", "1", "2", "3", "4", "5"] if AGGREGATOR_AVAILABLE else ["0", "1", "2", "3", "5"]
        ch = 1
        
        if ch == '0':
            sys.exit()

        defaults = {
            "file": "/home/felix/Documents/Scripts/all.txt", "url": None, "reuse": False,
            "domain": GLOBAL_CFG['test_domain'],
            "timeout": GLOBAL_CFG['timeout'], 
            "lport": GLOBAL_CFG['local_port_start'], 
            "threads": GLOBAL_CFG['threads'], 
            "core": GLOBAL_CFG['core_path'], 
            "t2exec": GLOBAL_CFG['core_startup_timeout'], 
            "t2kill": GLOBAL_CFG['core_kill_delay'], 
            "output": GLOBAL_CFG['output_file'], 
            "shuffle": GLOBAL_CFG['shuffle'], 
            "number": None,
            "direct_list": None,
            "speed_check": GLOBAL_CFG['check_speed'],
            "speed_test_url": GLOBAL_CFG['speed_test_url'],
            "sort_by": GLOBAL_CFG['sort_by'],
            "menu": True
        }
        
        if ch == '1':
            defaults["file"] = "/home/felix/Documents/Scripts/all.txt"
            if not defaults["file"]: continue
            
        elif ch == '2':
            defaults["url"] = Prompt.ask("[cyan][?][/] URL ссылки").strip()
            if not defaults["url"]: continue
            
        elif ch == '3':
            defaults["reuse"] = True
            
        elif ch == '4' and AGGREGATOR_AVAILABLE:
            console.print(Panel(f"Доступные категории: [green]{', '.join(GLOBAL_CFG.get('sources', {}).keys())}[/]", title="Агрегатор"))
            cats = Prompt.ask("Введите категории (через пробел)", default="1 2").split()
            kws = Prompt.ask("Фильтр (ключевые слова через пробел)", default="").split()
            
            sources_map = GLOBAL_CFG.get("sources", {})
            try:
                raw_links = aggregator.get_aggregated_links(sources_map, cats, kws, console=console)
                if not raw_links:
                    safe_print("[bold red]Ничего не найдено агрегатором.[/]")
                    time.sleep(2)
                    continue
                defaults["direct_list"] = raw_links
            except Exception as e:
                safe_print(f"[bold red]Ошибка агрегатора: {e}[/]")
                continue
            
        elif ch == '5':
            kill_all_cores_manual()
            continue

        args = SimpleNamespace(**defaults)
        
        safe_print("\n[yellow]>>> Инициализация проверки...[/]")
        time.sleep(0.5)
        
        try:
            run_logic(args)
        except Exception as e:
            safe_print(f"[bold red]CRITICAL ERROR: {e}[/]")
            import traceback
            traceback.print_exc()
        
        Prompt.ask("\n[bold]Нажмите Enter чтобы вернуться в меню...[/]", password=False)

def main():
    if len(sys.argv) == 1:
        interactive_menu()
    else:
        args = parser.parse_args()
        if args.menu: interactive_menu()
        else:
            print(Fore.CYAN + "MK_XRAYchecker by mkultra69 with HATE" + Style.RESET_ALL)
            run_logic(args)

if __name__ == '__main__':
    try: main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Exit.{Style.RESET_ALL}")
    finally:
        try: shutil.rmtree(TEMP_DIR)
        except: pass
