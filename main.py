import os
import re
import socket
import ssl
import time
import json
import requests
import base64
import websocket
import shutil
import ipaddress
from urllib.parse import quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

# ------------------ Настройки ------------------
BASE_DIR = "checked"
FOLDER_RU = os.path.join(BASE_DIR, "RU_Best")
FOLDER_EURO = os.path.join(BASE_DIR, "My_Euro")

# Чистим папки перед стартом
if os.path.exists(FOLDER_RU):
    shutil.rmtree(FOLDER_RU)
if os.path.exists(FOLDER_EURO):
    shutil.rmtree(FOLDER_EURO)
os.makedirs(FOLDER_RU, exist_ok=True)
os.makedirs(FOLDER_EURO, exist_ok=True)

TIMEOUT = 5
THREADS = 40
CACHE_HOURS = 12
CHUNK_LIMIT = 1000
MAX_KEYS_TO_CHECK = 15000

HISTORY_FILE = os.path.join(BASE_DIR, "history.json")
MY_CHANNEL = "@vlesstrojan"

URLS_RU = [
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/BLACK_VLESS_RUS_mobile.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/BLACK_SS%2BAll_RUS.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/WHITE-CIDR-RU-all.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/WHITE-CIDR-RU-checked.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    "https://etoneya.a9fm.site/1",
    "https://s3c3.001.gpucloud.ru/vahe4xkwi/cjdr"
]

URLS_MY = [
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/githubmirror/new/all_new.txt"
]

EURO_CODES = {
    "NL", "DE", "FI", "GB", "FR", "SE", "PL", "CZ", "AT", "CH",
    "IT", "ES", "NO", "DK", "BE", "IE", "LU", "EE", "LV", "LT"
}

BAD_MARKERS = [
    "CN", "IR", "KR", "BR", "IN", "RELAY", "POOL",
    "🇨🇳", "🇮🇷", "🇰🇷"
]

# ------------------ Вспомогательные функции ------------------


def load_json(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[WARN] Не удалось загрузить {path}: {e}")
    return {}


def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[WARN] Не удалось сохранить {path}: {e}")


def resolve_host_to_ip(host):
    """Резолвит хост в IP адрес"""
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def is_valid_public_ip(ip_str):
    """Проверяет, что IP публичный и глобально маршрутизируемый"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global
    except Exception:
        return False


def get_country_fast(host, key_name):
    """Быстрое определение страны по домену и имени ключа"""
    try:
        host = host.lower()
        name = key_name.upper()
        if host.endswith(".ru"):
            return "RU"
        domain_map = {
            ".de": "DE", ".nl": "NL", ".fr": "FR",
            ".fi": "FI", ".se": "SE", ".pl": "PL",
            ".cz": "CZ", ".at": "AT", ".ch": "CH",
            ".it": "IT", ".es": "ES", ".no": "NO",
            ".dk": "DK", ".be": "BE", ".ie": "IE",
            ".lu": "LU", ".ee": "EE", ".lv": "LV",
            ".lt": "LT",
        }
        if host.endswith(".uk") or host.endswith(".co.uk"):
            return "GB"
        for suffix, code in domain_map.items():
            if host.endswith(suffix):
                return code
        for code in EURO_CODES:
            if code in name:
                return code
        if "RU" in name or "RUSSIA" in name or "МОСКВА" in name.upper():
            return "RU"
    except Exception:
        pass
    return "UNKNOWN"


def is_garbage_text(key_str):
    upper = key_str.upper()
    for m in BAD_MARKERS:
        if m in upper:
            return True
    if ".ir" in key_str or ".cn" in key_str or "127.0.0.1" in key_str:
        return True
    return False


def parse_host_port(key):
    """Извлекает host и port из ключа VPN"""
    try:
        if key.startswith("vmess://"):
            raw = key[8:].split("#")[0]
            padding = 4 - len(raw) % 4
            if padding != 4:
                raw += "=" * padding
            decoded = base64.b64decode(raw).decode("utf-8", errors="ignore")
            obj = json.loads(decoded)
            return obj.get("add", ""), int(obj.get("port", 0))

        if "@" in key and ":" in key:
            part = key.split("@")[1].split("?")[0].split("#")[0]
            tokens = part.split(":")
            host = tokens[0]
            port = int(tokens[1])
            return host, port
    except Exception:
        pass
    return None, None


# ------------------ Загрузка ключей ------------------


def fetch_keys(urls, tag):
    out = []
    print(f"Загрузка {tag}...")
    for url in urls:
        try:
            if "github.com" in url and "/blob/" in url:
                url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

            r = requests.get(url, timeout=10)
            if r.status_code != 200:
                print(f"  [WARN] HTTP {r.status_code}: {url}")
                continue
            content = r.text.strip()

            if "://" not in content:
                try:
                    lines = base64.b64decode(content + "==").decode("utf-8", errors="ignore").splitlines()
                except Exception:
                    lines = content.splitlines()
            else:
                lines = content.splitlines()

            count = 0
            for l in lines:
                l = l.strip()
                if len(l) > 2000:
                    continue
                if l.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                    if tag == "MY" and is_garbage_text(l):
                        continue
                    out.append((l, tag))
                    count += 1
            print(f"  [{tag}] {url[:60]}... → {count} ключей")
        except Exception as e:
            print(f"  [ERR] {url[:60]}... → {e}")
    return out


# ------------------ Проверка ключей ------------------


def check_single_key(data):
    """
    Проверяет один ключ на доступность.
    Возвращает (latency, tag, country) или (None, None, None).
    """
    key, tag = data
    try:
        host, port = parse_host_port(key)
        if not host or not port:
            return None, None, None

        # Резолвим и проверяем IP
        ip = resolve_host_to_ip(host)
        if ip and not is_valid_public_ip(ip):
            return None, None, None

        country = get_country_fast(host, key)

        # MY-ключи из РФ не нужны в EURO
        if tag == "MY" and country == "RU":
            return None, None, None

        is_tls = (
            "security=tls" in key
            or "security=reality" in key
            or "trojan://" in key
        )
        is_ws = "type=ws" in key or "net=ws" in key

        path = "/"
        match = re.search(r"path=([^&]+)", key)
        if match:
            path = unquote(match.group(1))

        start = time.time()

        if is_ws:
            protocol = "wss" if is_tls else "ws"
            ws_url = f"{protocol}://{host}:{port}{path}"
            ws = websocket.create_connection(
                ws_url,
                timeout=TIMEOUT,
                sslopt={"cert_reqs": ssl.CERT_NONE},
            )
            ws.close()
        elif is_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    pass
        else:
            with socket.create_connection((host, port), timeout=TIMEOUT):
                pass

        latency = int((time.time() - start) * 1000)
        return latency, tag, country

    except Exception:
        return None, None, None


# ------------------ Формирование и сохранение ------------------


def make_final_key(k_id, latency, country):
    """Создает ключ с правильно закодированной меткой для Hiddify"""
    info_str = f"[{latency}ms {country} {MY_CHANNEL}]"
    label_encoded = quote(info_str, safe="")
    return f"{k_id}#{label_encoded}"


def extract_ping(key_str):
    """Извлекает пинг из метки ключа"""
    try:
        decoded = unquote(key_str)
        label = decoded.split("#")[-1]
        match = re.search(r"(\d+)ms", label)
        if match:
            return int(match.group(1))
    except Exception:
        pass
    return 999999  # Если не удалось — в конец списка


def save_chunked(keys_list, folder, base_name):
    """Сохраняет ключи в файлы, разбивая на части по CHUNK_LIMIT"""
    created_files = []
    valid_keys = [k.strip() for k in keys_list if k and k.strip()]

    if not valid_keys:
        fname = f"{base_name}.txt"
        path = os.path.join(folder, fname)
        with open(path, "w", encoding="utf-8") as f:
            f.write("")
        created_files.append(fname)
        return created_files

    chunks = [valid_keys[i: i + CHUNK_LIMIT] for i in range(0, len(valid_keys), CHUNK_LIMIT)]

    for i, chunk in enumerate(chunks, 1):
        if len(chunks) == 1:
            fname = f"{base_name}.txt"
        else:
            fname = f"{base_name}_part{i}.txt"

        content = "\n".join(chunk)
        with open(os.path.join(folder, fname), "w", encoding="utf-8") as f:
            f.write(content)

        created_files.append(fname)

    return created_files


# ------------------ MAIN ------------------

if __name__ == "__main__":
    print("=== CHECKER v10.2 (FIXED) ===")

    history = load_json(HISTORY_FILE)
    tasks = fetch_keys(URLS_RU, "RU") + fetch_keys(URLS_MY, "MY")

    # Убираем дубли
    unique_tasks = {}
    for k, tag in tasks:
        k_id = k.split("#")[0]
        unique_tasks[k_id] = (k, tag)
    all_items = list(unique_tasks.values())

    if len(all_items) > MAX_KEYS_TO_CHECK:
        all_items = all_items[:MAX_KEYS_TO_CHECK]

    current_time = time.time()
    to_check = []
    res_ru = []
    res_euro = []

    print(f"Всего уникальных ключей: {len(all_items)}")

    # 1. Обработка кэша
    for k, tag in all_items:
        k_id = k.split("#")[0]
        cached = history.get(k_id)

        if cached and (current_time - cached["time"] < CACHE_HOURS * 3600):
            if cached.get("alive"):
                latency = cached["latency"]
                country = cached.get("country", "UNKNOWN")
                final = make_final_key(k_id, latency, country)

                if tag == "RU":
                    res_ru.append(final)
                elif tag == "MY" and country in EURO_CODES:
                    res_euro.append(final)
            # Мёртвые из кэша — просто пропускаем
        else:
            to_check.append((k, tag))

    print(f"Из кэша: RU={len(res_ru)}, EURO={len(res_euro)}")
    print(f"На проверку: {len(to_check)}")

    # 2. Проверка новых ключей
    if to_check:
        alive_count = 0
        dead_count = 0

        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            future_to_item = {
                executor.submit(check_single_key, item): item
                for item in to_check
            }

            for future in as_completed(future_to_item):
                key, tag = future_to_item[future]
                k_id = key.split("#")[0]

                try:
                    latency, _, country = future.result()
                except Exception:
                    latency, country = None, None

                if latency is not None:
                    # Живой ключ
                    history[k_id] = {
                        "alive": True,
                        "latency": latency,
                        "time": current_time,
                        "country": country,
                    }

                    final = make_final_key(k_id, latency, country)

                    if tag == "RU":
                        res_ru.append(final)
                    elif tag == "MY" and country in EURO_CODES:
                        res_euro.append(final)

                    alive_count += 1
                else:
                    # Мёртвый ключ — тоже запоминаем
                    history[k_id] = {
                        "alive": False,
                        "latency": 0,
                        "time": current_time,
                        "country": "UNKNOWN",
                    }
                    dead_count += 1

        print(f"Живых: {alive_count}, Мёртвых: {dead_count}")

    # 3. Очистка старой истории (старше 3 дней)
    history_clean = {
        k: v for k, v in history.items()
        if current_time - v.get("time", 0) < 259200
    }
    save_json(HISTORY_FILE, history_clean)

    # 4. Сортировка по пингу
    res_ru.sort(key=extract_ping)
    res_euro.sort(key=extract_ping)

    print(f"Итого: RU={len(res_ru)}, EURO={len(res_euro)}")

    # 5. Сохранение файлов
    ru_files = save_chunked(res_ru, FOLDER_RU, "ru_white")
    euro_files = save_chunked(res_euro, FOLDER_EURO, "my_euro")

    # 6. Генерация списка подписок
    GITHUB_USER_REPO = "kort0881/vpn-checker-backend"
    BRANCH = "main"
    BASE_URL_RU = f"https://raw.githubusercontent.com/{GITHUB_USER_REPO}/{BRANCH}/{BASE_DIR}/RU_Best"
    BASE_URL_EURO = f"https://raw.githubusercontent.com/{GITHUB_USER_REPO}/{BRANCH}/{BASE_DIR}/My_Euro"

    subs_lines = ["=== 🇷🇺 RUSSIA ==="]
    for f in ru_files:
        subs_lines.append(f"{BASE_URL_RU}/{f}")

    subs_lines.append("\n=== 🇪🇺 EUROPE ===")
    for f in euro_files:
        subs_lines.append(f"{BASE_URL_EURO}/{f}")

    with open(os.path.join(BASE_DIR, "subscriptions_list.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(subs_lines))

    print("=== SUCCESS: LISTS GENERATED ===")
    print(f"RU файлы: {ru_files}")
    print(f"EURO файлы: {euro_files}")
































