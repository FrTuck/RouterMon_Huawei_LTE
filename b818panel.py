#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B818 LTE Panel — локальный дашборд и пульт для роутера Huawei B818-260 (HiLink).

Показывает сигнал LTE, статус, оператора и трафик на локальной странице
http://localhost:8099/ и позволяет: сменить Band, привязать к соте, перезагрузить.

Вход в роутер делается прямо на странице (пароль вводится в браузере при открытии
ссылки). Можно по-прежнему передать пароль и в командной строке.

Только стандартная библиотека Python 3.8+. Ставить ничего не нужно.

    py b818panel.py                       # открыть, вход — на странице
    py b818panel.py --password СЕКРЕТ      # войти сразу
    py b818panel.py --router 192.168.1.1 --port 8099

Пароль уходит только на сам роутер (вход SCRAM-SHA-256), держится в памяти процесса
на время работы и никуда не сохраняется.
"""

import argparse
import base64
import binascii
import getpass
import hashlib
import hmac
import http.cookiejar
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class HuaweiError(Exception):
    def __init__(self, code, context=""):
        self.code = str(code)
        self.context = context
        super().__init__(f"Huawei error {code}" + (f" ({context})" if context else ""))


_AUTH_ERRORS = {"100003", "125003", "125002", "125001", "108006", "108003"}

# человекочитаемые сообщения по кодам ошибок Huawei
ERR_RU = {
    "100002": "операция не поддерживается этой прошивкой",
    "100003": "нужен вход",
    "100004": "роутер занят, повторите",
    "108001": "неверное имя пользователя",
    "108002": "неверный пароль",
    "108003": "уже выполнен вход в другом месте",
    "108005": "на роутере занято слишком много сессий входа — закройте веб-интерфейс "
              "192.168.1.1 в других вкладках/браузерах, подождите ~1–5 минут (или "
              "перезагрузите роутер) и повторите",
    "108006": "неверный пароль или имя пользователя",
    "108007": "слишком много попыток входа — роутер временно заблокировал вход",
    "125001": "неверный токен проверки",
    "125002": "неверная сессия",
    "125003": "неверный токен проверки",
}


def err_ru(code):
    return ERR_RU.get(str(code), f"код {code}")


def _x(s):
    """Экранирование значения для безопасной вставки в XML-запрос."""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&apos;"))


class HiLink:
    def __init__(self, host="192.168.1.1", username="admin", password=""):
        self.base = f"http://{host}"
        self.host = host
        self.username = username
        self.password = password
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))
        self.token = ""
        self.logged_in = False
        self.last_login_error = ""
        self._supported_mask = 0
        self._lock = threading.RLock()

    def set_host(self, host):
        """Сменить адрес роутера на лету (для пользователей с другой подсетью)."""
        host = (host or "").strip()
        if host and host != self.host:
            with self._lock:
                self.host = host
                self.base = f"http://{host}"
                self.jar.clear()
                self.token = ""
                self.logged_in = False
                self._supported_mask = 0

    # --- низкий уровень ----------------------------------------------------
    def _request(self, path, data=None, extra_headers=None, content_type=None, timeout=10):
        url = self.base + path
        headers = {"User-Agent": "B818-LTE-Panel", "X-Requested-With": "XMLHttpRequest"}
        if self.token:
            headers["__RequestVerificationToken"] = self.token
        if extra_headers:
            headers.update(extra_headers)
        body = None
        if data is not None:
            body = data.encode("utf-8")
            headers["Content-Type"] = content_type or "application/x-www-form-urlencoded; charset=UTF-8"
        req = urllib.request.Request(
            url, data=body, headers=headers, method="POST" if body is not None else "GET")
        resp = self.opener.open(req, timeout=timeout)
        raw = resp.read()
        nt = resp.headers.get("__RequestVerificationToken")
        if nt:
            self.token = nt.split("#")[0].split(",")[0].strip()
        return raw.decode("utf-8", "replace")

    @staticmethod
    def _parse(xml_text):
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return {}
        if root.tag == "error":
            raise HuaweiError((root.findtext("code") or "?").strip(), xml_text[:120])
        return {c.tag: (c.text or "").strip() for c in root}

    def _has_session_cookie(self):
        return any(c.name == "SessionID" for c in self.jar)

    def _sestok(self):
        """Обновляет токен проверки (и сессию при первом вызове)."""
        d = self._parse(self._request("/api/webserver/SesTokInfo"))
        self.token = d.get("TokInfo", "")
        ses = d.get("SesInfo", "")
        if ses and not self._has_session_cookie():
            ck = http.cookiejar.Cookie(
                0, "SessionID", ses, None, False, self.host, True, False, "/",
                True, False, None, True, None, None, {})
            self.jar.set_cookie(ck)

    # --- SCRAM-SHA-256 (password_type=4) -----------------------------------
    @staticmethod
    def _client_proof(first_nonce, server_nonce, password, salt, iterations):
        msg = f"{first_nonce},{server_nonce},{server_nonce}".encode()
        salted = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                     bytearray.fromhex(salt), iterations)
        client_key = hmac.new(b"Client Key", salted, hashlib.sha256).digest()
        stored = hashlib.sha256(client_key).digest()
        sig = hmac.new(msg, stored, hashlib.sha256).digest()
        return binascii.hexlify(bytes(a ^ b for a, b in zip(client_key, sig))).decode()

    def login(self, password=None, username=None):
        """Вход по паролю. Возвращает True при успехе."""
        with self._lock:
            if password is not None:
                self.password = password
            if username:
                self.username = username
            self.logged_in = False
            self.last_login_error = ""
            # сессию НЕ сбрасываем намеренно: каждая новая сессия занимает слот на
            # роутере и приводит к 108005 (too many users). Переиспользуем текущую,
            # только обновляем проверочный токен.
            self._sestok()
            if not self.password:
                return False
            # авто-определение способа входа по password_type роутера
            pt = "4"
            try:
                d = self._parse(self._request("/api/user/state-login"))
                pt = (d.get("password_type") or "4").strip() or "4"
            except (HuaweiError, urllib.error.URLError, OSError):
                pt = "4"
            try:
                if pt == "4":
                    self._login_scram()      # новые прошивки (10.x+): SCRAM-SHA-256
                else:
                    self._login_hash(pt)     # старые прошивки: SHA-256 /api/user/login
                self.logged_in = True
                return True
            except HuaweiError as e:
                self.last_login_error = e.code
                raise

    def _login_scram(self):
        first = binascii.hexlify(os.urandom(32)).decode()
        chal = ('<?xml version="1.0" encoding="UTF-8"?><request>'
                f"<username>{_x(self.username)}</username>"
                f"<firstnonce>{first}</firstnonce><mode>1</mode></request>")
        d = self._parse(self._request("/api/user/challenge_login", chal))
        salt, snonce = d.get("salt", ""), d.get("servernonce", "")
        iters = int(d.get("iterations", "0") or "0")
        if not (salt and snonce and iters):
            raise HuaweiError("?", "нет salt/servernonce")
        proof = self._client_proof(first, snonce, self.password, salt, iters)
        auth = ('<?xml version="1.0" encoding="UTF-8"?><request>'
                f"<clientproof>{proof}</clientproof>"
                f"<finalnonce>{snonce}</finalnonce></request>")
        self._parse(self._request("/api/user/authentication_login", auth))

    def _login_hash(self, pt):
        # старый способ Huawei: Password = b64(sha256(user + b64(sha256(pass)) + token))
        def sh(s):
            return hashlib.sha256(s.encode("utf-8")).hexdigest()

        def b64(s):
            return base64.b64encode(s.encode("utf-8")).decode()
        pwd = b64(sh(self.username + b64(sh(self.password)) + self.token))
        xml = ('<?xml version="1.0" encoding="UTF-8"?><request>'
               f"<Username>{_x(self.username)}</Username>"
               f"<Password>{pwd}</Password>"
               f"<password_type>{_x(pt)}</password_type></request>")
        self._parse(self._request("/api/user/login", xml))

    def logout(self):
        with self._lock:
            self.password = ""
            self.logged_in = False
            self.jar.clear()
            self.token = ""
            self._supported_mask = 0

    def _home_token(self):
        """Токен проверки из мета csrf_token страницы /html/home.html (как в рабочем
        букмарклете для этой прошивки): берём последний из списка."""
        try:
            html = self._request("/html/home.html")
            toks = re.findall(r'name="csrf_token"\s+content="([^"]+)"', html)
            if toks:
                self.token = toks[-1]
                return True
        except (urllib.error.URLError, OSError, HuaweiError):
            pass
        return False

    # --- вызовы с авто-переподключением ------------------------------------
    def get(self, path):
        with self._lock:
            try:
                return self._parse(self._request(path))
            except HuaweiError as e:
                if e.code in ("125001", "125002", "125003"):  # протух токен сессии
                    self._sestok()
                    return self._parse(self._request(path))
                if e.code in _AUTH_ERRORS and self.password:   # протухла авторизация
                    self.login()
                    return self._parse(self._request(path))
                raise

    def post(self, path, xml):
        """Изменяющий POST как в рабочем скрипте для этой прошивки: токен со страницы
        home.html, Content-Type application/xml. При протухании токена/сессии — повторить."""
        with self._lock:
            if not self.logged_in:
                raise HuaweiError("100003", "нужен вход")

            def _do():
                return self._parse(self._request(path, xml, content_type="application/xml"))

            if not self._home_token():   # старые прошивки: токена в home.html нет — берём из SesTokInfo
                self._sestok()
            try:
                return _do()
            except HuaweiError as e:
                if e.code in ("125001", "125002", "125003"):
                    self._home_token()
                    return _do()
                if e.code in _AUTH_ERRORS and self.password:
                    self.login()
                    self._home_token()
                    return _do()
                raise

    # --- управление --------------------------------------------------------
    def supported_band_mask(self):
        """Маска поддерживаемых LTE-диапазонов роутера (кэшируется)."""
        with self._lock:
            if self._supported_mask:
                return self._supported_mask
            mask = 0
            try:                                   # из списка поддерживаемых режимов
                raw = self._request("/api/net/net-mode-list")
                mm = re.search(r"<LTEBandList>(.*?)</LTEBandList>", raw, re.S)
                if mm:
                    for v in re.findall(r"<Value>\s*([0-9A-Fa-f]+)\s*</Value>", mm.group(1)):
                        try:
                            mask |= int(v, 16)
                        except ValueError:
                            pass
            except (urllib.error.URLError, OSError, HuaweiError):
                pass
            if not mask:                           # запасной путь: маска текущего «Авто»
                try:
                    d = self._parse(self._request("/api/net/net-mode"))
                    if d.get("NetworkMode") == "00":
                        mask = int(d.get("LTEBand", "0") or "0", 16)
                except (urllib.error.URLError, OSError, HuaweiError, ValueError):
                    pass
            self._supported_mask = mask
            return mask

    def set_netmode_raw(self, mode, networkband, lteband):
        """Прямой POST net-mode теми же полями, что и рабочий скрипт."""
        xml = ('<?xml version="1.0" encoding="UTF-8"?><request>'
               f"<NetworkMode>{mode}</NetworkMode>"
               f"<NetworkBand>{networkband or '3FFFFFFF'}</NetworkBand>"
               f"<LTEBand>{lteband}</LTEBand></request>")
        return self.post("/api/net/net-mode", xml)

    def set_band(self, mode, bands):
        """mode: '00' Авто (все поддерживаемые), '03' только выбранные LTE-диапазоны."""
        if mode == "00":
            sm = self.supported_band_mask()
            mask = format(sm, "X") if sm else "7FFFFFFFFFFFFFFF"
        else:
            m = 0
            for b in bands:
                m |= 1 << (int(b) - 1)
            if not m:                              # пусто → не трогаем, ставим Авто
                sm = self.supported_band_mask()
                return self.set_netmode_raw("00", "3FFFFFFF",
                                            format(sm, "X") if sm else "7FFFFFFFFFFFFFFF")
            mask = format(m, "X")
        return self.set_netmode_raw(mode, "3FFFFFFF", mask)

    def reboot(self):
        xml = ('<?xml version="1.0" encoding="UTF-8"?>'
               "<request><Control>1</Control></request>")
        return self.post("/api/device/control", xml)

    def cell_lock_status(self):
        try:
            return self.get("/api/device/cell_lock")
        except HuaweiError:
            try:
                return self.get("/api/net/cell_lock")
            except HuaweiError:
                return {}

    def cell_lock_set(self, enable, cell_id="", pci="", freq="", rat="7"):
        """Экспериментально: формат зависит от прошивки. Возвращает (ok, code/raw)."""
        if enable:
            xml = ('<?xml version="1.0" encoding="UTF-8"?><request>'
                   "<enable>1</enable>"
                   f"<ratType>{_x(rat)}</ratType>"
                   f"<cellId>{_x(cell_id)}</cellId>"
                   f"<physicalCellId>{_x(pci)}</physicalCellId>"
                   f"<frequency>{_x(freq)}</frequency></request>")
        else:
            xml = ('<?xml version="1.0" encoding="UTF-8"?>'
                   "<request><enable>0</enable></request>")
        return self.post("/api/device/cell_lock", xml)


# ---------------------------------------------------------------------------
def _num(s):
    if s is None:
        return None
    m = re.search(r"-?\d+(?:\.\d+)?", str(s))
    return float(m.group()) if m else None


def bands_from_mask(mask):
    """Hex-маска LTEBand или число → список номеров диапазонов."""
    if isinstance(mask, str):
        try:
            mask = int(mask, 16)
        except (TypeError, ValueError):
            return []
    try:
        mask = int(mask)
    except (TypeError, ValueError):
        return []
    return [i + 1 for i in range(64) if (mask >> i) & 1]


def collect(client):
    out = {"ts": int(time.time()), "logged_in": client.logged_in,
           "login_error": client.last_login_error, "errors": []}

    # во время сканирования НЕ опрашиваем роутер с главной — иначе конкурируем со
    # сканером за сессию (перелогины, таймауты, резко медленный скан)
    if SCAN["running"]:
        out["scanning"] = True
        return out

    def safe(key, path, auth=False):
        try:
            out[key] = client.get(path)
        except HuaweiError as e:
            out[key] = {}
            if not (auth and not client.logged_in):
                out["errors"].append(f"{path}: {e.code}")
        except (urllib.error.URLError, OSError) as e:
            out[key] = {}
            out["errors"].append(f"{path}: {e}")

    safe("status", "/api/monitoring/status")
    safe("plmn", "/api/net/current-plmn")
    safe("traffic", "/api/monitoring/traffic-statistics")
    safe("month", "/api/monitoring/month_statistics")
    safe("signal", "/api/device/signal", auth=True)
    safe("info", "/api/device/information", auth=True)
    if client.logged_in:
        safe("netmode", "/api/net/net-mode", auth=True)
        out["celllock"] = client.cell_lock_status()
        try:
            out["supported"] = bands_from_mask(client.supported_band_mask())
        except Exception:  # noqa: BLE001
            out["supported"] = []
    return out


# --- сканер диапазонов ------------------------------------------------------
# Перебирает band по одному: фиксирует роутер на нём, ждёт подключения, читает
# соту и сигнал, затем возвращает «Авто». Во время скана связь рвётся на каждом band.
SCAN = {"running": False, "abort": False, "done": False, "results": [],
        "current": None, "bands": [], "restored": True, "error": ""}
SCAN_LOCK = threading.Lock()


def run_scan(client, bands):
    SCAN.update(running=True, abort=False, done=False, results=[], current=None,
                bands=list(bands), restored=False, error="")
    # запоминаем текущий режим сети, чтобы в конце вернуть РОВНО его (а не угадывать «Авто»)
    orig = None
    try:
        orig = client.get("/api/net/net-mode")
    except Exception:  # noqa: BLE001
        orig = None
    try:
        for b in bands:
            if SCAN["abort"]:
                break
            SCAN["current"] = b
            try:
                client.set_band("03", [b])
            except Exception as e:  # noqa: BLE001
                SCAN["results"].append({"band": b, "connected": False, "error": str(e)})
                continue
            connected = False
            sg = {}
            for _ in range(6):                  # до ~6 с, но выходим сразу как подключились
                if SCAN["abort"]:
                    break
                time.sleep(1.0)
                try:
                    st = client.get("/api/monitoring/status")
                except Exception:  # noqa: BLE001
                    st = {}
                if str(st.get("ConnectionStatus")) == "901":
                    try:
                        sg = client.get("/api/device/signal")
                    except Exception:  # noqa: BLE001
                        sg = {}
                    if sg.get("cell_id"):
                        connected = True
                        break
            if not sg:                          # не подключился — один раз прочитать сигнал
                try:
                    sg = client.get("/api/device/signal")
                except Exception:  # noqa: BLE001
                    sg = {}
            SCAN["results"].append({
                "band": b, "connected": bool(connected and sg.get("cell_id")),
                "cell_id": sg.get("cell_id", ""), "pci": sg.get("pci", ""),
                "band_actual": sg.get("band", ""), "earfcn": sg.get("earfcn", ""),
                "rsrp": sg.get("rsrp", ""), "rsrq": sg.get("rsrq", ""),
                "sinr": sg.get("sinr", ""), "rssi": sg.get("rssi", "")})
    finally:
        # восстановить ТОЧНО исходный режим — до 3 попыток, чтобы связь гарантированно вернулась
        for attempt in range(3):
            try:
                if orig and orig.get("LTEBand"):
                    client.set_netmode_raw(orig.get("NetworkMode", "00"),
                                           orig.get("NetworkBand", "3FFFFFFF"),
                                           orig.get("LTEBand"))
                else:
                    client.set_band("00", [])
                SCAN["restored"] = True
                SCAN["error"] = ""
                break
            except Exception as e:  # noqa: BLE001
                SCAN["error"] = "не удалось вернуть исходный режим: " + str(e)
                time.sleep(2)
        SCAN["current"] = None
        SCAN["running"] = False
        SCAN["done"] = True


# ---------------------------------------------------------------------------
PAGE = None


def load_page():
    global PAGE
    # В собранном exe (PyInstaller --onefile) ресурсы лежат в sys._MEIPASS
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(base, "dashboard.html"), "r", encoding="utf-8") as f:
        PAGE = f.read()


class Handler(BaseHTTPRequestHandler):
    client = None

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, ensure_ascii=False),
                   "application/json; charset=utf-8")

    def _host_ok(self):
        # запросы принимаем только с localhost (защита от DNS-rebinding)
        h = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip().strip("[]").lower()
        return h in ("localhost", "127.0.0.1", "::1", "")

    def _csrf_ok(self):
        # управляющие POST: только application/json и, если браузер прислал Origin, —
        # локальный (блокирует межсайтовые запросы со сторонних страниц)
        ctype = (self.headers.get("Content-Type") or "").lower()
        if not ctype.startswith("application/json"):
            return False
        origin = (self.headers.get("Origin") or "").lower()
        if origin and not (origin.startswith("http://localhost")
                           or origin.startswith("http://127.0.0.1")):
            return False
        return True

    def do_GET(self):
        if not self._host_ok():
            self._send(403, "forbidden", "text/plain; charset=utf-8")
            return
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif path == "/api/data":
            try:
                self._json(collect(self.client))
            except Exception as e:  # noqa: BLE001
                self._json({"fatal": str(e)})
        elif path == "/ctl/scan/status":
            self._json({**SCAN, "results": list(SCAN["results"])})
        else:
            self._send(404, "not found", "text/plain; charset=utf-8")

    def _body_json(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n <= 0 or n > 65536:          # лимит тела запроса
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, UnicodeError):
            return {}

    def do_POST(self):
        if not self._host_ok() or not self._csrf_ok():
            self._send(403, "forbidden", "text/plain; charset=utf-8")
            return
        path = self.path.split("?")[0]
        body = self._body_json()
        c = self.client
        try:
            if path == "/ctl/login":
                try:
                    if body.get("router"):
                        c.set_host(body.get("router"))
                    ok = c.login(password=body.get("password", ""),
                                 username=body.get("username") or "admin")
                    self._json({"ok": ok, "logged_in": c.logged_in})
                except HuaweiError as e:
                    self._json({"ok": False, "code": e.code, "error": err_ru(e.code)})
                return
            if path == "/ctl/logout":
                c.logout()
                self._json({"ok": True})
                return
            if path == "/ctl/quit":
                self._json({"ok": True})
                threading.Thread(target=lambda: (time.sleep(0.4), os._exit(0)),
                                 daemon=True).start()
                return
            # дальше — только для вошедших
            if not c.logged_in:
                self._json({"ok": False, "error": "нужен вход"})
                return
            if path == "/ctl/reboot":
                c.reboot()
                self._json({"ok": True})
            elif path == "/ctl/setband":
                c.set_band(body.get("mode", "00"), body.get("bands", []))
                self._json({"ok": True})
            elif path == "/ctl/celllock":
                try:
                    r = c.cell_lock_set(
                        bool(body.get("enable")), body.get("cell_id", ""),
                        body.get("pci", ""), body.get("freq", ""),
                        body.get("rat", "7"))
                    self._json({"ok": True, "raw": r})
                except HuaweiError as e:
                    # 100003/100002 здесь = роутер отклонил операцию (при выполненном входе),
                    # т.е. прошивка B818 не поддерживает привязку к соте через API
                    msg = ("привязка к соте не поддерживается этой прошивкой роутера"
                           if e.code in ("100003", "100002", "100005", "125004")
                           else err_ru(e.code))
                    self._json({"ok": False, "code": e.code, "error": msg})
            elif path == "/ctl/scan/start":
                with SCAN_LOCK:
                    if SCAN["running"]:
                        self._json({"ok": False, "error": "скан уже идёт"})
                        return
                    bands = body.get("bands")
                    if not bands:                       # по умолчанию — поддерживаемые
                        try:
                            bands = bands_from_mask(c.supported_band_mask())
                        except Exception:  # noqa: BLE001
                            bands = []
                    if not bands:
                        bands = [1, 3, 7, 8, 20, 38]
                    try:
                        bands = [int(x) for x in bands]
                    except (TypeError, ValueError):
                        self._json({"ok": False, "error": "неверный список диапазонов"})
                        return
                    threading.Thread(target=run_scan, args=(c, bands), daemon=True).start()
                self._json({"ok": True})
            elif path == "/ctl/scan/stop":
                SCAN["abort"] = True
                self._json({"ok": True})
            else:
                self._json({"ok": False, "error": "неизвестное действие"}, 404)
        except HuaweiError as e:
            self._json({"ok": False, "code": e.code, "error": err_ru(e.code)})
        except (urllib.error.URLError, OSError) as e:
            self._json({"ok": False, "error": f"нет связи с роутером: {e}"})


def main():
    # В собранном exe без консоли (--windowed) stdout/stderr = None → print упал бы
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")

    ap = argparse.ArgumentParser(description="LTE-панель и пульт для Huawei B818 (HiLink).")
    ap.add_argument("--router", default=os.environ.get("B818_ROUTER", "192.168.1.1"))
    ap.add_argument("--username", default=os.environ.get("B818_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("B818_PASSWORD"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("B818_PORT", "8099")))
    ap.add_argument("--ask-password", action="store_true",
                    help="спросить пароль в консоли при старте (можно и на странице)")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    password = args.password or ""
    if not password and args.ask_password:
        try:
            password = getpass.getpass("Пароль (Enter — вход позже на странице): ")
        except (EOFError, KeyboardInterrupt):
            password = ""

    load_page()
    client = HiLink(args.router, args.username, password)
    print(f"Роутер: {args.router}")
    if password:
        try:
            if client.login():
                print("  вход выполнен.")
        except HuaweiError as e:
            print(f"  вход не удался: {err_ru(e.code)} (код {e.code}). Можно войти на странице.")
        except (urllib.error.URLError, OSError) as e:
            print(f"  нет связи с роутером: {e}")
    else:
        print("  вход — на открывшейся странице (поле пароля).")

    Handler.client = client
    # подбираем свободный порт, если заданный занят (например, уже запущена панель)
    httpd = None
    port = args.port
    for p in range(args.port, args.port + 20):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", p), Handler)
            port = p
            break
        except OSError:
            continue
    if httpd is None:
        print("Не удалось занять ни один порт — закройте лишние экземпляры панели.")
        return
    url = f"http://localhost:{port}/"
    print(f"\nПанель: {url}\nОстановить — кнопка «Выключить панель» на странице или Ctrl+C\n")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")
        httpd.shutdown()


if __name__ == "__main__":
    main()
