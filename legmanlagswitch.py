
import os
import sys
import json
import time
import ctypes
import winreg
import threading
import subprocess

from PySide6 import QtCore, QtGui, QtWidgets, QtSvg
from PySide6.QtCore import Qt


if getattr(sys, "frozen", False):
    _APP_DIR = os.path.dirname(sys.executable)
else:
    _APP_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_DIR = os.path.join(os.environ.get("APPDATA", _APP_DIR), "LegmanLagSwitch")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
_LEGACY_CONFIG = os.path.join(_APP_DIR, "config.json")


def resource_path(name):
    """Path to a bundled resource (works both as .py and as a PyInstaller exe)."""
    base = getattr(sys, "_MEIPASS", _APP_DIR)
    return os.path.join(base, name)

RULE_NAME = "LagSwitch_Block"
LEGACY_RULES = ("LagSwitch_Block_Out", "LagSwitch_Block_In")
PANIC_VK = 0x1B

DEFAULTS = {"vk": 0x45, "key_name": "E", "mode": "toggle", "method": "firewall"}


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Keyboard input via polling (no hook -> not blocked by game anti-cheat)
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

_user32 = ctypes.windll.user32
_user32.GetAsyncKeyState.restype = ctypes.c_short
_user32.GetAsyncKeyState.argtypes = [ctypes.c_int]


def key_down(vk):
    return (_user32.GetAsyncKeyState(vk) & 0x8000) != 0


def any_key_down():
    return any(key_down(vk) for vk in range(0x07, 0xFF))


def capture_key():
    """Block until a key is pressed; return its virtual-key code."""
    while any_key_down():
        time.sleep(0.01)
    while True:
        for vk in range(0x07, 0xFF):
            if vk in (0x01, 0x02, 0x04):
                continue
            if key_down(vk):
                return vk
        time.sleep(0.005)


def vk_name(vk):
    scan = _user32.MapVirtualKeyW(vk, 0)
    buf = ctypes.create_unicode_buffer(64)
    if scan and _user32.GetKeyNameTextW(scan << 16, buf, 64) > 0:
        return buf.value
    return f"VK_0x{vk:02X}"


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Elevation
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    params = " ".join('"{}"'.format(a.replace('"', "")) for a in sys.argv)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    if rc <= 32:
        ctypes.windll.user32.MessageBoxW(
            None, "LagSwitch needs admin rights to run.", "LagSwitch", 0x10)
    sys.exit(0)


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Network controllers
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def _run(cmd, check=True):
    return subprocess.run(
        cmd, check=check,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


class FirewallController:
    """Toggles two pre-made firewall rules on/off — near-instant packet drop."""

    def __init__(self):
        self._lock = threading.Lock()
        self.disabled = False

    def setup(self):
        self._delete_rules()
        _run(["netsh", "advfirewall", "firewall", "add", "rule",
              f"name={RULE_NAME}", "dir=out", "action=block", "enable=no"])
        _run(["netsh", "advfirewall", "firewall", "add", "rule",
              f"name={RULE_NAME}", "dir=in", "action=block", "enable=no"])

    def _set(self, enable):
        state = "yes" if enable else "no"
        _run(["netsh", "advfirewall", "firewall", "set", "rule",
              f"name={RULE_NAME}", "new", f"enable={state}"])

    def _delete_rules(self):
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_NAME}"], check=False)
        for legacy in LEGACY_RULES:
            _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={legacy}"], check=False)

    def disable(self):
        with self._lock:
            if self.disabled:
                return
            try:
                self._set(True)
                self.disabled = True
            except subprocess.CalledProcessError:
                pass

    def enable(self):
        with self._lock:
            if not self.disabled:
                return
            try:
                self._set(False)
                self.disabled = False
            except subprocess.CalledProcessError:
                pass

    def teardown(self):
        try:
            self._delete_rules()
        except Exception:
            pass
        self.disabled = False


class DhcpController:
    """The original ipconfig /release + /renew approach."""

    def __init__(self):
        self._lock = threading.Lock()
        self.disabled = False

    def setup(self):
        pass

    def disable(self):
        with self._lock:
            if self.disabled:
                return
            try:
                _run(["ipconfig", "/release"])
                self.disabled = True
            except subprocess.CalledProcessError:
                pass

    def enable(self):
        with self._lock:
            if not self.disabled:
                return
            try:
                _run(["ipconfig", "/renew"])
                self.disabled = False
            except subprocess.CalledProcessError:
                pass

    def teardown(self):
        if self.disabled:
            try:
                _run(["ipconfig", "/renew"])
            except subprocess.CalledProcessError:
                _run(["ipconfig", "/renew"], check=False)
            self.disabled = False


class WinDivertController:
    """Roblox-targeted packet drop via the WinDivert driver (pydivert).

    Unlike firewall/DHCP, this cuts ONLY the Roblox process's traffic — the
    rest of your PC (Discord, browser, etc.) stays online. A single kernel-mode
    handle opened with FLAG_DROP does the dropping; closing it restores flow.
    """

    ROBLOX_NAMES = {"robloxplayerbeta.exe", "robloxplayer.exe"}

    def __init__(self):
        self._lock = threading.Lock()
        self.disabled = False
        self.note = ""
        self._handle = None

    def setup(self):
        import pydivert
        with pydivert.WinDivert("false", flags=pydivert.Flag.SNIFF):
            pass

    def _roblox_udp_ports(self):
        import psutil
        pids = {p.pid for p in psutil.process_iter(["name"])
                if (p.info.get("name") or "").lower() in self.ROBLOX_NAMES}
        if not pids:
            return set()
        ports = set()
        for conn in psutil.net_connections(kind="udp"):
            if conn.pid in pids and conn.laddr:
                ports.add(conn.laddr.port)
        return ports

    @staticmethod
    def _build_filter(ports):
        clauses = []
        for port in sorted(ports):
            clauses.append(f"(outbound and udp.SrcPort == {port})")
            clauses.append(f"(inbound and udp.DstPort == {port})")
        return " or ".join(clauses)

    def disable(self):
        with self._lock:
            if self.disabled:
                return
            ports = self._roblox_udp_ports()
            if not ports:
                self.note = "roblox not running — nothing to cut"
                self.disabled = True
                return
            import pydivert
            try:
                handle = pydivert.WinDivert(self._build_filter(ports), flags=pydivert.Flag.DROP)
                handle.open()
                self._handle = handle
                self.note = f"cutting roblox · {len(ports)} port(s)"
                self.disabled = True
            except Exception:
                self.note = "windivert failed to open"

    def enable(self):
        with self._lock:
            if not self.disabled:
                return
            if self._handle is not None:
                try:
                    self._handle.close()
                except Exception:
                    pass
                self._handle = None
            self.disabled = False
            self.note = ""

    def teardown(self):
        self.enable()


def make_controller(method):
    if method == "windivert":
        return WinDivertController()
    if method == "dhcp":
        return DhcpController()
    return FirewallController()


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Windows notification silencer
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

class NotificationSilencer:
    """
    Flips Windows' master "Notifications" toggles off while active and restores
    them afterwards, so no toast banners pop up over your game. We remember the
    previous values and put them back, so we never leave you permanently muted.
    """

    _KEYS = [
        (r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings",
         "NOC_GLOBAL_SETTING_TOASTS_ENABLED"),
        (r"Software\Microsoft\Windows\CurrentVersion\PushNotifications",
         "ToastEnabled"),
    ]

    def __init__(self):
        self._saved = {}
        self._active = False

    def silence(self):
        if self._active:
            return
        for path, name in self._KEYS:
            self._saved[(path, name)] = self._read(path, name)
            self._write(path, name, 0)
        self._active = True

    def restore(self):
        if not self._active:
            return
        for path, name in self._KEYS:
            prev = self._saved.get((path, name))
            self._write(path, name, 1 if prev is None else prev)
        self._active = False

    @staticmethod
    def _read(path, name):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as k:
                return winreg.QueryValueEx(k, name)[0]
        except OSError:
            return None

    @staticmethod
    def _write(path, name, value):
        try:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0,
                                    winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(value))
        except OSError:
            pass


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Config
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

def _valid_vk(vk):
    return isinstance(vk, int) and 0x07 <= vk <= 0xFE


def _config_source():
    if os.path.exists(CONFIG_PATH):
        return CONFIG_PATH
    if os.path.exists(_LEGACY_CONFIG):
        return _LEGACY_CONFIG
    return None


def load_config():
    cfg = dict(DEFAULTS)
    path = _config_source()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if _valid_vk(data.get("vk")):
                cfg["vk"] = data["vk"]
                cfg["key_name"] = str(data.get("key_name") or vk_name(data["vk"]))[:32]
            if data.get("mode") in ("toggle", "hold"):
                cfg["mode"] = data["mode"]
            if data.get("method") in ("firewall", "dhcp", "windivert"):
                cfg["method"] = data["method"]
        except (json.JSONDecodeError, OSError):
            pass
    return cfg


def save_config(cfg):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except OSError:
        pass


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Qt: styling (matches Legman Tracker)
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

STYLESHEET = """
#card {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #15212c, stop:1 #0c141b);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 16px;
}
QLabel { color: #e6edf3; }
#title { color: #f0f4f8; font-size: 13px; font-weight: 700; }
#caption { color: #5d6b76; font-size: 10px; font-weight: 700; }

#iconBtn {
    background: transparent; border: none; border-radius: 8px;
    color: #8b98a4; font-size: 15px; padding: 4px;
}
#iconBtn:hover { background: rgba(255,255,255,0.07); color: #e6edf3; }

#updCard {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #18242f, stop:1 #121b23);
    border: 1px solid rgba(255,255,255,0.05);
    border-radius: 12px;
}
#setLabel { color: #e6edf3; font-size: 12px; font-weight: 600; }
#setDesc { color: #6f7d88; font-size: 10px; }
#keyName { color: #00d488; font-size: 15px; font-weight: 800; }

#chip {
    background: #16212b; border: 1px solid rgba(255,255,255,0.06); border-radius: 9px;
    color: #9aa7b2; font-size: 12px; font-weight: 600; padding: 7px 0px;
}
#chip:hover { color: #cdd8e0; }
#chip:checked {
    background: rgba(0,212,136,0.16); color: #00d488; border: 1px solid rgba(0,212,136,0.35);
}
#chip:disabled { color: #4a5762; }

#bindBtn {
    background: #16212b; border: 1px solid rgba(255,255,255,0.06); border-radius: 9px;
    color: #9aa7b2; font-size: 11px; font-weight: 700; padding: 7px 14px;
}
#bindBtn:hover { color: #cdd8e0; border: 1px solid rgba(0,212,136,0.35); }
#bindBtn:disabled { color: #4a5762; }

#statusText { font-size: 13px; font-weight: 700; }

#startBtn {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #00d488, stop:1 #00b372);
    border: none; border-radius: 10px; color: #04231a;
    font-size: 12px; font-weight: 700; padding: 10px 16px;
}
#startBtn:hover { background: #12e095; }
#startBtn:pressed { background: #00b372; }
#startBtn:disabled { background: #1a242e; color: #4a5762; }

#stopBtn {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
        stop:0 #e85050, stop:1 #c73e3e);
    border: none; border-radius: 10px; color: #2a0808;
    font-size: 12px; font-weight: 700; padding: 10px 16px;
}
#stopBtn:hover { background: #f06060; }
#stopBtn:pressed { background: #c73e3e; }
#stopBtn:disabled { background: #1a242e; color: #4a5762; }
"""

STATUS_COLORS = {"idle": "#7d8b97", "online": "#00d488", "cut": "#e85050"}

ICON_SVGS = {
    "close": '<line x1="6" y1="6" x2="18" y2="18"/><line x1="18" y1="6" x2="6" y2="18"/>',
    "min": '<line x1="5" y1="12" x2="19" y2="12"/>',
}

_SVG_WRAP = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
             'stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">{body}</svg>')


def svg_icon(name, size=15, color="#8b98a4"):
    svg = _SVG_WRAP.format(c=color, body=ICON_SVGS[name])
    renderer = QtSvg.QSvgRenderer(QtCore.QByteArray(svg.encode("utf-8")))
    scale = 2
    pm = QtGui.QPixmap(size * scale, size * scale)
    pm.fill(Qt.transparent)
    p = QtGui.QPainter(pm)
    p.setRenderHint(QtGui.QPainter.Antialiasing)
    renderer.render(p)
    p.end()
    pm.setDevicePixelRatio(scale)
    return QtGui.QIcon(pm)


def app_icon_pixmap(size=26):
    app = QtWidgets.QApplication.instance()
    dpr = float(app.devicePixelRatio()) if app is not None else 1.0
    if dpr < 1.0:
        dpr = 1.0
    px = max(1, round(size * dpr))
    pm = None
    path = resource_path("LagSwitch.ico")
    if os.path.exists(path):
        ic = QtGui.QIcon(path)
        if not ic.isNull():
            big = ic.pixmap(256, 256)
            if not big.isNull():
                pm = big.scaled(px, px, Qt.KeepAspectRatio, Qt.SmoothTransformation)
    if pm is None or pm.isNull():
        pm = QtGui.QPixmap(px, px)
        pm.fill(Qt.transparent)
    pm.setDevicePixelRatio(dpr)
    return pm


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
# Qt: widgets
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

class Signals(QtCore.QObject):
    bind_captured = QtCore.Signal(int)


class LagSwitchWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.cfg = load_config()
        self.net = None
        self.silencer = NotificationSilencer()
        self.running = False
        self.capturing = False
        self._drag_pos = None

        self.signals = Signals()
        self.signals.bind_captured.connect(self._bind_done)

        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint | Qt.NoDropShadowWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setWindowTitle("Legman LagSwitch")
        self.setFixedWidth(384)
        self._build()

        self._status_timer = QtCore.QTimer(self)
        self._status_timer.setInterval(80)
        self._status_timer.timeout.connect(self._refresh_status)

        self._last_status = None
        self._set_status("idle", "idle — press start")

    def _build(self):
        outer = QtWidgets.QVBoxLayout(self)
        outer.setContentsMargins(16, 16, 16, 16)

        card = QtWidgets.QFrame()
        card.setObjectName("card")
        self.card = card
        outer.addWidget(card)

        v = QtWidgets.QVBoxLayout(card)
        v.setContentsMargins(16, 14, 16, 16)
        v.setSpacing(10)

        header = QtWidgets.QHBoxLayout()
        header.setSpacing(9)
        logo = QtWidgets.QLabel()
        logo.setPixmap(app_icon_pixmap(26))
        logo.setFixedSize(26, 26)
        header.addWidget(logo)
        title = QtWidgets.QLabel("LEGMAN LAGSWITCH")
        title.setObjectName("title")
        f = title.font()
        f.setLetterSpacing(QtGui.QFont.AbsoluteSpacing, 1.6)
        title.setFont(f)
        header.addWidget(title)
        header.addStretch(1)
        minb = QtWidgets.QPushButton()
        minb.setObjectName("iconBtn")
        minb.setCursor(Qt.PointingHandCursor)
        minb.setFixedSize(28, 28)
        minb.setIcon(svg_icon("min"))
        minb.setIconSize(QtCore.QSize(15, 15))
        minb.clicked.connect(self.showMinimized)
        header.addWidget(minb)
        closeb = QtWidgets.QPushButton()
        closeb.setObjectName("iconBtn")
        closeb.setCursor(Qt.PointingHandCursor)
        closeb.setFixedSize(28, 28)
        closeb.setIcon(svg_icon("close"))
        closeb.setIconSize(QtCore.QSize(15, 15))
        closeb.clicked.connect(self.close)
        header.addWidget(closeb)
        v.addLayout(header)

        v.addWidget(self._caption("BIND KEY"))
        bind_card = QtWidgets.QFrame()
        bind_card.setObjectName("updCard")
        bl = QtWidgets.QHBoxLayout(bind_card)
        bl.setContentsMargins(12, 10, 12, 10)
        bl.setSpacing(10)
        cur = QtWidgets.QLabel("current")
        cur.setObjectName("setLabel")
        bl.addWidget(cur)
        self.key_lbl = QtWidgets.QLabel(self.cfg["key_name"])
        self.key_lbl.setObjectName("keyName")
        bl.addWidget(self.key_lbl)
        bl.addStretch(1)
        self.bind_btn = QtWidgets.QPushButton("SET BIND KEY")
        self.bind_btn.setObjectName("bindBtn")
        self.bind_btn.setCursor(Qt.PointingHandCursor)
        self.bind_btn.clicked.connect(self.set_bind)
        bl.addWidget(self.bind_btn)
        v.addWidget(bind_card)

        v.addWidget(self._caption("MODE"))
        self.mode_chips, mode_row = self._chip_row(
            [("toggle", "TOGGLE"), ("hold", "HOLD")],
            self.cfg["mode"], self._on_mode)
        v.addWidget(mode_row)
        self.mode_desc = QtWidgets.QLabel()
        self.mode_desc.setObjectName("setDesc")
        v.addWidget(self.mode_desc)
        self._update_mode_desc()

        v.addWidget(self._caption("METHOD"))
        self.method_chips, method_row = self._chip_row(
            [("firewall", "FIREWALL"), ("dhcp", "DHCP"), ("windivert", "WINDIVERT")],
            self.cfg["method"], self._on_method)
        v.addWidget(method_row)
        self.method_desc = QtWidgets.QLabel()
        self.method_desc.setObjectName("setDesc")
        v.addWidget(self.method_desc)
        self._update_method_desc()

        v.addWidget(self._caption("STATUS"))
        status_card = QtWidgets.QFrame()
        status_card.setObjectName("updCard")
        sl = QtWidgets.QVBoxLayout(status_card)
        sl.setContentsMargins(12, 10, 12, 10)
        sl.setSpacing(3)
        self.status_lbl = QtWidgets.QLabel("")
        self.status_lbl.setObjectName("statusText")
        sl.addWidget(self.status_lbl)
        panic = QtWidgets.QLabel(f"panic key: {vk_name(PANIC_VK)}  (always restores)")
        panic.setObjectName("setDesc")
        sl.addWidget(panic)
        v.addWidget(status_card)

        btns = QtWidgets.QHBoxLayout()
        btns.setSpacing(8)
        self.start_btn = QtWidgets.QPushButton("start")
        self.start_btn.setObjectName("startBtn")
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.clicked.connect(self.start)
        self.stop_btn = QtWidgets.QPushButton("stop")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setCursor(Qt.PointingHandCursor)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop)
        btns.addWidget(self.start_btn, 1)
        btns.addWidget(self.stop_btn, 1)
        v.addLayout(btns)

    @staticmethod
    def _caption(text):
        lbl = QtWidgets.QLabel(text)
        lbl.setObjectName("caption")
        f = lbl.font()
        f.setLetterSpacing(QtGui.QFont.AbsoluteSpacing, 1.0)
        lbl.setFont(f)
        return lbl

    def _chip_row(self, options, current, handler):
        row = QtWidgets.QFrame()
        h = QtWidgets.QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(6)
        grp = QtWidgets.QButtonGroup(row)
        grp.setExclusive(True)
        chips = {}
        for value, label in options:
            b = QtWidgets.QPushButton(label)
            b.setObjectName("chip")
            b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor)
            if value == current:
                b.setChecked(True)
            b.clicked.connect(lambda _=False, val=value: handler(val))
            grp.addButton(b)
            h.addWidget(b, 1)
            chips[value] = b
        return chips, row

    def _on_mode(self, value):
        self.cfg["mode"] = value
        save_config(self.cfg)
        self._update_mode_desc()

    def _on_method(self, value):
        self.cfg["method"] = value
        save_config(self.cfg)
        self._update_method_desc()

    def _update_mode_desc(self):
        self.mode_desc.setText(
            "press to cut, press again to restore" if self.cfg["mode"] == "toggle"
            else "cut only while the key is held")

    def _update_method_desc(self):
        descs = {
            "firewall": "fast, instant — cuts ALL traffic (ethernet + wi-fi)  (recommended)",
            "dhcp": "slow ipconfig reset — cuts ALL traffic (ethernet only)",
            "windivert": "cuts ONLY Roblox, rest of PC stays online (needs driver)",
        }
        self.method_desc.setText(descs.get(self.cfg["method"], ""))

    def _set_config_enabled(self, enabled):
        self.bind_btn.setEnabled(enabled)
        for chips in (self.mode_chips, self.method_chips):
            for b in chips.values():
                b.setEnabled(enabled)

    def _set_status(self, state, text):
        if self._last_status == (state, text):
            return
        self._last_status = (state, text)
        color = STATUS_COLORS.get(state, STATUS_COLORS["idle"])
        self.status_lbl.setText(f"●  {text}")
        self.status_lbl.setStyleSheet(f"color: {color};")

    def _refresh_status(self):
        net = self.net
        if not self.running or net is None:
            return
        note = getattr(net, "note", "")
        if net.disabled:
            self._set_status("cut", note or "cut — packets dropping")
        else:
            self._set_status("online", "connected — traffic flowing")

    def set_bind(self):
        if self.running or self.capturing:
            return
        self.capturing = True
        self.key_lbl.setText("press a key…")
        self.bind_btn.setEnabled(False)

        def worker():
            vk = capture_key()
            self.signals.bind_captured.emit(vk)

        threading.Thread(target=worker, daemon=True).start()

    def _bind_done(self, vk):
        self.cfg["vk"] = vk
        self.cfg["key_name"] = vk_name(vk)
        self.key_lbl.setText(self.cfg["key_name"])
        self.bind_btn.setEnabled(True)
        self.capturing = False
        save_config(self.cfg)

    def start(self):
        if self.running:
            return
        self.net = make_controller(self.cfg["method"])
        try:
            self.net.setup()
        except Exception as e:
            hint = ("\n\nWinDivert needs its driver — antivirus or Secure Boot "
                    "may be blocking it.") if self.cfg["method"] == "windivert" else ""
            QtWidgets.QMessageBox.critical(
                self, "Legman LagSwitch",
                f"Couldn't set up the {self.cfg['method']} method:\n{e}{hint}")
            self.net = None
            return

        self.silencer.silence()

        self.running = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_config_enabled(False)
        threading.Thread(target=self._poll_loop, daemon=True).start()
        self._status_timer.start()
        self._refresh_status()

    def stop(self):
        self.running = False
        self._status_timer.stop()
        time.sleep(0.02)
        if self.net:
            self.net.teardown()
            self.net = None
        self.silencer.restore()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._set_config_enabled(True)
        self._set_status("idle", "idle — press start")

    def _poll_loop(self):
        net = self.net
        if net is None:
            return
        vk = self.cfg["vk"]
        toggle = self.cfg["mode"] == "toggle"
        prev = key_down(vk)
        ppanic = key_down(PANIC_VK)
        while self.running:
            down = key_down(vk)
            if down and not prev:
                if toggle:
                    net.enable() if net.disabled else net.disable()
                else:
                    net.disable()
            elif not down and prev and not toggle:
                net.enable()
            prev = down

            if PANIC_VK != vk:
                p = key_down(PANIC_VK)
                if p and not ppanic and net.disabled:
                    net.enable()
                ppanic = p
            time.sleep(0.006)

    def closeEvent(self, e):
        try:
            self.running = False
            self._status_timer.stop()
            if self.net:
                self.net.teardown()
            self.silencer.restore()
        finally:
            e.accept()

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._drag_pos = e.globalPosition().toPoint() - self.frameGeometry().topLeft()
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e):
        if self._drag_pos is not None and (e.buttons() & Qt.LeftButton):
            self.move(e.globalPosition().toPoint() - self._drag_pos)
        super().mouseMoveEvent(e)

    def mouseReleaseEvent(self, e):
        self._drag_pos = None
        super().mouseReleaseEvent(e)

    def center_on_screen(self):
        self.adjustSize()
        scr = QtWidgets.QApplication.primaryScreen().availableGeometry()
        geo = self.frameGeometry()
        geo.moveCenter(scr.center())
        self.move(geo.topLeft())

    def paintEvent(self, _):
        card = getattr(self, "card", None)
        if card is None:
            return
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        base = QtCore.QRectF(card.geometry()).translated(0, 5)
        layers = 13
        for i in range(layers, 0, -1):
            p.setBrush(QtGui.QColor(0, 0, 0, 7))
            p.drawRoundedRect(base.adjusted(-i, -i, i, i), 16 + i, 16 + i)


def main():
    if not is_admin():
        relaunch_as_admin()

    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Legman.LagSwitch")
    except Exception:
        pass

    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("Legman LagSwitch")
    app.setWindowIcon(QtGui.QIcon(resource_path("LagSwitch.ico")))
    app.setStyleSheet(STYLESHEET)

    win = LagSwitchWindow()
    win.center_on_screen()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
