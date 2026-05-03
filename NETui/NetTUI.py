#!/usr/bin/env python3

import curses
import curses.textpad
import ipaddress
import re
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime


REFRESH_SECONDS = 0.5
PING_SAMPLE_SECONDS = 2
DEFAULT_CHECK_INTERVAL = 30
PING_HISTORY_SIZE = 15
TARGET_CARD_HEIGHT = 7


@dataclass
class PingStats:
    target: str
    display_name: str = ""
    sent: int = 0
    received: int = 0
    last_latency_ms: float | None = None
    last_status: str = "waiting"
    last_error: str = ""
    min_latency_ms: float | None = None
    max_latency_ms: float | None = None
    total_latency_ms: float = 0.0
    recent_results: deque[bool] = field(default_factory=lambda: deque(maxlen=PING_HISTORY_SIZE))
    updated_at: float = field(default_factory=time.time)

    @property
    def packet_loss_percent(self) -> float:
        if not self.recent_results:
            return 0.0
        successes = sum(1 for result in self.recent_results if result)
        return ((len(self.recent_results) - successes) / len(self.recent_results)) * 100

    @property
    def avg_latency_ms(self) -> float | None:
        if self.received == 0:
            return None
        return self.total_latency_ms / self.received


@dataclass
class ConnectivityState:
    enabled: bool = True
    interval_seconds: int = DEFAULT_CHECK_INTERVAL
    target: str = ""
    status: str = "no target"
    ping_ms: float | None = None
    resolved_host: str = ""
    last_error: str = ""
    last_run_at: float | None = None


@dataclass
class ConnectionEntry:
    protocol: str
    local_address: str
    remote_address: str
    state: str
    process: str


class NetworkMonitorModel:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.monitored_targets: dict[str, PingStats] = {}
        self.ping_workers: dict[str, threading.Thread] = {}
        self.connectivity = ConnectivityState()
        self.connections: deque[ConnectionEntry] = deque(maxlen=32)
        self.events: deque[str] = deque(maxlen=8)

    def log(self, message: str) -> None:
        with self.lock:
            timestamp = datetime.now().strftime("%H:%M:%S")
            self.events.appendleft(f"{timestamp} {message}")

    def add_target(self, target: str) -> None:
        normalized = normalize_ping_target(target)
        with self.lock:
            if normalized in self.monitored_targets:
                raise ValueError(f"{normalized} is already being monitored")
            self.monitored_targets[normalized] = PingStats(target=normalized)

        worker = threading.Thread(target=self._ping_worker, args=(normalized,), daemon=True)
        with self.lock:
            self.ping_workers[normalized] = worker
        worker.start()
        self.log(f"Added {normalized}")

    def remove_target(self, target: str) -> None:
        with self.lock:
            removed = self.monitored_targets.pop(target, None)
            self.ping_workers.pop(target, None)
        if removed is not None:
            self.log(f"Removed {target}")

    def rename_target(self, target: str, display_name: str) -> None:
        with self.lock:
            stats = self.monitored_targets.get(target)
            if stats is None:
                raise ValueError("Selected target no longer exists")
            stats.display_name = display_name.strip()
        action = "Cleared name" if not display_name.strip() else f"Named {target} as {display_name.strip()}"
        self.log(action)

    def list_targets(self) -> list[PingStats]:
        with self.lock:
            return [self.monitored_targets[key] for key in sorted(self.monitored_targets)]

    def update_connections(self, rows: list[ConnectionEntry]) -> None:
        with self.lock:
            self.connections.clear()
            self.connections.extend(rows)

    def snapshot_connections(self) -> list[ConnectionEntry]:
        with self.lock:
            return list(self.connections)

    def snapshot_events(self) -> list[str]:
        with self.lock:
            return list(self.events)

    def snapshot_connectivity(self) -> ConnectivityState:
        with self.lock:
            state = self.connectivity
            return ConnectivityState(
                enabled=state.enabled,
                interval_seconds=state.interval_seconds,
                target=state.target,
                status=state.status,
                ping_ms=state.ping_ms,
                resolved_host=state.resolved_host,
                last_error=state.last_error,
                last_run_at=state.last_run_at,
            )

    def toggle_connectivity(self) -> None:
        with self.lock:
            self.connectivity.enabled = not self.connectivity.enabled
            enabled = self.connectivity.enabled
            if not enabled:
                self.connectivity.status = "disabled"
                self.connectivity.ping_ms = None
        self.log(f"Connectivity check {'enabled' if enabled else 'disabled'}")

    def set_connectivity_interval(self, seconds: int) -> None:
        if seconds < 5:
            raise ValueError("Interval must be at least 5 seconds")
        with self.lock:
            self.connectivity.interval_seconds = seconds
        self.log(f"Connectivity interval set to {seconds}s")

    def set_connectivity_target(self, target: str) -> None:
        normalized = normalize_connectivity_target(target)
        with self.lock:
            self.connectivity.target = normalized
            self.connectivity.status = "no target" if not normalized else "idle"
            self.connectivity.last_error = ""
            self.connectivity.ping_ms = None
            self.connectivity.resolved_host = ""
        if normalized:
            self.log(f"Connectivity target set to {normalized}")
        else:
            self.log("Connectivity target cleared")

    def _ping_worker(self, target: str) -> None:
        while not self.stop_event.is_set():
            with self.lock:
                active = target in self.monitored_targets
            if not active:
                return

            latency_ms, status, error = run_ping(target)
            with self.lock:
                stats = self.monitored_targets.get(target)
                if stats is None:
                    return
                stats.sent += 1
                stats.updated_at = time.time()
                stats.last_status = status
                stats.last_error = error
                success = latency_ms is not None and status == "up"
                stats.recent_results.append(success)
                if success:
                    stats.received += 1
                    stats.last_latency_ms = latency_ms
                    stats.total_latency_ms += latency_ms
                    stats.min_latency_ms = latency_ms if stats.min_latency_ms is None else min(stats.min_latency_ms, latency_ms)
                    stats.max_latency_ms = latency_ms if stats.max_latency_ms is None else max(stats.max_latency_ms, latency_ms)
                else:
                    stats.last_latency_ms = None

            time.sleep(1)


def normalize_ping_target(target: str) -> str:
    value = target.strip()
    if not value:
        raise ValueError("Enter an IPv4 address or hostname")

    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        pass

    if value.startswith(("http://", "https://")):
        raise ValueError("Ping target must be an IPv4 address or hostname, not a URL")
    if not is_valid_hostname(value):
        raise ValueError("Invalid hostname or IPv4 address")
    return value.lower()


def normalize_connectivity_target(target: str) -> str:
    value = target.strip()
    if not value:
        return ""

    parsed = urllib.parse.urlparse(value)
    if parsed.scheme and parsed.netloc:
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Connectivity target URL must use http or https")
        if parsed.hostname is None:
            raise ValueError("Connectivity target URL must include a host")
        return value

    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        pass

    if is_valid_hostname(value):
        return value.lower()
    raise ValueError("Enter a valid IPv4 address, hostname, or http/https URL")


def is_valid_hostname(value: str) -> bool:
    if len(value) > 253:
        return False
    if value.endswith("."):
        value = value[:-1]
    labels = value.split(".")
    if any(not label for label in labels):
        return False
    pattern = re.compile(r"^[A-Za-z0-9-]{1,63}$")
    return all(pattern.match(label) and not label.startswith("-") and not label.endswith("-") for label in labels)


def run_ping(target: str) -> tuple[float | None, str, str]:
    command = ["ping", target]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=PING_SAMPLE_SECONDS, check=False)
        output = f"{completed.stdout}\n{completed.stderr}"
    except subprocess.TimeoutExpired as exc:
        output = timeout_output_text(exc)
        latency = parse_ping_latency(output)
        if latency is not None:
            return latency, "up", ""
        return None, "timeout", summarize_error(output) or "request timed out"
    except FileNotFoundError:
        return None, "error", "ping command not found"

    if completed.returncode == 0:
        latency = parse_ping_latency(output)
        if latency is not None:
            return latency, "up", ""
        return None, "up", ""

    return None, infer_ping_status(output), summarize_error(output)


def timeout_output_text(exc: subprocess.TimeoutExpired) -> str:
    stdout = exc.stdout.decode("utf-8", errors="ignore") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
    stderr = exc.stderr.decode("utf-8", errors="ignore") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
    return f"{stdout}\n{stderr}"


def parse_ping_latency(output: str) -> float | None:
    match = re.search(r"time=([0-9.]+)\s*ms", output)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def infer_ping_status(output: str) -> str:
    lower_output = output.lower()
    if "name or service not known" in lower_output or "temporary failure in name resolution" in lower_output:
        return "invalid"
    if "destination host unreachable" in lower_output or "network is unreachable" in lower_output:
        return "unreachable"
    if "request timeout" in lower_output or "100% packet loss" in lower_output:
        return "timeout"
    if "time=" in lower_output:
        return "up"
    return "error"


def summarize_error(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines:
        return "unknown error"
    return lines[-1][:90]


def connectivity_worker(model: NetworkMonitorModel) -> None:
    while not model.stop_event.is_set():
        state = model.snapshot_connectivity()
        if not state.enabled:
            time.sleep(1)
            continue
        if not state.target:
            with model.lock:
                model.connectivity.status = "no target"
                model.connectivity.ping_ms = None
                model.connectivity.resolved_host = ""
                model.connectivity.last_error = ""
            time.sleep(1)
            continue

        with model.lock:
            model.connectivity.status = "checking"
            model.connectivity.last_error = ""

        try:
            ping_ms, resolved_host, status, error = run_connectivity_check(state.target)
            with model.lock:
                model.connectivity.status = status
                model.connectivity.ping_ms = ping_ms
                model.connectivity.resolved_host = resolved_host
                model.connectivity.last_error = error
                model.connectivity.last_run_at = time.time()
        except Exception as exc:  # noqa: BLE001
            with model.lock:
                model.connectivity.status = "error"
                model.connectivity.ping_ms = None
                model.connectivity.resolved_host = ""
                model.connectivity.last_error = str(exc)[:120]
                model.connectivity.last_run_at = time.time()
            model.log(f"Connectivity error: {str(exc)[:60]}")

        for _ in range(state.interval_seconds):
            if model.stop_event.is_set():
                return
            time.sleep(1)


def run_connectivity_check(target: str) -> tuple[float | None, str, str, str]:
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme and parsed.netloc:
        host = parsed.hostname
        if host is None:
            raise ValueError("Target URL is missing a host")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=5):
            pass
        latency_ms = (time.perf_counter() - start) * 1000

        request = urllib.request.Request(url=target, method="HEAD")
        with urllib.request.urlopen(request, timeout=8) as response:
            response.read(0)
        return latency_ms, host, "up", ""

    latency_ms, status, error = run_ping(target)
    return latency_ms, target, status, error


def connection_worker(model: NetworkMonitorModel) -> None:
    while not model.stop_event.is_set():
        model.update_connections(read_connections())
        time.sleep(2)


def read_connections() -> list[ConnectionEntry]:
    command = ["ss", "-tunapH"]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
    except FileNotFoundError:
        return [ConnectionEntry("n/a", "n/a", "n/a", "error", "ss not found")]
    except subprocess.TimeoutExpired:
        return [ConnectionEntry("n/a", "n/a", "n/a", "timeout", "ss timed out")]

    stderr_text = completed.stderr.strip()
    if completed.returncode not in (0, 1):
        return [ConnectionEntry("n/a", "n/a", "n/a", "error", summarize_error(stderr_text))]
    if "permission denied" in stderr_text.lower():
        return [ConnectionEntry("n/a", "n/a", "n/a", "limited", "permission denied for some process data")]

    rows: list[ConnectionEntry] = []
    for raw_line in completed.stdout.splitlines():
        parts = raw_line.split()
        if len(parts) < 6:
            continue
        rows.append(
            ConnectionEntry(
                protocol=parts[0],
                state=parts[1],
                local_address=parts[4],
                remote_address=parts[5],
                process=(" ".join(parts[6:]) if len(parts) > 6 else "-")[:40],
            )
        )
    return rows[:32]


class NetworkTUI:
    def __init__(self, stdscr: curses.window, model: NetworkMonitorModel) -> None:
        self.stdscr = stdscr
        self.model = model
        self.message = "Ready."
        self.legend = (
            "Tab switch pane | Up/Down scroll | a add | n name | d delete | "
            "c target | i interval | t toggle | q quit"
        )
        self.selected_index = 0
        self.connection_scroll = 0
        self.focus = "targets"
        self.colors: dict[str, int] = {}

    def run(self) -> None:
        self.set_cursor_visibility(0)
        self.configure_colors()
        self.stdscr.nodelay(True)
        self.stdscr.timeout(int(REFRESH_SECONDS * 1000))

        while not self.model.stop_event.is_set():
            self.handle_input()
            self.draw()

    def configure_colors(self) -> None:
        if not curses.has_colors():
            return
        curses.start_color()
        curses.use_default_colors()
        pairs = {
            "green": (1, curses.COLOR_GREEN),
            "red": (2, curses.COLOR_RED),
            "yellow": (3, curses.COLOR_YELLOW),
            "blue": (4, curses.COLOR_BLUE),
            "cyan": (5, curses.COLOR_CYAN),
        }
        for name, (pair_id, color) in pairs.items():
            curses.init_pair(pair_id, color, -1)
            self.colors[name] = curses.color_pair(pair_id) | curses.A_BOLD

    def handle_input(self) -> None:
        try:
            key = self.stdscr.getch()
        except KeyboardInterrupt:
            self.model.stop_event.set()
            return

        if key == -1:
            return
        if key in (ord("q"), ord("Q")):
            self.model.stop_event.set()
        elif key == 9:
            self.focus = "connections" if self.focus == "targets" else "targets"
            self.message = f"Focused {self.focus} pane."
        elif key in (ord("a"), ord("A")):
            self.prompt_add_target()
        elif key in (ord("n"), ord("N")):
            self.prompt_name_target()
        elif key in (ord("d"), ord("D")):
            self.remove_selected_target()
        elif key in (ord("t"), ord("T")):
            self.model.toggle_connectivity()
            self.message = "Connectivity check toggled."
        elif key in (ord("c"), ord("C")):
            self.prompt_connectivity_target()
        elif key in (ord("i"), ord("I")):
            self.prompt_interval()
        elif key == curses.KEY_UP:
            self.move_selection(-1)
        elif key == curses.KEY_DOWN:
            self.move_selection(1)
        elif key == curses.KEY_PPAGE:
            self.move_selection(-5)
        elif key == curses.KEY_NPAGE:
            self.move_selection(5)

    def move_selection(self, delta: int) -> None:
        if self.focus == "connections":
            rows = self.model.snapshot_connections()
            self.connection_scroll = max(0, min(self.connection_scroll + delta, max(0, len(rows) - 1)))
            return
        rows = self.model.list_targets()
        if not rows:
            self.selected_index = 0
            return
        self.selected_index = max(0, min(self.selected_index + delta, len(rows) - 1))

    def prompt_add_target(self) -> None:
        value = self.prompt("Add IPv4/host")
        if value is None:
            self.message = "Add target canceled."
            return
        try:
            self.model.add_target(value)
            self.message = f"Monitoring {value.strip()}."
        except ValueError as exc:
            self.message = str(exc)

    def prompt_name_target(self) -> None:
        targets = self.model.list_targets()
        if not targets:
            self.message = "No monitored targets to name."
            return
        target = targets[min(self.selected_index, len(targets) - 1)]
        label = f"Name for {target.target}"
        value = self.prompt(label, initial=target.display_name)
        if value is None:
            self.message = "Name update canceled."
            return
        if value == "" and target.display_name == "":
            self.message = "Name unchanged."
            return
        try:
            self.model.rename_target(target.target, value)
            self.message = "Target name updated." if value.strip() else "Target name cleared."
        except ValueError as exc:
            self.message = str(exc)

    def remove_selected_target(self) -> None:
        targets = self.model.list_targets()
        if not targets:
            self.message = "No monitored targets to remove."
            return
        index = min(self.selected_index, len(targets) - 1)
        target = targets[index].target
        self.model.remove_target(target)
        self.selected_index = max(0, min(self.selected_index, len(targets) - 2))
        self.message = f"Removed {target}."

    def prompt_connectivity_target(self) -> None:
        state = self.model.snapshot_connectivity()
        value = self.prompt("Connectivity URL/host/IP", initial=state.target)
        if value is None:
            self.message = "Connectivity target unchanged."
            return
        try:
            self.model.set_connectivity_target(value)
            self.message = "Connectivity target updated." if value.strip() else "Connectivity target cleared."
        except ValueError as exc:
            self.message = str(exc)

    def prompt_interval(self) -> None:
        state = self.model.snapshot_connectivity()
        value = self.prompt("Interval seconds", initial=str(state.interval_seconds))
        if value is None or not value:
            self.message = "Interval unchanged."
            return
        try:
            self.model.set_connectivity_interval(int(value.strip()))
            self.message = "Interval updated."
        except (ValueError, TypeError) as exc:
            self.message = str(exc)

    def prompt(self, label: str, initial: str = "") -> str | None:
        height, width = self.stdscr.getmaxyx()
        prompt = f"{label} (Enter submit, Esc cancel): "
        input_y = height - 1
        input_x = min(len(prompt), max(0, width - 2))
        input_w = max(1, width - input_x - 1)

        self.stdscr.nodelay(False)
        self.stdscr.timeout(-1)
        self.set_cursor_visibility(1)
        self.stdscr.move(height - 2, 0)
        self.stdscr.clrtoeol()
        self.stdscr.addnstr(height - 2, 0, prompt, width - 1)
        self.stdscr.move(input_y, 0)
        self.stdscr.clrtoeol()

        window = curses.newwin(1, input_w, input_y, input_x)
        if initial:
            window.addnstr(0, 0, initial, max(0, input_w - 1))
            window.move(0, min(len(initial), input_w - 1))
        textbox = curses.textpad.Textbox(window, insert_mode=True)

        def validator(ch: int) -> int:
            if ch == 27:
                raise KeyboardInterrupt
            if ch in (10, 13, curses.KEY_ENTER):
                return 7
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                return 263
            return ch

        try:
            value = textbox.edit(validator).strip()
        except KeyboardInterrupt:
            value = None
        finally:
            self.set_cursor_visibility(0)
            self.stdscr.nodelay(True)
            self.stdscr.timeout(int(REFRESH_SECONDS * 1000))
            self.stdscr.move(height - 2, 0)
            self.stdscr.clrtoeol()
            self.stdscr.move(height - 1, 0)
            self.stdscr.clrtoeol()
        return value

    def draw(self) -> None:
        self.stdscr.erase()
        height, width = self.stdscr.getmaxyx()
        if height < 18 or width < 90:
            self.safe_addnstr(0, 0, "Terminal too small. Need at least 90x18.", width - 1)
            self.stdscr.refresh()
            return

        left_width = max(40, width // 3)
        right_width = width - left_width
        content_height = height - 3
        top_height = max(10, content_height // 2)
        bottom_height = content_height - top_height

        self.draw_box(0, 0, content_height, left_width, "Monitored IPs / Hosts", self.focus == "targets")
        self.draw_box(0, left_width, top_height, right_width, "Internet Connectivity Check")
        self.draw_box(top_height, left_width, bottom_height, right_width, "Connections", self.focus == "connections")
        self.draw_status_bar(height - 3, width)
        self.draw_footer(height - 2, width)
        self.draw_legend(height - 1, width)

        self.draw_targets(1, 1, content_height - 2, left_width - 2)
        self.draw_connectivity(1, left_width + 1, top_height - 2, right_width - 2)
        self.draw_connections(top_height + 1, left_width + 1, bottom_height - 2, right_width - 2)
        self.stdscr.refresh()

    def draw_box(self, y: int, x: int, h: int, w: int, title: str, highlighted: bool = False) -> None:
        self.stdscr.addch(y, x, curses.ACS_ULCORNER)
        self.stdscr.hline(y, x + 1, curses.ACS_HLINE, w - 2)
        self.stdscr.addch(y, x + w - 1, curses.ACS_URCORNER)
        self.stdscr.vline(y + 1, x, curses.ACS_VLINE, h - 2)
        self.stdscr.vline(y + 1, x + w - 1, curses.ACS_VLINE, h - 2)
        self.stdscr.addch(y + h - 1, x, curses.ACS_LLCORNER)
        self.stdscr.hline(y + h - 1, x + 1, curses.ACS_HLINE, w - 2)
        self.stdscr.addch(y + h - 1, x + w - 1, curses.ACS_LRCORNER)
        title_attr = curses.A_BOLD | (curses.A_REVERSE if highlighted else curses.A_NORMAL)
        self.safe_addnstr(y, x + 2, f" {title} ", max(0, w - 4), title_attr)

    def draw_status_bar(self, y: int, width: int) -> None:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.stdscr.attron(curses.A_REVERSE)
        self.safe_addnstr(y, 0, f" {now} ".ljust(width), width)
        self.stdscr.attroff(curses.A_REVERSE)

    def draw_footer(self, y: int, width: int) -> None:
        self.safe_addnstr(y, 0, self.message.ljust(width), width - 1)

    def draw_legend(self, y: int, width: int) -> None:
        self.stdscr.attron(curses.A_DIM)
        self.safe_addnstr(y, 0, self.legend.ljust(width), width - 1)
        self.stdscr.attroff(curses.A_DIM)

    def draw_targets(self, y: int, x: int, h: int, w: int) -> None:
        rows = self.model.list_targets()
        if not rows:
            self.safe_addnstr(y, x, "No targets configured. Press 'a' to add 10.0.0.1 or a hostname.", w)
            return

        self.selected_index = min(self.selected_index, len(rows) - 1)
        visible_cards = max(1, h // TARGET_CARD_HEIGHT)
        start = min(max(0, self.selected_index - visible_cards + 1), max(0, len(rows) - visible_cards))

        for draw_idx, stats in enumerate(rows[start : start + visible_cards]):
            idx = start + draw_idx
            base_y = y + draw_idx * TARGET_CARD_HEIGHT
            if base_y + TARGET_CARD_HEIGHT - 1 >= y + h:
                break
            self.draw_target_card(base_y, x, w, stats, idx == self.selected_index)

    def draw_target_card(self, y: int, x: int, w: int, stats: PingStats, selected: bool) -> None:
        self.draw_inner_box(y, x, TARGET_CARD_HEIGHT, w, selected)
        text_x = x + 2
        text_w = max(1, w - 4)

        row1 = stats.display_name if stats.display_name else "(no name)"
        self.safe_addnstr(y + 1, text_x, row1, text_w, curses.A_BOLD)
        self.safe_addnstr(y + 2, text_x, stats.target, text_w)

        conn_label, conn_color = describe_connection_label(stats.last_status)
        latency_label, latency_color = describe_latency_label(stats.last_latency_ms)
        self.safe_addnstr(y + 3, text_x, "Status:", text_w)
        self.safe_addnstr(y + 3, text_x + 8, conn_label, max(1, text_w - 8), self.color_attr(conn_color))
        self.safe_addnstr(y + 3, text_x + 23, "Latency:", max(1, text_w - 23))
        self.safe_addnstr(y + 3, text_x + 32, latency_label, max(1, text_w - 32), self.color_attr(latency_color))

        loss_text = f"{stats.packet_loss_percent:.0f}%"
        loss_color = describe_loss_color(stats.packet_loss_percent)
        latency_value = f"{stats.last_latency_ms:.1f} ms" if stats.last_latency_ms is not None else "--"
        self.safe_addnstr(y + 4, text_x, "Last:", text_w)
        self.safe_addnstr(y + 4, text_x + 6, latency_value, max(1, text_w - 6))
        self.safe_addnstr(y + 4, text_x + 20, "Loss:", max(1, text_w - 20))
        self.safe_addnstr(y + 4, text_x + 26, loss_text, max(1, text_w - 26), self.color_attr(loss_color))

        detail = f"Samples {len(stats.recent_results)}/{PING_HISTORY_SIZE}  Sent {stats.sent}  Recv {stats.received}"
        if stats.last_error and stats.last_status != "up":
            detail = stats.last_error
        self.safe_addnstr(y + 5, text_x, detail, text_w, curses.A_DIM)

    def draw_inner_box(self, y: int, x: int, h: int, w: int, selected: bool) -> None:
        attr = curses.A_REVERSE if selected else curses.A_NORMAL
        self.stdscr.attron(attr)
        self.stdscr.addch(y, x, curses.ACS_ULCORNER)
        self.stdscr.hline(y, x + 1, curses.ACS_HLINE, w - 2)
        self.stdscr.addch(y, x + w - 1, curses.ACS_URCORNER)
        self.stdscr.vline(y + 1, x, curses.ACS_VLINE, h - 2)
        self.stdscr.vline(y + 1, x + w - 1, curses.ACS_VLINE, h - 2)
        self.stdscr.addch(y + h - 1, x, curses.ACS_LLCORNER)
        self.stdscr.hline(y + h - 1, x + 1, curses.ACS_HLINE, w - 2)
        self.stdscr.addch(y + h - 1, x + w - 1, curses.ACS_LRCORNER)
        self.stdscr.attroff(attr)

    def draw_connectivity(self, y: int, x: int, h: int, w: int) -> None:
        state = self.model.snapshot_connectivity()
        line = y
        self.safe_addnstr(line, x, "Mode: connectivity check (not full bandwidth test)", w)
        line += 1
        self.safe_addnstr(line, x, f"Enabled: {'yes' if state.enabled else 'no'}", w)
        line += 1
        self.safe_addnstr(line, x, f"Interval: {state.interval_seconds}s", w)
        line += 1
        self.safe_addnstr(line, x, f"Target field: {state.target or '<not set>'}", w)
        line += 1

        conn_label, conn_color = describe_connection_label(state.status)
        latency_label, latency_color = describe_latency_label(state.ping_ms)
        self.safe_addnstr(line, x, "Connection:", w)
        self.safe_addnstr(line, x + 12, conn_label, max(1, w - 12), self.color_attr(conn_color))
        line += 1
        self.safe_addnstr(line, x, "Latency:", w)
        self.safe_addnstr(line, x + 9, latency_label, max(1, w - 9), self.color_attr(latency_color))
        line += 1
        self.safe_addnstr(line, x, f"Measured: {format_metric(state.ping_ms, 'ms')}", w)
        line += 1

        if state.resolved_host and line < y + h:
            self.safe_addnstr(line, x, f"Resolved host: {state.resolved_host}", w)
            line += 1
        if state.last_run_at is not None and line < y + h:
            last_run = datetime.fromtimestamp(state.last_run_at).strftime("%H:%M:%S")
            self.safe_addnstr(line, x, f"Last run: {last_run}", w)
            line += 1
        if state.last_error and line < y + h:
            self.safe_addnstr(line, x, f"Error: {state.last_error}", w)
            line += 1

        if line < y + h:
            self.safe_addnstr(line, x, "Recent events:", w, curses.A_BOLD)
            line += 1
        for event in self.model.snapshot_events():
            if line >= y + h:
                break
            self.safe_addnstr(line, x, event, w)
            line += 1

    def draw_connections(self, y: int, x: int, h: int, w: int) -> None:
        rows = self.model.snapshot_connections()
        header = f"{'Proto':<6} {'State':<12} {'Local':<24} {'Remote':<24} Process"
        self.safe_addnstr(y, x, header, w, curses.A_BOLD)
        visible_rows = max(0, h - 1)
        max_scroll = max(0, len(rows) - visible_rows)
        self.connection_scroll = min(self.connection_scroll, max_scroll)
        for idx, row in enumerate(rows[self.connection_scroll : self.connection_scroll + visible_rows]):
            line = f"{row.protocol:<6} {row.state:<12} {row.local_address:<24} {row.remote_address:<24} {row.process}"
            self.safe_addnstr(y + idx + 1, x, line, w)
        if max_scroll > 0:
            indicator = f"Rows {self.connection_scroll + 1}-{min(len(rows), self.connection_scroll + visible_rows)} of {len(rows)}"
            indicator_x = max(x, x + w - len(indicator) - 1)
            self.safe_addnstr(y, indicator_x, indicator, min(len(indicator), w - 1), curses.A_DIM)

    def color_attr(self, name: str) -> int:
        return self.colors.get(name, curses.A_BOLD)

    def set_cursor_visibility(self, value: int) -> None:
        try:
            curses.curs_set(value)
        except curses.error:
            pass

    def safe_addnstr(self, y: int, x: int, text: str, width: int, attr: int = 0) -> None:
        if width <= 0:
            return
        try:
            self.stdscr.addnstr(y, x, text, width, attr)
        except curses.error:
            pass


def describe_connection_label(status: str) -> tuple[str, str]:
    mapping = {
        "up": ("Connected", "green"),
        "reachable": ("Connected", "green"),
        "unreachable": ("Routing Error", "red"),
        "timeout": ("Disconnected", "yellow"),
        "disabled": ("Disabled", "yellow"),
        "no target": ("No Target", "yellow"),
        "checking": ("Checking", "blue"),
        "idle": ("Idle", "blue"),
        "invalid": ("Invalid Target", "red"),
        "error": ("Disconnected", "yellow"),
        "waiting": ("Waiting", "blue"),
    }
    return mapping.get(status, ("Disconnected", "yellow"))


def describe_latency_label(latency_ms: float | None) -> tuple[str, str]:
    if latency_ms is None:
        return "Unknown", "yellow"
    if latency_ms < 50:
        return "Strong", "green"
    if latency_ms <= 150:
        return "Fair", "blue"
    if latency_ms <= 200:
        return "Poor", "yellow"
    return "Broken", "red"


def describe_loss_color(loss_percent: float) -> str:
    if loss_percent <= 5:
        return "green"
    if loss_percent < 50:
        return "yellow"
    return "red"


def format_metric(value: float | None, unit: str) -> str:
    if value is None:
        return "--"
    return f"{value:.2f} {unit}"


def run_app(stdscr: curses.window) -> None:
    model = NetworkMonitorModel()
    model.log("Application started")

    workers = [
        threading.Thread(target=connectivity_worker, args=(model,), daemon=True),
        threading.Thread(target=connection_worker, args=(model,), daemon=True),
    ]
    for worker in workers:
        worker.start()

    app = NetworkTUI(stdscr, model)
    try:
        app.run()
    finally:
        model.stop_event.set()
        for worker in workers:
            worker.join(timeout=1.5)


def main() -> None:
    curses.wrapper(run_app)


if __name__ == "__main__":
    main()
