"""
Base module class for PenTool.
Uses PTY (pseudo-terminal) so tools like ffuf, nmap, hydra think they're
running in a real terminal — colored output, progress bars, etc.

- ANSI color codes are stripped before sending to the Tkinter widget
  (Tk can't render ANSI natively, and we don't want raw escape codes)
- Carriage-return progress overwrites are handled correctly
- Progress-only lines (ffuf ':: Progress:') are filtered to prevent spam
"""
import subprocess
import threading
import os
import re
import time
import pty
import select
import signal
from datetime import datetime


# Strip ALL ANSI escape sequences (CSI + OSC + others)
ANSI_RE = re.compile(
    r"\x1b(?:"
    r"\[[0-?]*[ -/]*[@-~]"     # CSI (Control Sequence Introducer)
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC (Operating System Command)
    r"|[@-_]"                  # other simple escapes
    r")"
)


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


# Lines we always want to suppress (progress counters, etc.)
SPAM_PATTERNS = [
    re.compile(r"^\s*:: Progress:"),      # ffuf progress
    re.compile(r"^\s*$"),                 # empty lines (too many)
]


def is_spam(line: str) -> bool:
    for p in SPAM_PATTERNS:
        if p.match(line):
            return True
    return False


class BaseModule:
    def __init__(self, output_callback, status_callback, session=None):
        self.output_callback = output_callback
        self.status_callback = status_callback
        self.session = session
        self.process = None
        self.master_fd = None
        self.running = False
        self._last_output: list[str] = []
        self._module_name = self.__class__.__name__.replace("Module", "").lower()

    # ── Execution ────────────────────────────────────────────────────────────

    def run_command(self, command: list[str], target: str, save_output: bool = False):
        self.running = True
        self._last_output = []
        cmd_str = " ".join(command)
        start_time = time.time()

        self.status_callback(f"Running: {command[0]}", "running")
        self.output_callback(f"\n{'─'*60}\n", "separator")
        self.output_callback(f"  CMD     {cmd_str}\n", "cmd")
        self.output_callback(f"  TARGET  {target}\n", "info")
        self.output_callback(f"  START   {datetime.now().strftime('%H:%M:%S')}\n", "info")
        self.output_callback(f"{'─'*60}\n\n", "separator")

        returncode = None

        try:
            # Create PTY - tool sees this as a real interactive terminal
            master_fd, slave_fd = pty.openpty()
            self.master_fd = master_fd

            # Spawn process attached to the slave side
            self.process = subprocess.Popen(
                command,
                stdout=slave_fd,
                stderr=slave_fd,
                stdin=slave_fd,
                close_fds=True,
                preexec_fn=os.setsid,  # new process group, for clean kill
            )
            os.close(slave_fd)  # parent doesn't need it

            # Read loop — accumulate bytes, split on \n / \r
            buffer = ""
            last_progress_emit = 0.0
            while True:
                # Has the process exited?
                if self.process.poll() is not None and not buffer:
                    # Drain remaining output
                    try:
                        r, _, _ = select.select([master_fd], [], [], 0.05)
                        if not r:
                            break
                    except (OSError, ValueError):
                        break

                try:
                    r, _, _ = select.select([master_fd], [], [], 0.1)
                except (OSError, ValueError):
                    break

                if not r:
                    if self.process.poll() is not None:
                        break
                    continue

                try:
                    chunk = os.read(master_fd, 4096).decode("utf-8", errors="replace")
                except OSError:
                    break

                if not chunk:
                    break

                buffer += chunk

                # Extract complete lines (split on \n OR \r)
                while True:
                    nl = buffer.find("\n")
                    cr = buffer.find("\r")
                    if nl == -1 and cr == -1:
                        break
                    if nl == -1:
                        pos = cr
                    elif cr == -1:
                        pos = nl
                    else:
                        pos = min(nl, cr)

                    line_raw = buffer[:pos]
                    buffer = buffer[pos + 1:]

                    line_clean = strip_ansi(line_raw)

                    # Progress lines: throttle to ~1 per second
                    if is_spam(line_clean):
                        now = time.time()
                        if ":: Progress:" in line_clean and now - last_progress_emit > 1.0:
                            last_progress_emit = now
                            self.output_callback(f"  {line_clean.strip()}\n", "info")
                        continue

                    self.output_callback(line_clean + "\n", "output")
                    self._last_output.append(line_clean + "\n")

            self.process.wait()
            returncode = self.process.returncode

        except FileNotFoundError:
            tool = command[0]
            self.output_callback(f"\n  ERROR  '{tool}' no encontrado.\n", "error")
            self.output_callback(f"  HINT   sudo apt install {tool}\n\n", "hint")
            self.status_callback(f"Error: {tool} not installed", "error")
            self._record_history(cmd_str, -1, time.time() - start_time)
            self.running = False
            self._cleanup_fd()
            return

        except Exception as e:
            self.output_callback(f"\n  ERROR  {str(e)}\n", "error")
            self.status_callback("Error during execution", "error")
            self._record_history(cmd_str, -1, time.time() - start_time)
            self.running = False
            self._cleanup_fd()
            return

        finally:
            self._cleanup_fd()

        duration = time.time() - start_time
        self.output_callback(f"\n{'─'*60}\n", "separator")
        if returncode == 0:
            self.output_callback(f"  DONE    Completed in {duration:.1f}s\n", "success")
            self.status_callback("Completed", "success")
        elif returncode == -15 or returncode == 143:
            self.output_callback(f"  STOPPED (user)\n", "warning")
            self.status_callback("Stopped", "warning")
        else:
            self.output_callback(f"  WARN    Exit code {returncode} ({duration:.1f}s)\n", "warning")
            self.status_callback(f"Finished (code {returncode})", "warning")
        self.output_callback(f"  END     {datetime.now().strftime('%H:%M:%S')}\n", "info")
        self.output_callback(f"{'─'*60}\n\n", "separator")

        if save_output and self._last_output:
            self._save_output(target, command[0])

        self._record_history(cmd_str, returncode if returncode is not None else 0, duration)

        # Auto-parse nmap output for victim panel
        if command[0] == "nmap" and self.session:
            try:
                from core.parser import NmapParser
                parsed = NmapParser.parse("".join(self._last_output))
                if parsed["ports"]:
                    self.session.parsed_services = parsed
            except Exception:
                pass

        self.running = False

    # ── Cleanup ──────────────────────────────────────────────────────────────

    def _cleanup_fd(self):
        if self.master_fd is not None:
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            self.master_fd = None

    def _save_output(self, target: str, tool: str):
        os.makedirs("output", exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("/", "_").replace(":", "_")
        filename = f"output/{tool}_{safe_target}_{timestamp}.txt"
        with open(filename, "w") as f:
            f.writelines(self._last_output)
        self.output_callback(f"  SAVED   {filename}\n\n", "hint")

    def _record_history(self, cmd: str, exit_code: int, duration: float):
        if self.session:
            self.session.add_history(cmd, self._module_name, duration, exit_code)

    def get_last_output(self) -> str:
        return "".join(self._last_output)

    def stop(self):
        if self.process and self.running:
            try:
                # Kill the whole process group (ffuf/nmap may spawn children)
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except (ProcessLookupError, OSError):
                try:
                    self.process.terminate()
                except Exception:
                    pass
            self.running = False
            self.output_callback("\n  STOPPED  Process terminated by user\n\n", "warning")
            self.status_callback("Stopped", "warning")
