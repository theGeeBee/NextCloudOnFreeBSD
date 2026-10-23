"""Small terminal UI using FreeBSD's base bsddialog, with a plain fallback.

Dialogs inherit stdin/stdout (the foreground terminal). Only their documented
response descriptor, stderr, is captured. Secrets never enter a subprocess.
"""

import builtins
import getpass
import os
import re
import shutil
import subprocess
import sys
import unicodedata
import warnings


def _interactive(stream):
    return (sys.stdin.isatty() and sys.stdout.isatty() and stream.isatty()
            and os.environ.get("TERM", "") not in ("", "dumb", "unknown"))


def _safe(text):
    """Escape terminal controls in display text, never in input/returned values."""
    return "".join(char if char == "\n" or not unicodedata.category(char).startswith("C")
                   else repr(char)[1:-1] for char in str(text)).expandtabs(4)


def _cells(text):
    return sum(0 if unicodedata.combining(char) else
               2 if unicodedata.east_asian_width(char) in ("W", "F") else 1 for char in text)


def _wrapped(text, width):
    """Wrap existing lines at spaces/cell boundaries without dropping long values."""
    lines = []
    for line in _safe(text).split("\n"):
        indent = line[:len(line) - len(line.lstrip())]
        indent = indent if len(indent) < width // 2 else ""
        while _cells(line) > width:
            used, cut = 0, 0
            for char in line:
                size = _cells(char)
                if used + size > width:
                    break
                used += size
                cut += 1
            space = line.rfind(" ", len(indent) + 1, cut + 1)
            cut = space if space > 0 else max(1, cut)
            lines.append(line[:cut].rstrip())
            line = indent + line[cut:].lstrip()
        lines.append(line)
    return lines


def _emphasis(text, code, color):
    return f"\033[{code}m{text}\033[0m" if color else text


def _menu_view(title, choices, default, columns, color):
    """One ordered choice source for every width; no input or selection state."""
    width = max(4, min(96, columns - 4)) if columns >= 60 else max(4, columns)
    framed = columns >= 60
    inner = width - 4 if framed else width
    rows = []
    for number, (key, label) in enumerate(choices, 1):
        text = f"  {number}. {label}" + (" (default)" if key == default else "")
        rows.extend((line, key == default) for line in _wrapped(text, inner))
    rows.extend((line, False) for line in _wrapped("  0. Cancel", inner))
    margin = " " * ((columns - width) // 2) if framed else ""
    if not framed:
        return "\n" + "\n".join([*_wrapped(title, inner), *(line for line, _ in rows)])
    border = margin + "+" + "-" * (width - 2) + "+"
    result = ["", _emphasis(border, "36", color)]
    for line in _wrapped(title, inner):
        result.append(margin + "| " + _emphasis(line, "1;36", color) + " " * (inner - _cells(line)) + " |")
    result.append(border)
    for line, selected in rows:
        result.append(margin + "| " + _emphasis(line, "1;36", color and selected) + " " * (inner - _cells(line)) + " |")
    result.append(_emphasis(border, "36", color))
    return "\n".join(result)


def _text_view(text, columns, color):
    """Reflow only already-emitted human text; headless callers bypass this."""
    width = max(4, min(96, columns - 4)) if columns >= 60 else max(4, columns)
    margin = " " * ((columns - width) // 2) if columns >= 60 else ""
    lines = _wrapped(text, width)
    heading = str(text).startswith("\n") or (len(lines) > 1 and lines[0].endswith(":"))
    first = next((index for index, line in enumerate(lines) if line), None)
    # Only emphasize facts already printed by the caller; never infer a stage
    # outcome from its number, elapsed time or absence of an error.
    public = _safe(text).lstrip()
    tone = "1;36" if heading or re.match(r"\[[0-9]+/[0-9]+\]", public) else None
    if public.startswith(("Error:", "Invalid value:", "Preflight failed:")):
        tone = "31"
    elif public.startswith(("Stopped.", "NOTICE:", "ATTENTION:", "Configuration needs correction:")):
        tone = "33"
    elif public.startswith("Installer checks passed."):
        tone = "32"
    result = []
    for index, line in enumerate(lines):
        result.append(margin + _emphasis(line, tone, color and tone is not None and index == first) if line else "")
        if heading and index == first and len(lines) <= 2:
            result.append(margin + "-" * min(width, _cells(line)))
    return "\n".join(result)


class TerminalUI:
    def __init__(self, plain=False):
        self.dialog = None
        if plain or os.environ.get("CLOUD_INSTALLER_PLAIN") == "1":
            return
        term = os.environ.get("TERM", "")
        if not term or term in ("dumb", "unknown") or not (sys.stdin.isatty() and sys.stdout.isatty()):
            return
        executable = shutil.which("bsddialog")
        if not executable:
            return
        try:
            import curses
            curses.setupterm(term=term, fd=sys.stdout.fileno())
            size = shutil.get_terminal_size((80, 24))
            if size.columns < 60 or size.lines < 15:
                return
        except (ImportError, OSError, ValueError):
            return
        except curses.error:
            return
        self.dialog = executable

    def _dialog(self, title, arguments, *, negative=False):
        if not self.dialog:
            return None
        appearance = ["--ascii-lines"]
        if os.environ.get("NO_COLOR"):
            appearance += ["--theme", "blackwhite"]
        command = [self.dialog, "--alternate-screen", "--text-unchanged", *appearance,
                   "--backtitle", "Cloud installer | FreeBSD", "--title", _safe(title),
                   "--output-fd", "2", "--ok-exit-code", "0", "--cancel-exit-code", "1",
                   "--esc-exit-code", "5", "--error-exit-code", "255", *arguments]
        try:
            # Capturing stdout would hide the curses display. bsddialog(1)
            # documents stderr as its response channel, made explicit above.
            result = subprocess.run(command, stderr=subprocess.PIPE, text=True, check=False)
        except OSError:
            result = None
        if result is not None:
            if result.returncode == 0:
                return result.stderr.rstrip("\n")
            if result.returncode == 1 and negative:
                return False
            if result.returncode in (1, 5, 130, -2):
                raise KeyboardInterrupt
        self.dialog = None
        self.message("Dialog unavailable; continuing with numbered terminal prompts.")
        return None

    @staticmethod
    def _read(prompt):
        try:
            value = builtins.input(prompt)
        except EOFError:
            raise KeyboardInterrupt from None
        if value == "\x1b":
            raise KeyboardInterrupt
        return value

    def menu(self, title, choices, default=None):
        choices = [(str(key), str(label)) for key, label in choices]
        keys = [key for key, _ in choices]
        if not keys or len(set(keys)) != len(keys) or any(not key or key == "0" for key in keys):
            raise ValueError("A menu needs distinct nonempty keys other than 0")
        if default is not None and default not in keys:
            raise ValueError("Menu default is not a choice")
        arguments = ["--default-item", default] if default is not None else []
        # Base bsddialog owns highlighting/navigation; its item description is
        # derived from the same label, not a second menu/help catalog.
        width = str(max(4, min(96, shutil.get_terminal_size((80, 24)).columns - 4)))
        arguments += ["--item-bottom-desc", "--menu", _safe(title), "0", width, "0"]
        arguments += [part for key, label in choices for part in (key, _safe(label), _safe(label))]
        response = self._dialog(title, arguments)
        if response is not None:
            if response not in keys:
                raise ValueError("Dialog returned an unknown menu choice")
            return response
        if _interactive(sys.stdout):
            print(_menu_view(title, choices, default, shutil.get_terminal_size((80, 24)).columns,
                             not os.environ.get("NO_COLOR")), flush=True)
        else:
            self.message("\n" + str(title))
            for number, (key, label) in enumerate(choices, 1):
                marker = " (default)" if key == default else ""
                self.message(f"  {number}. {label}{marker}")
            self.message("  0. Cancel")
        while True:
            response = self._read("Selection: ").strip()
            if response == "0":
                raise KeyboardInterrupt
            if not response and default is not None:
                return default
            if response.isdecimal() and 1 <= int(response) <= len(keys):
                return keys[int(response) - 1]
            if response in keys:
                return response
            self.message("Enter a listed number or choice; 0 cancels.")

    def input(self, label, default=""):
        default = str(default)
        response = self._dialog("Configuration", ["--inputbox", str(label), "0", "0", default])
        if response is not None:
            return response.strip()
        suffix = f" [{default}]" if default else ""
        return self._read(f"{label}{suffix}: ").strip() or default

    def confirm(self, message):
        response = self._dialog("Confirmation", ["--default-no", "--yesno", str(message), "0", "0"], negative=True)
        if response is not None:
            return response is not False
        while True:
            answer = self._read(str(message) + " [y/N]: ").strip().lower()
            if answer in ("y", "yes"):
                return True
            if answer in ("", "n", "no"):
                return False
            self.message("Enter yes or no; Ctrl-C cancels.")

    def secret(self, label):
        # Treat getpass's echoing fallback as an error, rather than exposing a
        # password when a controlling terminal cannot be opened.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                return getpass.getpass(str(label) + ": ")
            except EOFError:
                raise KeyboardInterrupt from None
            except getpass.GetPassWarning:
                raise ValueError("A terminal with hidden input is required for passwords") from None

    @staticmethod
    def message(text, *, file=None):
        stream = sys.stdout if file is None else file
        if _interactive(stream):
            text = _text_view(text, shutil.get_terminal_size((80, 24)).columns, not os.environ.get("NO_COLOR"))
        if file is None:
            print(text, flush=True)
        else:
            print(text, file=file)

    def progress(self, current, total, label):
        """Present existing step counts, not completion claims or percentages."""
        total = max(0, int(total))
        current = min(total, max(0, int(current)))
        self.message(f"[{current}/{total}] {label}")
