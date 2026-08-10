from __future__ import annotations

import copy
import posixpath
import re
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class ShellResult:
    output: str
    should_exit: bool = False
    handled: bool = True


DEFAULT_FILESYSTEM: dict[str, str | None] = {
    "/": None,
    "/bin": None,
    "/etc": None,
    "/home": None,
    "/home/guest": None,
    "/opt": None,
    "/opt/inventory-api": None,
    "/root": None,
    "/srv": None,
    "/tmp": None,
    "/usr": None,
    "/var": None,
    "/var/log": None,
    "/etc/hostname": "ubuntu-web-01\n",
    "/etc/os-release": (
        'PRETTY_NAME="Ubuntu 24.04.2 LTS"\n'
        'NAME="Ubuntu"\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n'
    ),
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        "guest:x:1001:1001:Guest:/home/guest:/bin/bash\n"
        "backup:x:1002:1002:Backup Service:/srv/backup:/usr/sbin/nologin\n"
    ),
    "/home/guest/notes.txt": (
        "Deployment checklist\n- verify nginx\n- rotate demo credentials\n- check backups\n"
    ),
    "/home/guest/backup.sh": "#!/bin/bash\necho 'backup complete'\n",
    "/opt/inventory-api/.env": (
        "APP_ENV=production\nDATABASE_URL=postgresql://inventory:[REDACTED]@db/inventory\n"
        "API_TOKEN=demo_honeypot_token_not_real\n"
    ),
    "/var/log/auth.log": "Aug 10 07:00:01 ubuntu-web-01 sshd[802]: Server listening\n",
}


def _clean_text(value: str, limit: int = 6000) -> str:
    value = value.replace("\x00", "")
    value = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", value)
    return value[:limit]


class VirtualFilesystem:
    def __init__(self) -> None:
        self.entries = copy.deepcopy(DEFAULT_FILESYSTEM)

    @staticmethod
    def normalize(path: str, cwd: str) -> str:
        if not path:
            return cwd
        expanded = path.replace("~", "/home/guest", 1) if path.startswith("~") else path
        combined = expanded if expanded.startswith("/") else posixpath.join(cwd, expanded)
        normalized = posixpath.normpath(combined)
        return normalized if normalized.startswith("/") else f"/{normalized}"

    def exists(self, path: str) -> bool:
        return path in self.entries

    def is_dir(self, path: str) -> bool:
        return self.entries.get(path, "__missing__") is None and path in self.entries

    def read(self, path: str) -> str | None:
        value = self.entries.get(path)
        return value if isinstance(value, str) else None

    def list_dir(self, path: str) -> list[str]:
        if not self.is_dir(path):
            return []
        prefix = "/" if path == "/" else f"{path.rstrip('/')}/"
        children: set[str] = set()
        for candidate in self.entries:
            if candidate == path or not candidate.startswith(prefix):
                continue
            remainder = candidate[len(prefix):]
            children.add(remainder.split("/", 1)[0])
        return sorted(children)

    def write_file(self, path: str, content: str = "") -> None:
        parent = posixpath.dirname(path) or "/"
        if not self.is_dir(parent):
            raise FileNotFoundError(parent)
        self.entries[path] = content

    def mkdir(self, path: str) -> None:
        parent = posixpath.dirname(path) or "/"
        if not self.is_dir(parent):
            raise FileNotFoundError(parent)
        self.entries[path] = None

    def remove(self, path: str, recursive: bool = False) -> None:
        if path in {"/", "/etc", "/bin", "/usr"}:
            raise PermissionError(path)
        if path not in self.entries:
            raise FileNotFoundError(path)
        if self.is_dir(path):
            children = [p for p in self.entries if p.startswith(path.rstrip("/") + "/")]
            if children and not recursive:
                raise IsADirectoryError(path)
            for child in children:
                self.entries.pop(child, None)
        self.entries.pop(path, None)


class VirtualShell:
    def __init__(self, username: str = "guest", hostname: str = "ubuntu-web-01") -> None:
        self.username = username or "guest"
        self.hostname = hostname
        self.cwd = f"/home/{self.username}" if f"/home/{self.username}" in DEFAULT_FILESYSTEM else "/home/guest"
        self.fs = VirtualFilesystem()
        self.history: list[str] = []

    @property
    def prompt(self) -> str:
        display = "~" if self.cwd == "/home/guest" else self.cwd
        return f"{self.username}@{self.hostname}:{display}$ "

    def context(self) -> dict:
        return {
            "username": self.username,
            "hostname": self.hostname,
            "cwd": self.cwd,
            "history": self.history[-12:],
        }

    def execute(self, raw_command: str) -> ShellResult:
        command = _clean_text(raw_command.strip(), 2048)
        if not command:
            return ShellResult("")
        self.history.append(command)

        if command in {"exit", "logout", "quit"}:
            return ShellResult("logout", should_exit=True)
        if command == "clear":
            return ShellResult("\033[2J\033[H")
        if command == "history":
            return ShellResult("\n".join(f"{i + 1:4d}  {cmd}" for i, cmd in enumerate(self.history)))

        # Compound shell syntax is never executed. It can be sent to the optional LLM simulator.
        if re.search(r"(;|&&|\|\||\||`|\$\()", command):
            return ShellResult("", handled=False)

        try:
            args = shlex.split(command)
        except ValueError as exc:
            return ShellResult(f"bash: {exc}")
        if not args:
            return ShellResult("")

        name = args[0]
        handler = getattr(self, f"_cmd_{name.replace('-', '_')}", None)
        if handler:
            return handler(args[1:])
        return ShellResult("", handled=False)

    def _cmd_help(self, _: list[str]) -> ShellResult:
        return ShellResult("GNU bash, version 5.2.21(1)-release\nType 'help' for shell built-ins.")

    def _cmd_whoami(self, _: list[str]) -> ShellResult:
        return ShellResult(self.username)

    def _cmd_hostname(self, _: list[str]) -> ShellResult:
        return ShellResult(self.hostname)

    def _cmd_pwd(self, _: list[str]) -> ShellResult:
        return ShellResult(self.cwd)

    def _cmd_id(self, _: list[str]) -> ShellResult:
        return ShellResult(f"uid=1001({self.username}) gid=1001({self.username}) groups=1001({self.username})")

    def _cmd_date(self, _: list[str]) -> ShellResult:
        return ShellResult(datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y"))

    def _cmd_uname(self, args: list[str]) -> ShellResult:
        if "-a" in args:
            return ShellResult(
                "Linux ubuntu-web-01 6.8.0-52-generic #53-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux"
            )
        return ShellResult("Linux")

    def _cmd_cd(self, args: list[str]) -> ShellResult:
        target = args[0] if args else "/home/guest"
        path = self.fs.normalize(target, self.cwd)
        if not self.fs.exists(path):
            return ShellResult(f"bash: cd: {target}: No such file or directory")
        if not self.fs.is_dir(path):
            return ShellResult(f"bash: cd: {target}: Not a directory")
        self.cwd = path
        return ShellResult("")

    def _cmd_ls(self, args: list[str]) -> ShellResult:
        show_all = any("a" in arg[1:] for arg in args if arg.startswith("-"))
        long = any("l" in arg[1:] for arg in args if arg.startswith("-"))
        targets = [arg for arg in args if not arg.startswith("-")]
        target = targets[-1] if targets else self.cwd
        path = self.fs.normalize(target, self.cwd)
        if not self.fs.exists(path):
            return ShellResult(f"ls: cannot access '{target}': No such file or directory")
        if not self.fs.is_dir(path):
            return ShellResult(posixpath.basename(path))
        items = self.fs.list_dir(path)
        if show_all:
            items = [".", "..", *items]
        if not long:
            return ShellResult("  ".join(items))
        lines = ["total 20"]
        for item in items:
            child = self.fs.normalize(item, path)
            if item in {".", ".."}:
                lines.append(f"drwxr-xr-x 2 {self.username} {self.username} 4096 Aug 10 07:00 {item}")
            elif self.fs.is_dir(child):
                lines.append(f"drwxr-xr-x 2 {self.username} {self.username} 4096 Aug 10 07:00 {item}")
            else:
                size = len(self.fs.read(child) or "")
                lines.append(f"-rw-r--r-- 1 {self.username} {self.username} {size:4d} Aug 10 07:00 {item}")
        return ShellResult("\n".join(lines))

    def _cmd_cat(self, args: list[str]) -> ShellResult:
        if not args:
            return ShellResult("")
        output: list[str] = []
        for raw in args:
            path = self.fs.normalize(raw, self.cwd)
            if not self.fs.exists(path):
                output.append(f"cat: {raw}: No such file or directory")
            elif self.fs.is_dir(path):
                output.append(f"cat: {raw}: Is a directory")
            else:
                output.append((self.fs.read(path) or "").rstrip("\n"))
        return ShellResult("\n".join(output))

    def _cmd_head(self, args: list[str]) -> ShellResult:
        return self._head_tail(args, tail=False)

    def _cmd_tail(self, args: list[str]) -> ShellResult:
        return self._head_tail(args, tail=True)

    def _head_tail(self, args: list[str], tail: bool) -> ShellResult:
        targets = [arg for arg in args if not arg.startswith("-")]
        if not targets:
            return ShellResult("")
        path = self.fs.normalize(targets[-1], self.cwd)
        content = self.fs.read(path)
        if content is None:
            return ShellResult(f"{'tail' if tail else 'head'}: cannot open '{targets[-1]}'")
        lines = content.splitlines()
        chosen = lines[-10:] if tail else lines[:10]
        return ShellResult("\n".join(chosen))

    def _cmd_echo(self, args: list[str]) -> ShellResult:
        return ShellResult(" ".join(args))

    def _cmd_touch(self, args: list[str]) -> ShellResult:
        for raw in args:
            path = self.fs.normalize(raw, self.cwd)
            try:
                self.fs.write_file(path, self.fs.read(path) or "")
            except FileNotFoundError:
                return ShellResult(f"touch: cannot touch '{raw}': No such file or directory")
        return ShellResult("")

    def _cmd_mkdir(self, args: list[str]) -> ShellResult:
        targets = [arg for arg in args if not arg.startswith("-")]
        for raw in targets:
            path = self.fs.normalize(raw, self.cwd)
            if self.fs.exists(path):
                return ShellResult(f"mkdir: cannot create directory '{raw}': File exists")
            try:
                self.fs.mkdir(path)
            except FileNotFoundError:
                return ShellResult(f"mkdir: cannot create directory '{raw}': No such file or directory")
        return ShellResult("")

    def _cmd_rm(self, args: list[str]) -> ShellResult:
        recursive = any("r" in arg[1:] for arg in args if arg.startswith("-"))
        targets = [arg for arg in args if not arg.startswith("-")]
        for raw in targets:
            path = self.fs.normalize(raw, self.cwd)
            try:
                self.fs.remove(path, recursive=recursive)
            except FileNotFoundError:
                return ShellResult(f"rm: cannot remove '{raw}': No such file or directory")
            except IsADirectoryError:
                return ShellResult(f"rm: cannot remove '{raw}': Is a directory")
            except PermissionError:
                return ShellResult(f"rm: cannot remove '{raw}': Permission denied")
        return ShellResult("")

    def _cmd_find(self, args: list[str]) -> ShellResult:
        root = self.fs.normalize(args[0], self.cwd) if args and not args[0].startswith("-") else self.cwd
        pattern = None
        if "-name" in args:
            index = args.index("-name")
            if index + 1 < len(args):
                pattern = args[index + 1].replace("*", "")
        found = [path for path in sorted(self.fs.entries) if path.startswith(root)]
        if pattern:
            found = [path for path in found if pattern.lower() in posixpath.basename(path).lower()]
        return ShellResult("\n".join(found[:100]))

    def _cmd_grep(self, args: list[str]) -> ShellResult:
        plain = [arg for arg in args if not arg.startswith("-")]
        if len(plain) < 2:
            return ShellResult("grep: missing search pattern or file")
        needle, raw_path = plain[0], plain[-1]
        path = self.fs.normalize(raw_path, self.cwd)
        content = self.fs.read(path)
        if content is None:
            return ShellResult(f"grep: {raw_path}: No such file or directory")
        lines = [line for line in content.splitlines() if needle.lower() in line.lower()]
        return ShellResult("\n".join(lines))

    def _cmd_ps(self, _: list[str]) -> ShellResult:
        return ShellResult(
            "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root         1  0.0  0.4  22088 13240 ?        Ss   06:59   0:01 /sbin/init\n"
            "www-data   623  0.1  1.2 145120 38400 ?        S    07:00   0:03 nginx: worker\n"
            f"{self.username:<10} 912  0.0  0.1  10440  5120 pts/0    Ss   07:10   0:00 -bash"
        )

    def _cmd_ss(self, _: list[str]) -> ShellResult:
        return ShellResult(
            "Netid State  Local Address:Port  Peer Address:Port Process\n"
            "tcp   LISTEN 0.0.0.0:22          0.0.0.0:*\n"
            "tcp   LISTEN 0.0.0.0:80          0.0.0.0:*\n"
            "tcp   LISTEN 127.0.0.1:5432      0.0.0.0:*"
        )

    def _cmd_netstat(self, args: list[str]) -> ShellResult:
        return self._cmd_ss(args)

    def _cmd_ifconfig(self, _: list[str]) -> ShellResult:
        return ShellResult(
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.20.0.15  netmask 255.255.255.0  broadcast 10.20.0.255"
        )

    def _cmd_ip(self, _: list[str]) -> ShellResult:
        return ShellResult(
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
            "    inet 10.20.0.15/24 brd 10.20.0.255 scope global eth0"
        )

    def _cmd_df(self, _: list[str]) -> ShellResult:
        return ShellResult(
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/sda2        40G   11G   27G  29% /\n"
            "tmpfs           1.9G     0  1.9G   0% /dev/shm"
        )

    def _cmd_free(self, _: list[str]) -> ShellResult:
        return ShellResult(
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:            3924        1220        1841          21         862        2460\n"
            "Swap:           2047           0        2047"
        )

    def _cmd_sudo(self, _: list[str]) -> ShellResult:
        return ShellResult(f"{self.username} is not in the sudoers file. This incident will be reported.")

    def _cmd_env(self, _: list[str]) -> ShellResult:
        return ShellResult(
            f"SHELL=/bin/bash\nUSER={self.username}\nHOME=/home/{self.username}\n"
            "LANG=C.UTF-8\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        )

    def _cmd_printenv(self, args: list[str]) -> ShellResult:
        return self._cmd_env(args)

    def _cmd_curl(self, args: list[str]) -> ShellResult:
        target = next((arg for arg in args if arg.startswith("http")), "remote host")
        return ShellResult(f"curl: (7) Failed to connect to {target}: Connection refused")

    def _cmd_wget(self, args: list[str]) -> ShellResult:
        target = next((arg for arg in args if arg.startswith("http")), "remote host")
        return ShellResult(f"--2026-08-10 07:15:00--  {target}\nConnecting... failed: Connection refused.")
