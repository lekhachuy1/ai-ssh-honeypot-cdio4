from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from app.config import Settings
from app.llm import OllamaClient
from app.repository import HoneypotRepository
from app.risk import RiskAnalyzer
from app.virtual_shell import VirtualShell

logger = logging.getLogger(__name__)

try:
    import asyncssh
except ImportError:  # Web dashboard can still start in reduced mode.
    asyncssh = None  # type: ignore[assignment]


if asyncssh is not None:

    class HoneypotSSHServer(asyncssh.SSHServer):
        def __init__(self, settings: Settings):
            self.settings = settings

        def connection_made(self, conn):  # noqa: ANN001
            peer = conn.get_extra_info("peername")
            logger.info("SSH connection from %s", peer)

        def connection_lost(self, exc):  # noqa: ANN001
            if exc:
                logger.warning("SSH connection error: %s", exc)

        def begin_auth(self, username: str) -> bool:
            return True

        def password_auth_supported(self) -> bool:
            return True

        def validate_password(self, username: str, password: str) -> bool:
            # Intentionally never stores the supplied password.
            if self.settings.accept_any_password:
                return True
            return (
                username == self.settings.honeypot_username
                and password == self.settings.honeypot_password
            )


async def _handle_process(
    process,  # asyncssh.SSHServerProcess at runtime
    settings: Settings,
    repository: HoneypotRepository,
    llm: OllamaClient,
) -> None:
    peer = process.get_extra_info("peername") or ("unknown", 0)
    source_ip = str(peer[0]) if isinstance(peer, tuple) and peer else "unknown"
    source_port = int(peer[1]) if isinstance(peer, tuple) and len(peer) > 1 else 0
    username = str(process.get_extra_info("username") or "guest")

    session_id = repository.create_session(source_ip, source_port, username)
    shell = VirtualShell(username=username)
    analyzer = RiskAnalyzer()

    process.stdout.write(
        "Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-52-generic x86_64)\n\n"
        " * Documentation:  https://help.ubuntu.com\n"
        " * Management:     https://landscape.canonical.com\n\n"
    )

    try:
        while True:
            process.stdout.write(shell.prompt)
            try:
                line = await asyncio.wait_for(
                    process.stdin.readline(), timeout=settings.session_idle_timeout_seconds
                )
            except TimeoutError:
                process.stdout.write("\nConnection timed out.\n")
                break
            except asyncssh.BreakReceived:
                process.stdout.write("^C\n")
                continue

            if not line:
                break
            command = line.rstrip("\r\n")[: settings.max_command_length]
            risk = analyzer.analyze(command)
            result = shell.execute(command)
            used_llm = False

            if not result.handled:
                llm_result = await llm.simulate_command(command, shell.context())
                output = llm_result.text
                used_llm = llm_result.used_llm
            else:
                output = result.output

            output = output[: settings.max_response_length]
            repository.add_command(session_id, command, output, risk, used_llm)

            if output:
                process.stdout.write(output)
                if not output.endswith("\n"):
                    process.stdout.write("\n")
            if result.should_exit:
                break
    except (asyncssh.DisconnectError, ConnectionError, OSError) as exc:
        logger.info("SSH session %s disconnected: %s", session_id, exc)
    finally:
        commands = repository.get_session_commands(session_id)
        max_risk = max((analyzer.analyze(cmd).score for cmd in commands), default=0)
        classification = analyzer.classify_session(max_risk, len(commands))
        mitre = sorted(
            {
                technique
                for cmd in commands
                for technique in analyzer.analyze(cmd).mitre_techniques
            }
        )
        heuristic = repository.heuristic_summary(
            classification, len(commands), max_risk, ",".join(mitre)
        )
        summary = await llm.summarize_session(commands, heuristic)
        repository.close_session(session_id, summary=summary)
        try:
            process.exit(0)
        except Exception:
            pass


async def start_ssh_server(
    settings: Settings, repository: HoneypotRepository, llm: OllamaClient
):
    if asyncssh is None:
        raise RuntimeError("AsyncSSH is not installed. Run: pip install -e .")

    key_path = Path(settings.ssh_host_key_path)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if not key_path.exists():
        key = asyncssh.generate_private_key("ssh-ed25519")
        key.write_private_key(key_path)
        key_path.chmod(0o600)

    logger.info("Starting SSH honeypot on %s:%s", settings.ssh_host, settings.ssh_port)
    return await asyncssh.listen(
        settings.ssh_host,
        settings.ssh_port,
        server_factory=lambda: HoneypotSSHServer(settings),
        server_host_keys=[str(key_path)],
        process_factory=lambda process: _handle_process(process, settings, repository, llm),
        line_editor=True,
    )
