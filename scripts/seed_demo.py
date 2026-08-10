from pathlib import Path
import sys

# Allow running as: python scripts/seed_demo.py
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import Settings
from app.database import Database
from app.repository import HoneypotRepository
from app.risk import RiskAnalyzer


def main() -> None:
    settings = Settings(start_ssh_server=False)
    database = Database(settings.database_url)
    database.create_all()
    repository = HoneypotRepository(database)
    analyzer = RiskAnalyzer()

    scenarios = [
        (
            "192.168.56.101",
            "root",
            ["whoami", "uname -a", "cat /etc/passwd", 'find / -name "*.pem"'],
        ),
        (
            "192.168.56.102",
            "admin",
            ["id", "ss -tulpn", "cat /opt/inventory-api/.env", "history -c"],
        ),
        (
            "192.168.56.103",
            "guest",
            ["pwd", "ls -la", "cat notes.txt"],
        ),
    ]

    for index, (ip, username, commands) in enumerate(scenarios, start=1):
        session_id = repository.create_session(ip, 50000 + index, username)
        for command in commands:
            risk = analyzer.analyze(command)
            repository.add_command(
                session_id,
                command,
                "[demo response]",
                risk,
                used_llm=False,
            )
        repository.close_session(session_id)

    print("Demo data created.")


if __name__ == "__main__":
    main()
