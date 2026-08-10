from app.database import Database
from app.repository import HoneypotRepository
from app.risk import RiskAnalyzer


def test_repository_session_lifecycle():
    database = Database("sqlite+pysqlite:///:memory:")
    database.create_all()
    repository = HoneypotRepository(database)
    analyzer = RiskAnalyzer()

    session_id = repository.create_session("127.0.0.1", 12345, "guest")
    risk = analyzer.analyze("cat /etc/shadow")
    repository.add_command(session_id, "cat /etc/shadow", "permission denied", risk, False)
    repository.close_session(session_id)

    item = repository.get_session(session_id)
    assert item is not None
    assert item.status == "CLOSED"
    assert item.command_count == 1
    assert item.severity in {"HIGH", "CRITICAL"}
    assert len(item.commands) == 1
