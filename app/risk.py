from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RiskRule:
    name: str
    pattern: re.Pattern[str]
    score: int
    label: str
    mitre: str = ""


@dataclass(frozen=True)
class RiskResult:
    score: int
    severity: str
    labels: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    matched_rules: tuple[str, ...]


RULES: tuple[RiskRule, ...] = (
    RiskRule(
        "system-discovery",
        re.compile(r"\b(whoami|id|uname|hostnamectl?|lscpu|lsb_release)\b", re.I),
        5,
        "System Discovery",
        "T1082",
    ),
    RiskRule(
        "network-discovery",
        re.compile(r"\b(ip\s+(a|addr|route)|ifconfig|ss\b|netstat|arp\b|route\b)" , re.I),
        8,
        "Network Discovery",
        "T1016",
    ),
    RiskRule(
        "process-discovery",
        re.compile(r"\b(ps\s|top\b|pstree|pgrep)" , re.I),
        6,
        "Process Discovery",
        "T1057",
    ),
    RiskRule(
        "account-discovery",
        re.compile(r"(/etc/passwd|\bgetent\s+passwd|\blastlog\b|\blast\b)", re.I),
        15,
        "Account Discovery",
        "T1087",
    ),
    RiskRule(
        "sensitive-file-access",
        re.compile(
            r"(\.env\b|/etc/shadow|id_rsa|authorized_keys|\.aws/credentials|"
            r"\.kube/config|\.npmrc|\.docker/config\.json)",
            re.I,
        ),
        55,
        "Unsecured Credentials",
        "T1552",
    ),
    RiskRule(
        "credential-search",
        re.compile(
            r"\b(find|grep|rg)\b.*(pass(word)?|secret|token|credential|\.pem|\.key)",
            re.I,
        ),
        35,
        "Credential Search",
        "T1552.001",
    ),
    RiskRule(
        "ingress-tool-transfer",
        re.compile(r"\b(curl|wget|scp|sftp|ftp|tftp)\b", re.I),
        25,
        "Ingress Tool Transfer",
        "T1105",
    ),
    RiskRule(
        "download-and-execute",
        re.compile(r"\b(curl|wget)\b.+\|\s*(ba)?sh\b", re.I),
        70,
        "Download and Execute",
        "T1105",
    ),
    RiskRule(
        "privilege-escalation",
        re.compile(r"\b(sudo|su\s+-?|pkexec|doas)\b", re.I),
        25,
        "Privilege Escalation Attempt",
        "T1548",
    ),
    RiskRule(
        "persistence-account",
        re.compile(r"\b(useradd|adduser|usermod|groupadd)\b", re.I),
        45,
        "Account Persistence",
        "T1136",
    ),
    RiskRule(
        "persistence-cron-service",
        re.compile(r"\b(crontab|systemctl\s+enable|update-rc\.d)\b", re.I),
        40,
        "Scheduled Task or Service Persistence",
        "T1053",
    ),
    RiskRule(
        "reverse-shell",
        re.compile(
            r"(bash\s+-i|sh\s+-i|nc\s+.*-e|ncat\s+.*-e|/dev/tcp/|"
            r"python\w*\s+-c.+socket|socat.+exec)",
            re.I,
        ),
        90,
        "Reverse Shell",
        "T1059",
    ),
    RiskRule(
        "encoded-execution",
        re.compile(r"\b(base64\s+(-d|--decode)|python\w*\s+-c|perl\s+-e|ruby\s+-e)\b", re.I),
        35,
        "Command and Scripting Interpreter",
        "T1059",
    ),
    RiskRule(
        "log-deletion",
        re.compile(r"(history\s+-c|rm\s+.*(/var/log|\.bash_history)|truncate\s+.*log)", re.I),
        55,
        "Indicator Removal",
        "T1070",
    ),
    RiskRule(
        "destructive-command",
        re.compile(r"(rm\s+-[^\n]*r[^\n]*f[^\n]*\s+/(\s|$)|mkfs\b|dd\s+if=|:(){:|:&};:)", re.I),
        100,
        "Destructive Impact",
        "T1485",
    ),
    RiskRule(
        "container-escape-interest",
        re.compile(r"(docker\s+run.+-v\s+/:|/var/run/docker\.sock|nsenter\b)", re.I),
        75,
        "Container Escape Attempt",
        "T1611",
    ),
)


def severity_for_score(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


class RiskAnalyzer:
    def analyze(self, command: str) -> RiskResult:
        matches = [rule for rule in RULES if rule.pattern.search(command)]
        score = min(100, sum(rule.score for rule in matches))
        labels = tuple(dict.fromkeys(rule.label for rule in matches))
        mitre = tuple(dict.fromkeys(rule.mitre for rule in matches if rule.mitre))
        names = tuple(rule.name for rule in matches)
        return RiskResult(score, severity_for_score(score), labels, mitre, names)

    def classify_session(self, max_score: int, command_count: int) -> str:
        if max_score >= 80:
            return "MALICIOUS"
        if max_score >= 35 or command_count >= 15:
            return "SUSPICIOUS"
        return "BENIGN"
