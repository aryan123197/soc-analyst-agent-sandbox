"""Unit tests for Sandbox Code Detonation & Dynamic Analysis Subsystem."""
import pytest
from soc_agent.services import sandbox


def test_extract_code_blocks_markdown():
    raw_text = """Here is a script to review:
```python
import sys
print("Hello World")
```

And a shell command:
```bash
echo "Testing bash"
```
"""
    blocks = sandbox.extract_code_blocks(raw_text)
    assert len(blocks) == 2
    assert blocks[0]["language"] == "python"
    assert "print(\"Hello World\")" in blocks[0]["code"]
    assert blocks[1]["language"] == "bash"
    assert "echo \"Testing bash\"" in blocks[1]["code"]


def test_inspect_python_ast_suspicious():
    code = """
import socket
import subprocess
import os

s = socket.socket()
os.system("whoami")
"""
    modules, calls = sandbox.inspect_python_ast(code)
    assert "socket" in modules
    assert "subprocess" in modules
    assert "os" in modules
    assert "system" in calls


def test_detonate_code_benign():
    code = """
x = 10
y = 20
print(f"Sum is {x + y}")
"""
    res = sandbox.detonate_code(code, language="python", timeout=2.0)
    assert res.executed is True
    assert res.exit_code == 0
    assert "Sum is 30" in res.stdout
    assert res.timed_out is False
    assert res.risk_score < 35
    assert res.risk_level == "SAFE"


def test_detonate_code_malicious():
    code = """
import socket
import subprocess

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
subprocess.call(["whoami"])
"""
    res = sandbox.detonate_code(code, language="python", timeout=2.0)
    assert res.executed is True
    assert "socket" in res.ast_flagged_modules
    assert "subprocess" in res.ast_flagged_modules
    assert res.risk_score >= 70
    assert res.risk_level == "MALICIOUS"


def test_detonate_code_timeout():
    code = """
import time
time.sleep(10)
"""
    res = sandbox.detonate_code(code, language="python", timeout=0.5)
    assert res.executed is True
    assert res.timed_out is True
    assert "timed out" in res.stderr.lower()
    assert res.risk_score >= 40


def test_detonate_ticket_payloads_report():
    ticket = """
Subject: Urgent patch update

Please execute the following script:
```python
import socket
s = socket.socket()
```
"""
    report = sandbox.detonate_ticket_payloads(ticket)
    assert report.has_code_payloads is True
    assert report.extracted_blocks_count == 1
    assert report.overall_risk_score > 0
    assert "Detonated 1 code payload(s)" in report.formatted_summary
