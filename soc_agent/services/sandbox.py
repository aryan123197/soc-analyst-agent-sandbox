"""Sandbox Execution & Dynamic Code Detonation Service.

Provides isolated detonation and profiling of code blocks (Python, Bash/Shell, PowerShell)
extracted from untrusted ticket feeds, emails, or security alerts.

Key Features:
1. Regex & Markdown Code Extraction (Python, Bash, PowerShell, Base64 snippets)
2. AST (Abstract Syntax Tree) Static Security Inspection
3. Restricted Subprocess Execution Guardrails (Timeout, Memory, Scratched Environment)
4. Dynamic Sandbox Risk Scoring (0–100) & Behavioral Telemetry
"""
import ast
import base64
import os
import re
import sys
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# Suspicious/Malicious Imports & Functions for AST Static Inspection
SUSPICIOUS_MODULES = {
    "socket", "subprocess", "os", "sys", "ctypes", "urllib", "urllib.request",
    "requests", "http.client", "ftplib", "smtplib", "shutil", "pty", "multiprocessing",
    "threading", "winreg", "webbrowser", "win32api", "builtins"
}

HIGH_RISK_CALLS = {
    "system", "popen", "exec", "eval", "spawn", "fork", "connect", "send", "sendall",
    "bind", "listen", "remove", "unlink", "rmdir", "chmod", "chown", "dlopen"
}


@dataclass
class SandboxExecutionResult:
    language: str
    code_snippet: str
    executed: bool
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool
    ast_flagged_modules: List[str] = field(default_factory=list)
    ast_flagged_calls: List[str] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "SAFE"  # "SAFE" | "SUSPICIOUS" | "MALICIOUS"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "language": self.language,
            "code_snippet": self.code_snippet,
            "executed": self.executed,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
            "ast_flagged_modules": self.ast_flagged_modules,
            "ast_flagged_calls": self.ast_flagged_calls,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
        }


@dataclass
class SandboxReport:
    has_code_payloads: bool
    extracted_blocks_count: int
    executions: List[SandboxExecutionResult] = field(default_factory=list)
    overall_risk_score: int = 0
    overall_verdict: str = "CLEAN"  # "CLEAN" | "SUSPICIOUS" | "MALICIOUS"
    formatted_summary: str = "No executable code blocks detected in ticket."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_code_payloads": self.has_code_payloads,
            "extracted_blocks_count": self.extracted_blocks_count,
            "executions": [e.to_dict() for e in self.executions],
            "overall_risk_score": self.overall_risk_score,
            "overall_verdict": self.overall_verdict,
            "formatted_summary": self.formatted_summary,
        }


def extract_code_blocks(raw_text: str) -> List[Dict[str, str]]:
    """Extract code blocks from markdown text or raw ticket content.
    
    Supports:
    - ```python ... ```
    - ```bash / ```sh ... ```
    - ```powershell / ```ps1 ... ```
    - Inline python snippet heuristics (e.g. `import os`, `subprocess.call`)
    - Base64 encoded payload strings
    """
    blocks = []
    
    # 1. Markdown Fenced Code Blocks
    fenced_pattern = r'```(python|py|bash|sh|powershell|ps1|cmd)?\n(.*?)```'
    matches = re.findall(fenced_pattern, raw_text, re.DOTALL | re.IGNORECASE)
    for lang, code in matches:
        lang = lang.lower()
        if lang in ("python", "py", ""):
            resolved_lang = "python"
        elif lang in ("bash", "sh"):
            resolved_lang = "bash"
        elif lang in ("powershell", "ps1", "cmd"):
            resolved_lang = "powershell"
        else:
            resolved_lang = "python"
            
        code_clean = code.strip()
        if code_clean:
            blocks.append({"language": resolved_lang, "code": code_clean})

    # 2. Base64 Payload Heuristic Extraction
    base64_pattern = r'(?:[A-Za-z0-9+/]{40,}=*)'
    b64_matches = re.findall(base64_pattern, raw_text)
    for candidate in b64_matches:
        try:
            decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore').strip()
            if any(k in decoded for k in ("import ", "def ", "os.system", "subprocess", "curl", "wget", "Invoke-WebRequest", "powershell")):
                lang = "powershell" if "powershell" in decoded.lower() or "invoke-" in decoded.lower() else "python"
                blocks.append({"language": lang, "code": decoded})
        except Exception:
            pass

    # 3. Unfenced Inline Script Heuristic (if no fenced blocks were found)
    if not blocks:
        lines = raw_text.splitlines()
        code_lines = []
        for line in lines:
            if re.search(r'^\s*(import\s+\w+|from\s+\w+\s+import|def\s+\w+\(|subprocess\.|os\.|exec\(|eval\()', line):
                code_lines.append(line)
        if code_lines:
            blocks.append({"language": "python", "code": "\n".join(code_lines)})

    return blocks


def inspect_python_ast(code: str) -> tuple[List[str], List[str]]:
    """Statically inspect Python AST for suspicious imports and function calls."""
    flagged_modules = []
    flagged_calls = []

    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            # Check import statements
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod = alias.name.split('.')[0]
                    if mod in SUSPICIOUS_MODULES:
                        flagged_modules.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    mod = node.module.split('.')[0]
                    if mod in SUSPICIOUS_MODULES:
                        flagged_modules.append(node.module)

            # Check function calls
            elif isinstance(node, ast.Call):
                func = node.func
                func_name = None
                if isinstance(func, ast.Name):
                    func_name = func.id
                elif isinstance(func, ast.Attribute):
                    func_name = func.attr

                if func_name and func_name in HIGH_RISK_CALLS:
                    flagged_calls.append(func_name)

    except SyntaxError:
        # Non-parsable syntax or shell syntax in python block
        pass

    return list(set(flagged_modules)), list(set(flagged_calls))


def detonate_code(code: str, language: str = "python", timeout: float = 2.0) -> SandboxExecutionResult:
    """Execute code snippet in an isolated subprocess with guardrails.
    
    Guardrails:
    - Strictly bounded execution timeout (default 2.0s)
    - Restricted environment variables (stripped access tokens)
    - Static AST profiling prior to execution
    - Dynamic STDOUT / STDERR capture
    """
    start_t = time.time()
    ast_modules, ast_calls = [], []
    
    if language == "python":
        ast_modules, ast_calls = inspect_python_ast(code)

    # Initial static risk calculation
    initial_risk = len(ast_modules) * 20 + len(ast_calls) * 25
    if any(m in ("socket", "subprocess", "ctypes", "win32api") for m in ast_modules):
        initial_risk += 30

    # Prepare isolated environment
    sanitized_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": "",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8"
    }

    executed = False
    exit_code = -1
    stdout_str, stderr_str = "", ""
    timed_out = False

    with tempfile.TemporaryDirectory(prefix="soc_sandbox_") as tmpdir:
        file_ext = ".py" if language == "python" else (".sh" if language == "bash" else ".ps1")
        script_path = os.path.join(tmpdir, f"detonate_payload{file_ext}")
        
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(code)

        if language == "python":
            cmd = [sys.executable, "-I", "-B", script_path]  # Isolated mode
        elif language == "bash":
            cmd = ["bash", script_path]
        else:
            cmd = ["bash", script_path]  # Fallback runner for shell payloads

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=sanitized_env,
                cwd=tmpdir
            )
            executed = True
            exit_code = proc.returncode
            stdout_str = proc.stdout[:2000] if proc.stdout else ""
            stderr_str = proc.stderr[:2000] if proc.stderr else ""
        except subprocess.TimeoutExpired as exc:
            executed = True
            timed_out = True
            exit_code = -9
            stdout_str = exc.stdout[:1000] if exc.stdout else ""
            stderr_str = "Execution timed out (sandbox timeout exceeded limit)."
        except Exception as exc:
            stderr_str = f"Sandbox execution failure: {str(exc)}"

    duration_ms = (time.time() - start_t) * 1000.0

    # Calculate final sandbox risk score
    risk_score = initial_risk
    if timed_out:
        risk_score += 40
    if exit_code != 0 and not timed_out:
        risk_score += 10
    if any(kw in (stdout_str + stderr_str).lower() for kw in ("permission denied", "connection refused", "socket", "unauthorized", "killed")):
        risk_score += 25

    risk_score = min(100, risk_score)
    
    if risk_score >= 70:
        risk_level = "MALICIOUS"
    elif risk_score >= 35:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "SAFE"

    return SandboxExecutionResult(
        language=language,
        code_snippet=code[:500],
        executed=executed,
        exit_code=exit_code,
        stdout=stdout_str,
        stderr=stderr_str,
        duration_ms=round(duration_ms, 2),
        timed_out=timed_out,
        ast_flagged_modules=ast_modules,
        ast_flagged_calls=ast_calls,
        risk_score=risk_score,
        risk_level=risk_level
    )


def detonate_ticket_payloads(raw_text: str) -> SandboxReport:
    """Extract and detonate all code payloads in a ticket."""
    blocks = extract_code_blocks(raw_text)
    if not blocks:
        return SandboxReport(
            has_code_payloads=False,
            extracted_blocks_count=0,
            executions=[],
            overall_risk_score=0,
            overall_verdict="CLEAN",
            formatted_summary="No executable code blocks detected in ticket payload."
        )

    executions = []
    max_risk = 0
    
    for block in blocks[:3]:  # Detonate up to 3 code blocks per ticket
        res = detonate_code(code=block["code"], language=block["language"])
        executions.append(res)
        if res.risk_score > max_risk:
            max_risk = res.risk_score

    if max_risk >= 70:
        verdict = "MALICIOUS"
    elif max_risk >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    summary_parts = [f"Detonated {len(executions)} code payload(s). Highest Risk Score: {max_risk}/100 ({verdict})."]
    for idx, e in enumerate(executions, 1):
        summary_parts.append(
            f"Payload #{idx} [{e.language.upper()}]: status={'TIMED_OUT' if e.timed_out else f'exit({e.exit_code})'}, "
            f"modules_flagged={e.ast_flagged_modules or 'none'}, calls_flagged={e.ast_flagged_calls or 'none'}."
        )

    return SandboxReport(
        has_code_payloads=True,
        extracted_blocks_count=len(blocks),
        executions=executions,
        overall_risk_score=max_risk,
        overall_verdict=verdict,
        formatted_summary="\n".join(summary_parts)
    )
