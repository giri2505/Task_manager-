"""
NetWorker Backup Remediation System
====================================
Single-file application. Run:  python app.py
Open:  http://localhost:5050

No other files needed except this one.
Install:  pip install flask paramiko
"""

import csv
import io
import json
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime

from flask import Flask, jsonify, render_template_string, request

# ─── pip install check ────────────────────────────────────────────────────────
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

app = Flask(__name__)

# ─── Storage ──────────────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
TICKETS_FILE = os.path.join(BASE_DIR, "tickets.json")
AUDIT_FILE   = os.path.join(BASE_DIR, "audit.json")
CONFIG_FILE  = os.path.join(BASE_DIR, "config.json")

_tickets: dict = {}
_audit:   list = []
_logs:    dict = {}
_running: dict = {}

DEFAULT_CONFIG = {
    "azure_openai_endpoint":    "",
    "azure_openai_api_key":     "",
    "azure_openai_deployment":  "gpt-4o",
    "azure_openai_api_version": "2024-02-01",
    "linux_username":           "svc_backup",
    "linux_auth_method":        "password",
    "linux_password":           "",
    "linux_key_path":           "",
    "linux_key_text":           "",
    "linux_services":           ["nsrexecd"],
    "windows_rdp_domain":       "CORP",
    "nw_retrigger_cmd":         "",
    "min_disk_gb":              10,
    "ping_retries":             3,
    "ssh_timeout_sec":          15,
    "auto_run_new":             False,
    "dry_run":                  False,
    "server_port":              5050,
}


# ─── Persistence ──────────────────────────────────────────────────────────────

def load_all():
    global _tickets, _audit
    for path, target, default in [
        (TICKETS_FILE, "_tickets", {}),
        (AUDIT_FILE,   "_audit",   []),
    ]:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                if target == "_tickets":
                    _tickets = data
                else:
                    _audit = data
            except Exception as e:
                print(f"[WARN] Could not load {path}: {e}")


def save_tickets():
    with open(TICKETS_FILE, "w") as f:
        json.dump(_tickets, f, indent=2)


def save_audit():
    with open(AUDIT_FILE, "w") as f:
        json.dump(_audit[-500:], f, indent=2)  # keep last 500 entries


def cfg():
    c = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                c.update(json.load(f))
        except Exception:
            pass
    return c


def save_cfg(data: dict):
    c = cfg()
    c.update(data)
    with open(CONFIG_FILE, "w") as f:
        json.dump(c, f, indent=2)


def audit(action: str, ticket_id: str, detail: str, level: str = "INFO"):
    entry = {
        "ts":        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "level":     level,
        "action":    action,
        "ticket_id": ticket_id,
        "detail":    detail,
    }
    _audit.append(entry)
    save_audit()


def tlog(tid: str, msg: str):
    ts   = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    _logs.setdefault(tid, []).append(line)
    print(f"  [{tid}] {msg}")


# ─── AI (Azure OpenAI) ────────────────────────────────────────────────────────

def ai_call(messages: list, temperature=0.2, max_tokens=800, json_mode=False) -> str:
    c = cfg()
    endpoint   = c.get("azure_openai_endpoint", "").rstrip("/")
    api_key    = c.get("azure_openai_api_key", "")
    deployment = c.get("azure_openai_deployment", "gpt-4o")
    api_ver    = c.get("azure_openai_api_version", "2024-02-01")
    if not endpoint or not api_key:
        raise RuntimeError("Azure OpenAI not configured — go to Settings.")
    url  = f"{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={api_ver}"
    body = {"messages": messages, "temperature": temperature, "max_tokens": max_tokens}
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "api-key": api_key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())["choices"][0]["message"]["content"]
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"OpenAI HTTP {e.code}: {e.read().decode()[:300]}")


def ai_parse_ticket(raw: str, structured: dict = None) -> dict:
    context = ""
    if structured:
        context = "Form fields:\n" + "\n".join(f"  {k}: {v}" for k,v in structured.items() if v) + "\n\nDescription:\n"
    try:
        raw_json = ai_call([
            {"role": "system", "content": """Extract backup failure ticket info. Return ONLY JSON:
{
  "ticket_id": "INC number",
  "nw_server": "NetWorker server hostname",
  "client": "backup client hostname that failed",
  "os_type": "Windows or Linux",
  "error_code": "error code if any",
  "error_summary": "one sentence description",
  "priority": "P1/P2/P3/P4",
  "confidence": "high/medium/low"
}
Rules: nw_server is the backup server (has nw/backup/bkp in name). client is the server that failed to back up.
If OS unknown, guess from hostname (win/sql/dc=Windows, else Linux). Never return null for nw_server or client."""},
            {"role": "user", "content": context + raw},
        ], temperature=0.1, max_tokens=400, json_mode=True)
        result = json.loads(raw_json)
        result["ai_parsed"] = True
        result["ai_note"] = f"Parsed by GPT-4o at {datetime.now().strftime('%H:%M:%S')}"
        return result
    except Exception as e:
        tid = (structured or {}).get("number", "UNKNOWN")
        return {
            "ticket_id": tid, "nw_server": (structured or {}).get("nw_server",""),
            "client": (structured or {}).get("client",""), "os_type": "Unknown",
            "error_summary": raw[:200], "priority": "P3",
            "confidence": "low", "ai_parsed": False, "ai_note": f"AI failed: {e}",
        }


def ai_plan(ticket: dict) -> dict:
    summary = json.dumps({k: ticket.get(k) for k in
        ("ticket_id","nw_server","client","os_type","error_code","error_summary","priority")}, indent=2)
    try:
        raw = ai_call([
            {"role": "system", "content": """You are a NetWorker backup automation engine.
Decide which steps to run. Return ONLY JSON:
{"steps": [...], "rationale": "one sentence", "risk_level": "low/medium/high"}

Available steps: reachability, os_detect, ssh_login, service_check, disk_check, retrigger, rdp_workorder
Rules:
- ALWAYS start with reachability
- Windows only: reachability + rdp_workorder (no SSH)
- Linux: reachability, os_detect (if unknown), ssh_login, service_check, disk_check, retrigger
- error mentions nsrexecd/service: prioritize service_check
- error mentions disk/space: put disk_check before retrigger
- Always end with retrigger (Linux) or rdp_workorder (Windows)"""},
            {"role": "user", "content": f"Ticket:\n{summary}"},
        ], temperature=0.1, max_tokens=300, json_mode=True)
        plan = json.loads(raw)
        plan["ai_planned"] = True
        return plan
    except Exception as e:
        os_t = ticket.get("os_type","Unknown")
        steps = (["reachability","rdp_workorder"] if os_t == "Windows"
                 else ["reachability","os_detect","ssh_login","service_check","disk_check","retrigger"])
        return {"steps": steps, "rationale": f"Default plan (AI failed: {e})", "risk_level": "low", "ai_planned": False}


def ai_close_notes(ticket: dict, results: list) -> str:
    ctx = f"Ticket: {ticket.get('ticket_id')}\nClient: {ticket.get('client')}\n"
    ctx += f"Server: {ticket.get('nw_server')}\nOS: {ticket.get('os_type')}\n"
    ctx += f"Error: {ticket.get('error_summary','Backup failure')}\n\nSteps:\n"
    for r in results:
        ctx += f"  [{r.get('step')}] {r.get('status')} — {r.get('note','')}\n"
    try:
        return ai_call([
            {"role": "system", "content": """Write a professional ServiceNow close note for this backup failure.
Include: root cause, automated actions taken, whether backup was retriggered, any follow-up needed.
150-250 words. Plain paragraphs, no bullet points."""},
            {"role": "user", "content": ctx},
        ], temperature=0.4, max_tokens=500).strip()
    except Exception as e:
        lines = [f"=== Close Notes: {ticket.get('ticket_id')} ===",
                 f"Client: {ticket.get('client')} | Server: {ticket.get('nw_server')}",
                 f"Error: {ticket.get('error_summary','Backup failure')}", ""]
        for r in results:
            lines.append(f"  [{r.get('step')}] {r.get('status')} — {r.get('note','')}")
        lines.append(f"\n(AI note generation failed: {e})")
        return "\n".join(lines)


def ai_rdp_workorder(ticket: dict) -> str:
    c = cfg()
    try:
        return ai_call([
            {"role": "system", "content": "Write a step-by-step RDP work order for a Windows backup failure. Number each step. Be specific with service names and PowerShell commands."},
            {"role": "user", "content": f"Client: {ticket.get('client')}\nServer: {ticket.get('nw_server')}\nError: {ticket.get('error_summary','Backup failure')}"},
        ], temperature=0.3, max_tokens=600).strip()
    except Exception as e:
        domain = c.get("windows_rdp_domain", "CORP")
        min_gb = c.get("min_disk_gb", 10)
        return f"""Windows RDP Work Order — {ticket.get('ticket_id')}
Client: {ticket.get('client')} | Server: {ticket.get('nw_server')}

1. RDP into {ticket.get('client')} using your PAM account ({domain}\\<your_username>)
2. Open services.msc → check 'NetWorker Remote Exec Service' is Running
3. If stopped: right-click → Start
4. Open PowerShell as Admin:
   Get-PSDrive -PSProvider FileSystem | Select Name,@{{N='FreeGB';E={{[math]::Round($_.Free/1GB,1)}}}}
5. Verify no drives below {min_gb} GB free. Clean up if needed.
6. Event Viewer → Windows Logs → Application → filter for NetWorker errors
7. To retrigger: connect to {ticket.get('nw_server')} NetWorker console → manually start the backup group
8. Update ticket with findings.

(AI work order generation failed: {e})"""


def ai_rca(tickets: list) -> dict:
    summaries = [{"id": t.get("ticket_id"), "client": t.get("client"),
                  "server": t.get("nw_server"), "os": t.get("os_type"),
                  "error": t.get("error_summary"), "root_cause": t.get("root_cause"),
                  "resolved": t.get("status") in ("Remediated","Partial")}
                 for t in tickets[-50:]]
    try:
        raw = ai_call([
            {"role": "system", "content": """Analyse backup failure tickets. Return ONLY JSON:
{"top_causes":[{"cause":"...","count":N,"recommendation":"..."}],
 "problem_clients":[{"client":"...","failure_count":N,"likely_cause":"..."}],
 "patterns":["..."],
 "priority_actions":["..."],
 "predicted_reduction_pct":N}"""},
            {"role": "user", "content": f"Tickets:\n{json.dumps(summaries,indent=2)}"},
        ], temperature=0.3, max_tokens=1000, json_mode=True)
        result = json.loads(raw)
        result["analysed_at"] = datetime.now().isoformat()
        result["count"] = len(summaries)
        return result
    except Exception as e:
        return {"error": str(e), "analysed_at": datetime.now().isoformat()}


# ─── SSH ──────────────────────────────────────────────────────────────────────

def _load_key_from_text(key_text: str, passphrase: str = None):
    for loader in [paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey]:
        try:
            buf = io.StringIO(key_text.strip())
            kw = {"file_obj": buf}
            if passphrase:
                kw["password"] = passphrase
            return loader.from_private_key(**kw)
        except Exception:
            continue
    raise RuntimeError("Cannot parse SSH private key — check format in Settings")


def get_ssh(hostname: str):
    if not HAS_PARAMIKO:
        raise RuntimeError("paramiko not installed — run: pip install paramiko")
    c = cfg()
    username = c.get("linux_username", "svc_backup")
    method   = c.get("linux_auth_method", "password")
    password = c.get("linux_password") or None
    key_path = c.get("linux_key_path") or None
    key_text = c.get("linux_key_text") or None
    timeout  = c.get("ssh_timeout_sec", 15)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = dict(hostname=hostname, username=username, timeout=timeout)

    if method == "password":
        if not password: raise RuntimeError("Linux password not set — go to Settings")
        kw.update(password=password, look_for_keys=False, allow_agent=False)
    elif method == "key_file":
        if not key_path or not os.path.exists(key_path):
            raise RuntimeError(f"SSH key file not found: {key_path}")
        kw.update(key_filename=key_path, look_for_keys=False, allow_agent=False)
        if password: kw["passphrase"] = password
    elif method == "key_text":
        if not key_text: raise RuntimeError("SSH key text not set — go to Settings")
        kw.update(pkey=_load_key_from_text(key_text, passphrase=password),
                  look_for_keys=False, allow_agent=False)
    elif method == "agent":
        kw.update(allow_agent=True, look_for_keys=True)
    elif method in ("pam","ldap","radius","tacacs"):
        if not password: raise RuntimeError(f"{method} auth needs a password — go to Settings")
        kw.update(password=password, look_for_keys=False, allow_agent=False)
    else:
        raise RuntimeError(f"Unknown SSH method: {method}")

    try:
        client.connect(**kw)
        return client
    except paramiko.AuthenticationException:
        raise RuntimeError(f"SSH auth failed for {username}@{hostname} (method: {method})")
    except Exception as e:
        raise RuntimeError(f"SSH to {hostname} failed: {e}")


def ssh_run(hostname: str, command: str):
    client = get_ssh(hostname)
    try:
        _, stdout, stderr = client.exec_command(command, timeout=60)
        rc = stdout.channel.recv_exit_status()
        return stdout.read().decode().strip(), stderr.read().decode().strip(), rc
    finally:
        client.close()


# ─── Pipeline steps ───────────────────────────────────────────────────────────

def step_ping(hostname: str) -> dict:
    retries = cfg().get("ping_retries", 3)
    timeout = cfg().get("ping_timeout_sec", 3)  # noqa – keep as reference
    os_name = platform.system().lower()
    for _ in range(retries):
        cmd = (["ping","-n","1","-w","3000",hostname] if os_name=="windows"
               else ["ping","-c","1","-W","3",hostname])
        try:
            r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if r.returncode == 0:
                return {"step":"reachability","status":"PASS","note":f"{hostname} is reachable"}
        except Exception:
            pass
    return {"step":"reachability","status":"FAIL","note":f"{hostname} unreachable — ICMP timeout after {retries} retries"}


def step_os_detect(hostname: str, hint: str = "Unknown") -> dict:
    if hint in ("Windows","Linux"):
        return {"step":"os_detect","status":"PASS","note":f"OS from ticket: {hint}","os_type":hint}
    for port, os_t, label in [(22,"Linux","SSH"),(5985,"Windows","WinRM"),(3389,"Windows","RDP")]:
        try:
            with socket.create_connection((hostname, port), timeout=4):
                return {"step":"os_detect","status":"PASS","note":f"Port {port} ({label}) open → {os_t}","os_type":os_t}
        except Exception:
            pass
    return {"step":"os_detect","status":"PASS","note":"Could not detect OS — defaulting to Linux","os_type":"Linux"}


def step_ssh_login(hostname: str) -> dict:
    try:
        out, _, rc = ssh_run(hostname, "hostname && id")
        if rc == 0:
            return {"step":"ssh_login","status":"PASS","note":f"Logged in as {cfg().get('linux_username')} — {out.splitlines()[0]}"}
        return {"step":"ssh_login","status":"FAIL","note":f"hostname command failed (rc={rc})"}
    except RuntimeError as e:
        return {"step":"ssh_login","status":"FAIL","note":str(e)}


def step_service_check(hostname: str) -> dict:
    services = cfg().get("linux_services", ["nsrexecd"])
    results, overall = [], "PASS"
    for svc in services:
        try:
            out, _, rc = ssh_run(hostname,
                f"systemctl is-active {svc} 2>/dev/null || service {svc} status 2>/dev/null | grep -iE 'running|active'")
            running = rc == 0 or "active" in out.lower() or "running" in out.lower()
            if running:
                results.append({"service":svc,"state":"running","action":"none"})
            else:
                _, _, rrc = ssh_run(hostname,
                    f"sudo systemctl restart {svc} 2>/dev/null || sudo service {svc} restart 2>/dev/null")
                _, _, vrc = ssh_run(hostname, f"systemctl is-active {svc} 2>/dev/null")
                if rrc == 0 or vrc == 0:
                    results.append({"service":svc,"state":"restarted","action":"restarted"})
                else:
                    results.append({"service":svc,"state":"restart_failed","action":"restart_failed"})
                    overall = "FAIL"
        except RuntimeError as e:
            results.append({"service":svc,"state":"error","action":"error","error":str(e)})
            overall = "FAIL"

    restarted = [r["service"] for r in results if r["action"]=="restarted"]
    failed    = [r["service"] for r in results if r["action"]=="restart_failed"]
    note = " | ".join(filter(None,[
        f"Restarted: {', '.join(restarted)}" if restarted else "",
        f"Restart FAILED: {', '.join(failed)}" if failed else "",
        "All services running OK" if not restarted and not failed else "",
    ]))
    return {"step":"service_check","status":overall,"note":note,"services":results}


def step_disk_check(hostname: str) -> dict:
    min_gb = cfg().get("min_disk_gb", 10)
    CHECK_PATHS = ["/","/backup","/nsr","/tmp","/var"]
    try:
        out, _, _ = ssh_run(hostname, "df -BG --output=target,avail,pcent 2>/dev/null || df -BG")
        disks, red = [], []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 3: continue
            mp = parts[0]
            if not any(mp == p or mp.startswith(p+"/") for p in CHECK_PATHS): continue
            try:
                avail = float(parts[1].replace("G","").replace("M",""))
                if "M" in parts[1]: avail /= 1024
                flag = "RED" if avail < min_gb else "OK"
                disks.append({"path":mp,"free_gb":round(avail,1),"pct_used":parts[2],"flag":flag})
                if flag == "RED": red.append(f"{mp} ({avail:.1f}GB free)")
            except (ValueError, IndexError):
                continue
        if red:
            return {"step":"disk_check","status":"RED","note":f"Low disk space: {', '.join(red)} — manual cleanup required","disks":disks}
        if disks:
            return {"step":"disk_check","status":"PASS","note":"Sufficient disk space on all paths","disks":disks}
        return {"step":"disk_check","status":"WARN","note":"No matching mount points found","disks":[]}
    except RuntimeError as e:
        return {"step":"disk_check","status":"FAIL","note":str(e),"disks":[]}


def step_retrigger(nw_server: str, client: str) -> dict:
    cmd_tmpl = cfg().get("nw_retrigger_cmd","")
    if not cmd_tmpl:
        return {"step":"retrigger","status":"SKIP","note":"Retrigger command not configured — set in Settings"}
    cmd = cmd_tmpl.format(nw_server=nw_server, client=client)
    if cfg().get("dry_run"):
        return {"step":"retrigger","status":"DRY_RUN","note":f"Dry run — would execute: {cmd}","command":cmd}
    try:
        out, err, rc = ssh_run(nw_server, cmd)
        if rc == 0:
            return {"step":"retrigger","status":"PASS","note":f"Command succeeded on {nw_server}","command":cmd,"output":out[:300]}
        return {"step":"retrigger","status":"FAIL","note":f"Command failed (rc={rc}): {err[:200] or out[:200]}","command":cmd}
    except RuntimeError as e:
        return {"step":"retrigger","status":"FAIL","note":str(e),"command":cmd}


# ─── Pipeline runner ──────────────────────────────────────────────────────────

STEP_LABELS = {
    "reachability":  "Reachability check",
    "os_detect":     "OS identification",
    "ssh_login":     "Service account login",
    "service_check": "Service health check",
    "disk_check":    "Disk space check",
    "retrigger":     "Retrigger backup",
    "rdp_workorder": "RDP work order (Windows)",
}


def run_pipeline(tid: str):
    t = _tickets.get(tid)
    if not t: return
    _running[tid] = True
    _logs[tid] = []

    def log(msg):
        tlog(tid, msg)

    try:
        t["status"]       = "Running"
        t["step_results"] = []
        t["steps_done"]   = 0
        t["updated"]      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        audit("PIPELINE_START", tid, f"Pipeline started for {t.get('client')}")

        log("AI: Planning steps...")
        plan = ai_plan(t)
        t["ai_plan"]    = plan
        t["steps_plan"] = plan.get("steps", [])
        log(f"AI plan: {plan.get('steps')} — {plan.get('rationale')}")
        audit("AI_PLAN", tid, f"Steps: {plan.get('steps')} | {plan.get('rationale')}")

        client    = t.get("client","")
        nw_server = t.get("nw_server","")
        os_type   = t.get("os_type","Unknown")
        steps     = plan.get("steps", ["reachability"])
        total     = len(steps)

        for i, sname in enumerate(steps):
            log(f"Step {i+1}/{total}: {STEP_LABELS.get(sname, sname)}...")
            t["current_step"] = sname
            result = None

            try:
                if sname == "reachability":
                    result = step_ping(client)
                    if result["status"] == "FAIL":
                        t["step_results"].append(result)
                        t["steps_done"] = i + 1
                        t["status"] = "Unreachable"
                        log(f"  STOP: {result['note']}")
                        audit("STEP_FAIL", tid, f"Reachability failed: {result['note']}", "WARN")
                        break

                elif sname == "os_detect":
                    result = step_os_detect(client, os_type)
                    os_type = result.get("os_type", os_type)
                    t["os_type"] = os_type

                elif sname == "ssh_login":
                    result = step_ssh_login(client)
                    if result["status"] == "FAIL":
                        t["step_results"].append(result)
                        t["steps_done"] = i + 1
                        t["status"] = "Failed"
                        log(f"  STOP: {result['note']}")
                        audit("STEP_FAIL", tid, f"Login failed: {result['note']}", "ERROR")
                        break

                elif sname == "service_check":
                    result = step_service_check(client)
                    t["step5_services"] = result.get("services", [])
                    restarted = [s["service"] for s in result.get("services",[]) if s.get("action")=="restarted"]
                    if restarted:
                        audit("SERVICE_RESTART", tid, f"Restarted: {', '.join(restarted)}", "WARN")

                elif sname == "disk_check":
                    result = step_disk_check(client)
                    t["disk_results"] = result.get("disks", [])
                    if result["status"] == "RED":
                        audit("DISK_LOW", tid, result["note"], "WARN")

                elif sname == "retrigger":
                    svc_fail = any(r["step"]=="service_check" and r["status"]=="FAIL"
                                   for r in t["step_results"])
                    if svc_fail:
                        result = {"step":"retrigger","status":"SKIP","note":"Skipped — service check failed"}
                    else:
                        result = step_retrigger(nw_server, client)
                        audit("RETRIGGER", tid, result.get("note",""), "INFO" if result["status"]=="PASS" else "WARN")

                elif sname == "rdp_workorder":
                    log("  AI: Generating RDP work order...")
                    workorder = ai_rdp_workorder(t)
                    t["rdp_workorder"] = workorder
                    result = {"step":"rdp_workorder","status":"MANUAL","note":"Windows — manual RDP investigation required"}
                    audit("RDP_WORKORDER", tid, "AI-generated RDP work order created")

                else:
                    result = {"step":sname,"status":"SKIP","note":f"Unknown step: {sname}"}

            except Exception as e:
                result = {"step":sname,"status":"ERROR","note":f"Unexpected error: {e}"}
                audit("STEP_ERROR", tid, str(e), "ERROR")

            if result:
                icon = {"PASS":"✓","FAIL":"✗","RED":"🔴","SKIP":"—","MANUAL":"📋","WARN":"⚠","ERROR":"✗","DRY_RUN":"~"}.get(result["status"],"•")
                log(f"  {icon} {result['note']}")
                t["step_results"].append(result)
                t["steps_done"] = i + 1

        # Final status
        if t["status"] not in ("Unreachable","Failed"):
            has_fail    = any(r["status"] in ("FAIL","ERROR") for r in t["step_results"])
            has_red     = any(r["step"]=="disk_check" and r["status"]=="RED" for r in t["step_results"])
            retrig_pass = any(r["step"]=="retrigger" and r["status"]=="PASS" for r in t["step_results"])
            is_windows  = os_type == "Windows"
            if is_windows:              t["status"] = "Manual Required"
            elif has_fail:              t["status"] = "Failed"
            elif has_red and retrig_pass: t["status"] = "Partial"
            elif retrig_pass:           t["status"] = "Remediated"
            else:                       t["status"] = "Partial"

        # Root cause
        svc_r = next((r for r in t["step_results"] if r["step"]=="service_check"), None)
        if svc_r:
            restarted = [s["service"] for s in svc_r.get("services",[]) if s.get("action")=="restarted"]
            if restarted:
                t["root_cause"] = f"Service stopped: {', '.join(restarted)}"
        disk_r = next((r for r in t["step_results"] if r["step"]=="disk_check"), None)
        if disk_r and disk_r["status"]=="RED" and not t.get("root_cause"):
            t["root_cause"] = "Insufficient disk space"
        if not t.get("root_cause"):
            t["root_cause"] = "Unknown — see close notes"

        # AI close notes
        log("AI: Writing close notes...")
        t["close_notes"] = ai_close_notes(t, t["step_results"])

        t["current_step"] = None
        t["updated"]      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        t["completed_at"] = datetime.now().isoformat()
        audit("PIPELINE_COMPLETE", tid, f"Status: {t['status']} | Root cause: {t.get('root_cause')}")
        log(f"Pipeline complete — {t['status']}")
        save_tickets()

    except Exception as e:
        log(f"PIPELINE ERROR: {e}")
        t["status"] = "Failed"
        t["error"]  = str(e)
        audit("PIPELINE_ERROR", tid, str(e), "ERROR")
        save_tickets()
    finally:
        _running[tid] = False


# ─── Flask routes ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/tickets", methods=["GET"])
def get_tickets():
    return jsonify(list(_tickets.values()))


@app.route("/api/tickets", methods=["POST"])
def add_ticket():
    data = request.json or {}
    tid  = data.get("ticket_id","").strip()
    if not tid:              return jsonify({"error":"ticket_id required"}), 400
    if tid in _tickets:      return jsonify({"error":f"{tid} already exists"}), 409
    if not data.get("client"):   return jsonify({"error":"client required"}), 400
    if not data.get("nw_server"): return jsonify({"error":"nw_server required"}), 400
    t = {
        "ticket_id":     tid,
        "nw_server":     data.get("nw_server",""),
        "client":        data.get("client",""),
        "os_type":       data.get("os_type","Unknown"),
        "raw_text":      data.get("raw_text",""),
        "error_summary": data.get("error_summary",""),
        "error_code":    data.get("error_code",""),
        "priority":      data.get("priority","P3"),
        "confidence":    data.get("confidence",""),
        "ai_parsed":     data.get("ai_parsed", False),
        "status":        "New",
        "steps_done":    0,
        "step_results":  [],
        "created":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "updated":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    _tickets[tid] = t
    _logs[tid]    = []
    save_tickets()
    audit("TICKET_ADDED", tid, f"Client: {t['client']} | Server: {t['nw_server']}")
    if cfg().get("auto_run_new"):
        threading.Thread(target=run_pipeline, args=(tid,), daemon=True).start()
    return jsonify(t), 201


@app.route("/api/tickets/ai-parse", methods=["POST"])
def api_ai_parse():
    data = request.json or {}
    raw  = data.get("raw_text","")
    sf   = data.get("structured_fields",{})
    if not raw and not sf:
        return jsonify({"error":"Provide raw_text or structured_fields"}), 400
    return jsonify(ai_parse_ticket(raw, sf))


@app.route("/api/tickets/import-csv", methods=["POST"])
def import_csv():
    if "file" not in request.files:
        return jsonify({"error":"No file uploaded"}), 400
    f       = request.files["file"]
    content = f.read().decode("utf-8-sig", errors="replace")
    reader  = csv.DictReader(io.StringIO(content))
    added   = 0
    for row in reader:
        sf  = {k.lower().strip(): v.strip() for k,v in row.items() if v.strip()}
        tid = (sf.get("number") or sf.get("ticket id") or sf.get("ticket_id") or sf.get("inc","")).strip()
        if not tid or tid in _tickets: continue
        raw = "\n".join(f"{k}: {v}" for k,v in sf.items())
        parsed = ai_parse_ticket(raw, sf)
        parsed.setdefault("ticket_id", tid)
        parsed["ticket_id"] = parsed.get("ticket_id") or tid
        parsed["raw_text"]  = raw
        parsed.update({"status":"New","steps_done":0,"step_results":[],
                        "created":datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "updated":datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
        real_tid = parsed["ticket_id"]
        _tickets[real_tid] = parsed
        _logs[real_tid] = []
        audit("TICKET_IMPORTED", real_tid, f"Client: {parsed.get('client')} | Confidence: {parsed.get('confidence')}")
        added += 1
    save_tickets()
    return jsonify({"imported":added})


@app.route("/api/tickets/<tid>", methods=["DELETE"])
def delete_ticket(tid):
    _tickets.pop(tid, None)
    _logs.pop(tid, None)
    _running.pop(tid, None)
    save_tickets()
    audit("TICKET_DELETED", tid, "Ticket deleted")
    return jsonify({"deleted":tid})


@app.route("/api/tickets/<tid>/run", methods=["POST"])
def run_ticket(tid):
    if tid not in _tickets:   return jsonify({"error":"Not found"}), 404
    if _running.get(tid):     return jsonify({"error":"Already running"}), 409
    if not cfg().get("linux_username"):
        return jsonify({"error":"Service account not configured — go to Settings"}), 400
    threading.Thread(target=run_pipeline, args=(tid,), daemon=True).start()
    audit("PIPELINE_TRIGGERED", tid, "Manual trigger")
    return jsonify({"started":tid})


@app.route("/api/run-all", methods=["POST"])
def run_all():
    new_t = [t for t in _tickets.values() if t["status"] == "New"]
    started = []
    for t in new_t:
        if not _running.get(t["ticket_id"]):
            threading.Thread(target=run_pipeline, args=(t["ticket_id"],), daemon=True).start()
            started.append(t["ticket_id"])
    return jsonify({"started":started})


@app.route("/api/tickets/<tid>/logs", methods=["GET"])
def get_logs(tid):
    return jsonify(_logs.get(tid, []))


@app.route("/api/tickets/<tid>/close-notes", methods=["GET"])
def get_close_notes(tid):
    t = _tickets.get(tid)
    if not t: return jsonify({"error":"Not found"}), 404
    return jsonify({"close_notes": t.get("close_notes","Not yet generated.")})


@app.route("/api/tickets/<tid>/workorder", methods=["GET"])
def get_workorder(tid):
    t = _tickets.get(tid)
    if not t: return jsonify({"error":"Not found"}), 404
    return jsonify({"workorder": t.get("rdp_workorder","Not generated yet.")})


@app.route("/api/audit", methods=["GET"])
def get_audit():
    page   = int(request.args.get("page", 1))
    limit  = int(request.args.get("limit", 50))
    tid    = request.args.get("ticket_id","")
    level  = request.args.get("level","")
    items  = list(reversed(_audit))
    if tid:   items = [e for e in items if e.get("ticket_id") == tid]
    if level: items = [e for e in items if e.get("level") == level]
    total  = len(items)
    start  = (page - 1) * limit
    return jsonify({"entries": items[start:start+limit], "total": total, "page": page, "limit": limit})


@app.route("/api/analytics", methods=["GET"])
def analytics():
    all_t = list(_tickets.values())
    statuses, os_types, root_causes, daily = {}, {}, {}, {}
    for t in all_t:
        s = t.get("status","Unknown")
        statuses[s] = statuses.get(s,0) + 1
        o = t.get("os_type","Unknown")
        os_types[o] = os_types.get(o,0) + 1
        rc = t.get("root_cause","Unknown")
        root_causes[rc] = root_causes.get(rc,0) + 1
        day = (t.get("created") or t.get("updated",""))[:10]
        if day: daily[day] = daily.get(day,0) + 1
    total = max(len(all_t), 1)
    remediated = len([t for t in all_t if t.get("status")=="Remediated"])
    return jsonify({
        "total":           len(all_t),
        "statuses":        statuses,
        "os_types":        os_types,
        "root_causes":     root_causes,
        "daily_counts":    dict(sorted(daily.items())[-14:]),
        "resolution_rate": round(remediated / total * 100, 1),
        "audit_count":     len(_audit),
    })


@app.route("/api/analytics/rca", methods=["POST"])
def rca():
    done = [t for t in _tickets.values()
            if t.get("status") in ("Remediated","Partial","Failed","Unreachable")]
    if not done: return jsonify({"error":"No completed tickets to analyse yet."})
    return jsonify(ai_rca(done))


@app.route("/api/config", methods=["GET"])
def get_config():
    c = cfg()
    for k in ("linux_password","linux_key_text","azure_openai_api_key"):
        if c.get(k): c[k] = "__saved__"
    return jsonify(c)


@app.route("/api/config", methods=["POST"])
def set_config():
    data = request.json or {}
    for k in ("linux_password","linux_key_text","azure_openai_api_key"):
        if data.get(k) == "__saved__": data.pop(k)
    save_cfg(data)
    audit("CONFIG_SAVED", "SYSTEM", f"Config updated by user")
    return jsonify({"saved":True})


@app.route("/api/test-ssh", methods=["POST"])
def test_ssh():
    sample = next((t for t in _tickets.values()), None)
    if not sample:
        return jsonify({"ok":True,"message":"Config saved. Add a ticket to test a live SSH connection."})
    client = sample.get("client","")
    ping   = step_ping(client)
    if ping["status"] != "PASS":
        return jsonify({"ok":False,"error":f"Cannot ping {client} — check network/firewall."})
    result = step_ssh_login(client)
    return jsonify({"ok": result["status"]=="PASS", "message": result["note"]})


@app.route("/api/test-ai", methods=["POST"])
def test_ai():
    try:
        resp = ai_call([{"role":"user","content":"Reply with exactly: AI connection OK"}], max_tokens=20)
        return jsonify({"ok":True,"message":resp.strip()})
    except Exception as e:
        return jsonify({"ok":False,"error":str(e)})


@app.route("/api/ping", methods=["GET"])
def ping():
    return jsonify({"ok":True,"version":"1.0","ts":datetime.now().isoformat()})


# ─── Dashboard HTML ───────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetWorker Remediation</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#f2f1ed;--surf:#fff;--surf2:#eceae4;--bdr:rgba(0,0,0,.08);--bdr2:rgba(0,0,0,.15);
--tx:#18180f;--tx2:#52524a;--tx3:#8a8a80;
--bl:#1558b0;--bl2:#e4eef9;--bl3:#0d3d80;
--gn:#155c2f;--gn2:#e4f3eb;--gn3:#0d3d1f;
--rd:#b02015;--rd2:#fce8e6;--rd3:#7a1510;
--am:#8a5000;--am2:#fef3e0;--am3:#5c3500;
--pu:#5c35a0;--pu2:#f0eafa;--pu3:#3d2270;
--r:7px;--rl:11px}
body{font-family:'Helvetica Neue',Arial,sans-serif;background:var(--bg);color:var(--tx);font-size:13px;line-height:1.45}
.app{display:flex;height:100vh;overflow:hidden}
/* Sidebar */
.sb{width:200px;flex-shrink:0;background:var(--surf);border-right:1px solid var(--bdr);display:flex;flex-direction:column;overflow:hidden}
.sb-logo{padding:14px 15px 12px;border-bottom:1px solid var(--bdr)}
.sb-logo h1{font-size:13px;font-weight:700;letter-spacing:-.2px}
.sb-logo p{font-size:10px;color:var(--tx3);margin-top:1px;text-transform:uppercase;letter-spacing:.05em}
.sb-nav{padding:7px;flex:1;overflow-y:auto}
.sb-sec{font-size:10px;font-weight:700;color:var(--tx3);text-transform:uppercase;letter-spacing:.06em;padding:9px 8px 3px}
.nb{display:flex;align-items:center;gap:7px;padding:6px 9px;border-radius:var(--r);cursor:pointer;color:var(--tx2);font-size:12px;margin-bottom:1px;transition:background .1s;user-select:none}
.nb:hover{background:var(--surf2)}.nb.on{background:var(--bl2);color:var(--bl3);font-weight:500}
.ni{width:14px;text-align:center;font-size:12px;flex-shrink:0}
.sb-foot{padding:9px 11px;border-top:1px solid var(--bdr)}
.dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:#ccc;margin-right:4px;vertical-align:middle}
.dot.ok{background:var(--gn)}.dot.err{background:var(--rd)}.dot.wait{background:var(--am)}
/* Main */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.tbar{background:var(--surf);border-bottom:1px solid var(--bdr);padding:0 16px;height:48px;display:flex;align-items:center;justify-content:space-between;gap:10px;flex-shrink:0}
.tbar-title{font-size:14px;font-weight:600}
.tbar-r{display:flex;gap:6px}
.body{flex:1;overflow-y:auto;padding:16px}
/* Buttons */
.btn{display:inline-flex;align-items:center;gap:4px;padding:5px 12px;border-radius:var(--r);border:1px solid var(--bdr2);background:var(--surf);color:var(--tx);font-size:12px;cursor:pointer;transition:background .1s;white-space:nowrap;font-family:inherit;font-weight:400}
.btn:hover{background:var(--surf2)}.btn:disabled{opacity:.4;cursor:not-allowed}
.btn.p{background:var(--bl);color:#fff;border-color:transparent}.btn.p:hover{background:var(--bl3)}
.btn.s{background:var(--gn);color:#fff;border-color:transparent}.btn.s:hover{background:var(--gn3)}
.btn.d{background:var(--rd);color:#fff;border-color:transparent}
.btn.sm{padding:3px 8px;font-size:11px}
/* Stats */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:9px;margin-bottom:16px}
.scard{background:var(--surf);border:1px solid var(--bdr);border-radius:var(--rl);padding:12px 14px}
.slbl{font-size:10px;text-transform:uppercase;letter-spacing:.04em;color:var(--tx3);margin-bottom:4px}
.sval{font-size:24px;font-weight:700;line-height:1}
.s1 .sval{color:var(--am)}.s2 .sval{color:var(--bl)}.s3 .sval{color:var(--gn)}.s4 .sval{color:var(--rd)}
/* Badges */
.bdg{display:inline-flex;align-items:center;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:600;white-space:nowrap}
.bn{background:var(--am2);color:var(--am3)}.br{background:var(--bl2);color:var(--bl3)}
.bg{background:var(--gn2);color:var(--gn3)}.bpa{background:var(--am2);color:var(--am3)}
.bf{background:var(--rd2);color:var(--rd3)}.bm{background:var(--pu2);color:var(--pu3)}
.bwin{background:var(--bl2);color:var(--bl3)}.blnx{background:var(--gn2);color:var(--gn3)}
/* Table */
.tc{background:var(--surf);border:1px solid var(--bdr);border-radius:var(--rl);overflow:hidden;margin-bottom:14px}
.ttb{display:flex;align-items:center;gap:7px;padding:10px 13px;border-bottom:1px solid var(--bdr);flex-wrap:wrap}
table{width:100%;border-collapse:collapse}
th{padding:7px 11px;text-align:left;font-size:10px;font-weight:700;color:var(--tx3);text-transform:uppercase;letter-spacing:.04em;background:var(--surf2);border-bottom:1px solid var(--bdr)}
td{padding:8px 11px;border-bottom:1px solid var(--bdr);vertical-align:middle}
tr:last-child td{border-bottom:none}
tr.cl{cursor:pointer}tr.cl:hover td{background:#fafaf7}tr.sel td{background:var(--bl2)!important}
/* Progress bar */
.pb{display:flex;align-items:center;gap:6px}
.pbt{flex:1;height:4px;background:var(--surf2);border-radius:2px;overflow:hidden;min-width:44px}
.pbf{height:100%;border-radius:2px;transition:width .4s}
/* Card */
.card{background:var(--surf);border:1px solid var(--bdr);border-radius:var(--rl);overflow:hidden;margin-bottom:12px}
.ch{padding:10px 13px;border-bottom:1px solid var(--bdr);display:flex;align-items:center;justify-content:space-between}
.ct{font-size:13px;font-weight:600}
.cb{padding:13px}
/* Steps */
.steps{display:flex;flex-direction:column;gap:4px}
.sr{display:flex;align-items:flex-start;gap:8px;padding:8px 10px;border-radius:var(--r);border:1px solid var(--bdr)}
.sr.done{border-color:#aad4b8;background:#f3faf5}.sr.active{border-color:#9fc4e8;background:#edf4fc}
.sr.fail{border-color:#e8aba3;background:#fdf4f3}.sr.warn{border-color:#e8d09a;background:#fef9ee}
.sr.manual{border-color:#bca8e0;background:#f7f2fd}.sr.skip{opacity:.38}
.sn{width:20px;height:20px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;flex-shrink:0;margin-top:1px}
.sd{background:var(--gn);color:#fff}.sa{background:var(--bl);color:#fff}
.sf{background:var(--rd);color:#fff}.sw{background:var(--am);color:#fff}
.sm2{background:var(--pu);color:#fff}.sp{background:var(--bdr2);color:var(--tx3)}
.sbody{flex:1;min-width:0}
.stitle{font-size:12px;font-weight:600}.snote{font-size:11px;color:var(--tx2);margin-top:1px}
@keyframes spin{to{transform:rotate(360deg)}}.spin{display:inline-block;animation:spin .7s linear infinite}
/* Log */
.log{background:#161610;color:#c0c0b8;font-family:'Menlo',monospace;font-size:11px;padding:10px;border-radius:var(--r);height:190px;overflow-y:auto;line-height:1.55}
.log .ok{color:#78c890}.log .fail{color:#e89090}.log .warn{color:#e8c870}.log .info{color:#78b0e8}
/* 2-col layout */
.dl{display:grid;grid-template-columns:1fr 300px;gap:12px}
/* Info grid */
.ig{display:grid;grid-template-columns:1fr 1fr;gap:7px;margin-bottom:12px}
.ic{background:var(--surf2);border-radius:var(--r);padding:8px 10px}
.ik{font-size:10px;text-transform:uppercase;letter-spacing:.04em;color:var(--tx3)}
.iv{font-size:12px;font-weight:600;margin-top:1px;word-break:break-all}
/* Textarea/forms */
.fg{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.ff{display:flex;flex-direction:column;gap:3px}
.ff label{font-size:10px;font-weight:700;color:var(--tx3);text-transform:uppercase;letter-spacing:.04em}
.ff input,.ff select,.ff textarea{padding:6px 8px;border:1px solid var(--bdr2);border-radius:var(--r);font-size:12px;background:var(--surf);color:var(--tx);outline:none;transition:border-color .1s;font-family:inherit}
.ff input:focus,.ff select:focus,.ff textarea:focus{border-color:var(--bl)}
.ff.full{grid-column:1/-1}
/* Dropzone */
.dz{border:2px dashed var(--bdr2);border-radius:var(--rl);padding:26px;text-align:center;cursor:pointer;transition:background .1s,border-color .1s}
.dz:hover,.dz.drag{background:var(--bl2);border-color:var(--bl)}
/* Toasts */
.toasts{position:fixed;bottom:16px;right:16px;display:flex;flex-direction:column;gap:6px;z-index:9999;pointer-events:none}
.toast{background:var(--tx);color:#fff;padding:8px 13px;border-radius:var(--r);font-size:12px;max-width:290px;opacity:0;transform:translateY(5px);transition:opacity .18s,transform .18s;pointer-events:all}
.toast.show{opacity:1;transform:none}.toast.ok{background:var(--gn)}.toast.err{background:var(--rd)}.toast.warn{background:var(--am)}
/* Audit */
.arow{display:flex;gap:10px;padding:7px 11px;border-bottom:1px solid var(--bdr);font-size:11px;align-items:flex-start}
.arow:last-child{border-bottom:none}
.ats{color:var(--tx3);min-width:130px;flex-shrink:0;font-family:monospace;font-size:10px}
.alv{min-width:46px;flex-shrink:0;font-weight:600;font-size:10px}
.lINFO{color:var(--bl3)}.lWARN{color:var(--am3)}.lERROR{color:var(--rd3)}
.atid{color:var(--pu3);min-width:90px;flex-shrink:0;font-size:10px;font-family:monospace}
.aact{font-weight:500;min-width:130px;flex-shrink:0;font-size:11px}
.adet{color:var(--tx2)}
/* Close notes & workorder */
.cb-pre{background:var(--surf2);border:1px solid var(--bdr);border-radius:var(--r);padding:11px;font-size:12px;line-height:1.75;white-space:pre-wrap;max-height:320px;overflow-y:auto;color:var(--tx)}
.wo-pre{background:#161610;color:#c8c8b8;font-family:'Menlo',monospace;font-size:11px;padding:11px;border-radius:var(--r);line-height:1.75;white-space:pre-wrap;max-height:340px;overflow-y:auto}
/* Parse preview */
.pp{background:var(--surf2);border:1px solid var(--bdr);border-radius:var(--r);padding:11px;font-size:12px;margin-top:9px;display:none}
.pf{display:flex;gap:8px;margin-bottom:3px}
.pk{color:var(--tx3);min-width:115px;flex-shrink:0;font-size:11px}.pv{font-weight:500}
.ch2{color:var(--gn3)}.cm{color:var(--am3)}.cl2{color:var(--rd3)}
/* Chart bars */
.br2{display:flex;align-items:center;gap:7px;margin-bottom:5px;font-size:11px}
.bl2{width:120px;flex-shrink:0;color:var(--tx2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.btr{flex:1;height:11px;background:var(--surf2);border-radius:5px;overflow:hidden}
.bfl{height:100%;border-radius:5px;transition:width .4s}
.bct{min-width:22px;text-align:right;color:var(--tx3);font-weight:500}
/* Pages */
.pg{display:none}.pg.on{display:block}
/* Info banners */
.info-box{border-radius:var(--r);padding:9px 12px;font-size:12px;line-height:1.6;margin-bottom:10px}
.info-warn{background:var(--am2);color:var(--am3)}.info-blue{background:var(--bl2);color:var(--bl3)}
input[type=file]{display:none}
.sec{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--tx3);margin-bottom:7px}
.divider{border:none;border-top:1px solid var(--bdr);margin:12px 0}
code{background:rgba(0,0,0,.06);padding:1px 5px;border-radius:3px;font-family:monospace;font-size:11px}
</style></head><body>
<div class="app">
<aside class="sb">
  <div class="sb-logo"><h1>&#x1F6E1; NetWorker</h1><p>Backup Remediation</p></div>
  <nav class="sb-nav">
    <div class="sb-sec">Monitor</div>
    <div class="nb on" id="nb-dash"     onclick="go('dash')">    <span class="ni">&#9632;</span>Dashboard</div>
    <div class="nb"    id="nb-tickets"  onclick="go('tickets')"> <span class="ni">&#9776;</span>All Tickets</div>
    <div class="nb"    id="nb-audit"    onclick="go('audit');loadAudit()"><span class="ni">&#128196;</span>Audit Log</div>
    <div class="nb"    id="nb-analytics"onclick="go('analytics');loadAnalytics()"><span class="ni">&#128200;</span>Analytics</div>
    <div class="sb-sec">Manage</div>
    <div class="nb"    id="nb-import"   onclick="go('import')">  <span class="ni">&#8679;</span>Import CSV</div>
    <div class="nb"    id="nb-add"      onclick="go('add')">     <span class="ni">&#43;</span>Add Ticket</div>
    <div class="nb"    id="nb-settings" onclick="go('settings');loadCfg()"><span class="ni">&#9881;</span>Settings</div>
  </nav>
  <div class="sb-foot">
    <div style="font-size:11px"><span class="dot wait" id="apidot"></span><span id="apilbl">Connecting...</span></div>
    <div style="font-size:10px;color:var(--tx3);margin-top:2px" id="api-ts"></div>
  </div>
</aside>

<div class="main">
<div class="tbar">
  <div class="tbar-title" id="pg-title">Dashboard</div>
  <div class="tbar-r">
    <button class="btn" onclick="refresh()">&#8635; Refresh</button>
    <button class="btn s" onclick="runAll()">&#9654; Run All New</button>
    <button class="btn p" onclick="go('import')">&#43; Import</button>
  </div>
</div>

<div class="body">

<!-- DASHBOARD -->
<div class="pg on" id="pg-dash">
  <div class="stats">
    <div class="scard s1"><div class="slbl">New / Pending</div><div class="sval" id="s1">—</div></div>
    <div class="scard s2"><div class="slbl">Running</div><div class="sval" id="s2">—</div></div>
    <div class="scard s3"><div class="slbl">Remediated</div><div class="sval" id="s3">—</div></div>
    <div class="scard s4"><div class="slbl">Failed / Unreachable</div><div class="sval" id="s4">—</div></div>
  </div>
  <div class="tc">
    <div class="ttb"><b>Recent Tickets</b><span style="flex:1"></span><button class="btn sm" onclick="go('tickets')">All &rarr;</button></div>
    <table><thead><tr><th>Ticket</th><th>Client</th><th>OS</th><th>Status</th><th>Progress</th><th>Updated</th><th></th></tr></thead>
    <tbody id="dt"></tbody></table>
  </div>
</div>

<!-- ALL TICKETS -->
<div class="pg" id="pg-tickets">
  <div class="tc" style="margin-bottom:12px">
    <div class="ttb">
      <input type="text" id="srch" placeholder="Search..." oninput="renderT()" style="padding:5px 8px;border:1px solid var(--bdr2);border-radius:var(--r);font-size:12px;width:170px;outline:none">
      <select id="fs" onchange="renderT()" style="padding:5px 8px;border:1px solid var(--bdr2);border-radius:var(--r);font-size:12px;outline:none">
        <option value="">All Status</option><option>New</option><option>Running</option><option>Remediated</option><option>Partial</option><option>Failed</option><option>Unreachable</option><option>Manual Required</option>
      </select>
      <select id="fos" onchange="renderT()" style="padding:5px 8px;border:1px solid var(--bdr2);border-radius:var(--r);font-size:12px;outline:none">
        <option value="">All OS</option><option>Linux</option><option>Windows</option>
      </select>
      <span style="flex:1"></span>
      <button class="btn sm s" onclick="runAll()">&#9654; Run All New</button>
    </div>
    <table><thead><tr><th>Ticket</th><th>Server</th><th>Client</th><th>OS</th><th>Status</th><th>Steps</th><th>Updated</th><th>Actions</th></tr></thead>
    <tbody id="tt"></tbody></table>
  </div>
  <div id="det" style="display:none">
    <div class="dl">
      <div>
        <div class="card">
          <div class="ch">
            <span class="ct" id="d-title">—</span>
            <div style="display:flex;gap:5px;align-items:center">
              <span id="d-ai-b" style="display:none;background:var(--pu2);color:var(--pu3);font-size:10px;font-weight:600;padding:2px 6px;border-radius:4px">&#129504; AI</span>
              <button class="btn sm p" id="d-run" onclick="runSel()">&#9654; Run</button>
              <button class="btn sm" onclick="closeDet()">&#x2715;</button>
            </div>
          </div>
          <div class="cb">
            <div class="ig">
              <div class="ic"><div class="ik">Server</div><div class="iv" id="d-sv">—</div></div>
              <div class="ic"><div class="ik">Client</div><div class="iv" id="d-cl">—</div></div>
              <div class="ic"><div class="ik">OS</div><div class="iv" id="d-os">—</div></div>
              <div class="ic"><div class="ik">Status</div><div class="iv" id="d-st">—</div></div>
            </div>
            <div id="d-rat" style="display:none;background:var(--pu2);color:var(--pu3);border-radius:var(--r);padding:8px 11px;font-size:11px;margin-bottom:11px;line-height:1.55"></div>
            <div class="sec">Steps</div>
            <div class="steps" id="d-steps"></div>
          </div>
        </div>
        <div class="card" id="d-cn-card" style="display:none">
          <div class="ch"><span class="ct">&#129504; AI Close Notes</span><button class="btn sm" onclick="dlNotes()">&#8681; Export</button></div>
          <div class="cb"><pre class="cb-pre" id="d-cn"></pre></div>
        </div>
        <div class="card" id="d-wo-card" style="display:none">
          <div class="ch"><span class="ct">&#128187; RDP Work Order</span><button class="btn sm" onclick="dlWo()">&#8681; Export</button></div>
          <div class="cb"><pre class="wo-pre" id="d-wo"></pre></div>
        </div>
        <div class="card" id="d-err-card" style="display:none">
          <div class="ch"><span class="ct">Original Error</span></div>
          <div class="cb"><p style="font-size:12px;color:var(--tx2);line-height:1.65" id="d-err"></p></div>
        </div>
      </div>
      <div>
        <div class="card">
          <div class="ch"><span class="ct">Live Log</span><button class="btn sm" onclick="document.getElementById('log').innerHTML=''">Clear</button></div>
          <div class="cb" style="padding:8px"><div class="log" id="log"></div></div>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- AUDIT LOG -->
<div class="pg" id="pg-audit">
  <div class="tc">
    <div class="ttb">
      <b>Audit Log</b>
      <select id="alf" onchange="loadAudit()" style="padding:5px 8px;border:1px solid var(--bdr2);border-radius:var(--r);font-size:12px;outline:none">
        <option value="">All Levels</option><option>INFO</option><option>WARN</option><option>ERROR</option>
      </select>
      <input type="text" id="atf" placeholder="Filter by ticket..." oninput="loadAudit()" style="padding:5px 8px;border:1px solid var(--bdr2);border-radius:var(--r);font-size:12px;width:150px;outline:none">
      <span style="flex:1"></span>
      <span id="audit-count" style="font-size:11px;color:var(--tx3)"></span>
      <button class="btn sm" onclick="exportAudit()">&#8681; Export CSV</button>
    </div>
    <div id="audit-rows" style="max-height:calc(100vh - 220px);overflow-y:auto"></div>
  </div>
</div>

<!-- ANALYTICS -->
<div class="pg" id="pg-analytics">
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px">
    <div class="card"><div class="ch"><span class="ct">Status distribution</span></div><div class="cb" id="c-st"></div></div>
    <div class="card"><div class="ch"><span class="ct">Root causes</span></div><div class="cb" id="c-rc"></div></div>
    <div class="card"><div class="ch"><span class="ct">Daily volume (14 days)</span></div><div class="cb" id="c-day"></div></div>
    <div class="card"><div class="ch"><span class="ct">OS distribution</span></div><div class="cb" id="c-os"></div></div>
  </div>
  <div class="card">
    <div class="ch"><span class="ct">&#129504; AI Root Cause Analysis</span><button class="btn p" onclick="runRCA()">&#9654; Run Analysis</button></div>
    <div class="cb" id="rca-body"><div style="text-align:center;padding:22px;color:var(--tx3)">Click "Run Analysis" to identify patterns across completed tickets.</div></div>
  </div>
</div>

<!-- IMPORT -->
<div class="pg" id="pg-import">
  <div style="max-width:540px">
    <div class="card">
      <div class="ch"><span class="ct">Import ServiceNow CSV</span><span style="background:var(--pu2);color:var(--pu3);font-size:10px;font-weight:600;padding:2px 6px;border-radius:4px">&#129504; AI Parsed</span></div>
      <div class="cb">
        <p style="font-size:12px;color:var(--tx2);margin-bottom:12px;line-height:1.65">Drop your ServiceNow CSV export. GPT-4o will parse every row — extracting server, client, error, and OS from the free-text description automatically.</p>
        <div class="dz" id="dz" onclick="document.getElementById('cf').click()" ondragover="event.preventDefault();this.classList.add('drag')" ondragleave="this.classList.remove('drag')" ondrop="doDrop(event)">
          <div style="font-size:28px;color:var(--tx3)">&#128193;</div>
          <div style="font-size:13px;font-weight:600;margin-top:7px">Drop CSV or click to browse</div>
          <div style="font-size:11px;color:var(--tx3);margin-top:3px">Any ServiceNow column layout — AI handles it</div>
        </div>
        <input type="file" id="cf" accept=".csv" onchange="doImport(this.files[0])">
        <div id="imp-res" style="margin-top:9px;font-size:12px;display:none"></div>
      </div>
    </div>
  </div>
</div>

<!-- ADD TICKET -->
<div class="pg" id="pg-add">
  <div style="max-width:600px">
    <div class="card">
      <div class="ch"><span class="ct">&#129504; AI Ticket Parser</span></div>
      <div class="cb">
        <p style="font-size:12px;color:var(--tx2);margin-bottom:11px;line-height:1.65">Paste ticket text below — GPT-4o extracts server, client, error, and OS automatically.</p>
        <div class="ff full" style="margin-bottom:9px">
          <label>Paste ticket text</label>
          <textarea id="ai-raw" rows="7" placeholder="Paste your ServiceNow ticket description here...&#10;&#10;Example:&#10;INC0098721 - Backup failed for client app-srv-42.corp.com on nw-prod-01.&#10;nsrexecd not running. Last backup was 3 days ago."></textarea>
        </div>
        <button class="btn p" onclick="aiParse()">&#129504; Parse with AI</button>
        <div id="pp" class="pp"></div>
        <div id="pa" style="margin-top:10px;display:none">
          <button class="btn s" onclick="addParsed()">&#43; Add Ticket</button>
          <button class="btn" style="margin-left:7px" onclick="clrParse()">Clear</button>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="ch"><span class="ct">Add manually</span></div>
      <div class="cb">
        <div class="fg">
          <div class="ff"><label>Ticket ID</label><input id="m-id" placeholder="INC0098721"></div>
          <div class="ff"><label>OS</label><select id="m-os"><option>Linux</option><option>Windows</option><option>Unknown</option></select></div>
          <div class="ff"><label>NetWorker Server</label><input id="m-sv" placeholder="nw-prod-01.corp.com"></div>
          <div class="ff"><label>Client Hostname</label><input id="m-cl" placeholder="app-srv-42.corp.com"></div>
          <div class="ff full"><label>Error description (optional)</label><input id="m-er" placeholder="nsrexecd not running, backup failed at 2am..."></div>
        </div>
        <div style="margin-top:9px"><button class="btn p" onclick="addManual()">&#43; Add Ticket</button></div>
      </div>
    </div>
  </div>
</div>

<!-- SETTINGS -->
<div class="pg" id="pg-settings">
  <div style="max-width:600px">

    <div class="card">
      <div class="ch"><span class="ct">&#129504; Azure OpenAI</span></div>
      <div class="cb">
        <div class="fg">
          <div class="ff full"><label>Endpoint</label><input id="c-ep" placeholder="https://YOUR-RESOURCE.openai.azure.com/"></div>
          <div class="ff full"><label>API Key</label><input id="c-key" type="password" placeholder="Your Azure OpenAI API key"></div>
          <div class="ff"><label>Deployment Name</label><input id="c-dep" placeholder="gpt-4o"></div>
          <div class="ff"><label>API Version</label><input id="c-ver" placeholder="2024-02-01"></div>
        </div>
        <div style="margin-top:9px;display:flex;gap:7px;align-items:center">
          <button class="btn sm" onclick="testAI()">&#9654; Test AI</button>
          <span id="ai-res" style="font-size:12px;display:none"></span>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="ch"><span class="ct">Linux SSH — Service Account</span></div>
      <div class="cb">
        <div class="fg">
          <div class="ff"><label>Username</label><input id="c-usr" placeholder="svc_backup"></div>
          <div class="ff"><label>Auth Method</label>
            <select id="c-auth" onchange="toggleSSH()">
              <option value="password">Password</option>
              <option value="key_file">SSH Key File</option>
              <option value="key_text">SSH Key Paste</option>
              <option value="agent">SSH Agent (ssh-add)</option>
              <option value="pam">PAM</option>
              <option value="ldap">LDAP</option>
              <option value="radius">RADIUS</option>
              <option value="tacacs">TACACS+</option>
            </select>
          </div>
          <div class="ff full" id="f-pass"><label>Password</label><input id="c-pass" type="password" placeholder="Service account password"></div>
          <div class="ff full" id="f-kpath" style="display:none"><label>Key File Path</label><input id="c-kpath" placeholder="/home/svc_backup/.ssh/id_rsa"></div>
          <div class="ff full" id="f-ktext" style="display:none"><label>SSH Private Key (paste)</label><textarea id="c-ktext" rows="4" style="font-family:monospace;font-size:11px;resize:vertical" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;..."></textarea></div>
          <div class="ff full" id="f-agent" style="display:none"><div class="info-box info-blue">Run <code>ssh-add ~/.ssh/id_rsa</code> on this server before starting the app.</div></div>
        </div>
        <div style="margin-top:9px;display:flex;gap:7px;align-items:center">
          <button class="btn sm" onclick="testSSH()">&#9654; Test SSH</button>
          <span id="ssh-res" style="font-size:12px;display:none"></span>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="ch"><span class="ct">Windows (RDP only)</span></div>
      <div class="cb">
        <div class="info-box info-warn">Windows clients use RDP with your PAM account only — no SSH. The AI generates a step-by-step RDP work order for each Windows ticket.</div>
        <div class="fg">
          <div class="ff"><label>AD Domain</label><input id="c-dom" placeholder="CORP"></div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="ch"><span class="ct">NetWorker &amp; Automation</span></div>
      <div class="cb">
        <div class="fg">
          <div class="ff full"><label>Retrigger Command <span style="font-size:9px;text-transform:none;letter-spacing:0;color:var(--tx3)">use {nw_server} and {client} as placeholders</span></label><input id="c-cmd" placeholder="nsrinfo -s {nw_server} -c {client} -v"></div>
          <div class="ff"><label>Linux Services <span style="font-size:9px;text-transform:none;letter-spacing:0;color:var(--tx3)">one per line</span></label><textarea id="c-svc" rows="3" placeholder="nsrexecd&#10;nsrd"></textarea></div>
          <div class="ff"><label>Min Free Disk (GB)</label><input id="c-disk" type="number" value="10" min="1"></div>
          <div class="ff full" style="flex-direction:row;align-items:center;gap:8px">
            <input type="checkbox" id="c-auto" style="width:15px;height:15px">
            <label for="c-auto" style="font-size:12px;text-transform:none;letter-spacing:0;color:var(--tx);font-weight:400">Auto-run pipeline on import</label>
          </div>
          <div class="ff full" style="flex-direction:row;align-items:center;gap:8px">
            <input type="checkbox" id="c-dry" style="width:15px;height:15px">
            <label for="c-dry" style="font-size:12px;text-transform:none;letter-spacing:0;color:var(--tx);font-weight:400">Dry run (skip actual backup retrigger)</label>
          </div>
        </div>
      </div>
    </div>

    <div style="display:flex;gap:8px;align-items:center">
      <button class="btn p" onclick="saveCfg()">&#10003; Save Settings</button>
      <span id="cfg-ok" style="font-size:12px;color:var(--gn);display:none">&#10003; Saved</span>
    </div>
  </div>
</div>

</div></div></div>
<div class="toasts" id="toasts"></div>

<script>
let tickets=[], selId=null, logPoll=null, tPoll=null, parsedT=null, auditData=[];

// ── API ───────────────────────────────────────────────────────────────────────
async function api(path, opts={}) {
  const r = await fetch(path, {
    headers:{'Content-Type':'application/json'},
    ...opts,
    body:opts.body?JSON.stringify(opts.body):undefined
  });
  if(!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg, t='') {
  const w=document.getElementById('toasts'), el=document.createElement('div');
  el.className='toast '+t; el.textContent=msg; w.appendChild(el);
  requestAnimationFrame(()=>el.classList.add('show'));
  setTimeout(()=>{el.classList.remove('show');setTimeout(()=>el.remove(),220)},3000);
}

// ── Navigation ────────────────────────────────────────────────────────────────
const PAGES={dash:'Dashboard',tickets:'All Tickets',audit:'Audit Log',analytics:'Analytics',import:'Import CSV',add:'Add Ticket',settings:'Settings'};
function go(name) {
  Object.keys(PAGES).forEach(p=>{
    document.getElementById('pg-'+p)?.classList.toggle('on', p===name);
    document.getElementById('nb-'+p)?.classList.toggle('on', p===name);
  });
  document.getElementById('pg-title').textContent = PAGES[name]||name;
  if(name==='tickets' && selId) setTimeout(()=>document.getElementById('det')?.scrollIntoView({behavior:'smooth'}), 100);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function bdg(s) {
  const m={New:'bn',Running:'br',Remediated:'bg',Partial:'bpa',Failed:'bf',Unreachable:'bf','Manual Required':'bm'};
  return `<span class="bdg ${m[s]||'bn'}">${s}</span>`;
}
function osBdg(os) {
  if(os==='Windows') return `<span class="bdg bwin">Win</span>`;
  if(os==='Linux')   return `<span class="bdg blnx">Linux</span>`;
  return `<span class="bdg">${os||'?'}</span>`;
}
function pct(t){return Math.round((t.steps_done||0)/Math.max((t.steps_plan||[]).length||7,1)*100)}
function pcol(t){
  if(['Failed','Unreachable'].includes(t.status)) return 'var(--rd)';
  if(t.status==='Remediated') return 'var(--gn)';
  if(t.status==='Partial')    return 'var(--am)';
  if(t.status==='Manual Required') return 'var(--pu)';
  return 'var(--bl)';
}
function dl(txt, name){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([txt],{type:'text/plain'}));a.download=name;a.click()}

// ── Refresh ───────────────────────────────────────────────────────────────────
async function refresh() {
  try {
    tickets = await api('/api/tickets');
    document.getElementById('apidot').className='dot ok';
    document.getElementById('apilbl').textContent='Connected';
    document.getElementById('api-ts').textContent=new Date().toLocaleTimeString();
    renderStats(); renderDash(); renderT();
    if(selId) refreshDet();
  } catch(e) {
    document.getElementById('apidot').className='dot err';
    document.getElementById('apilbl').textContent='Offline';
    document.getElementById('api-ts').textContent='Cannot reach server';
  }
}

function renderStats(){
  const c={};tickets.forEach(t=>{c[t.status]=(c[t.status]||0)+1});
  document.getElementById('s1').textContent=c.New||0;
  document.getElementById('s2').textContent=c.Running||0;
  document.getElementById('s3').textContent=(c.Remediated||0)+(c.Partial||0);
  document.getElementById('s4').textContent=(c.Failed||0)+(c.Unreachable||0)+(c['Manual Required']||0);
}

function trow(t, full) {
  const p=pct(t);
  return `<tr class="cl${selId===t.ticket_id?' sel':''}" onclick="selTick('${t.ticket_id}')">
    <td style="font-weight:600;font-size:12px">${t.ticket_id}</td>
    ${full?`<td style="font-size:11px;color:var(--tx2)">${t.nw_server||'—'}</td>`:''}
    <td style="font-size:11px">${t.client||'—'}</td>
    <td>${osBdg(t.os_type)}</td><td>${bdg(t.status)}</td>
    <td style="min-width:85px"><div class="pb"><div class="pbt"><div class="pbf" style="width:${p}%;background:${pcol(t)}"></div></div><span style="font-size:10px;color:var(--tx3)">${t.steps_done||0}</span></div></td>
    <td style="font-size:10px;color:var(--tx3)">${(t.updated||'').slice(0,16)}</td>
    ${full?`<td>
      <button class="btn sm ${['New','Failed'].includes(t.status)?'p':''}" onclick="event.stopPropagation();${['New','Failed'].includes(t.status)?`runTick('${t.ticket_id}')`:``selTick('${t.ticket_id}')}">${['New','Failed'].includes(t.status)?'&#9654;':'View'}</button>
      <button class="btn sm d" style="margin-left:3px" onclick="event.stopPropagation();delTick('${t.ticket_id}')">&#x2715;</button>
    </td>`:`<td><button class="btn sm" onclick="selTick('${t.ticket_id}');go('tickets')">View</button></td>`}
  </tr>`;
}

function renderDash(){
  const tb=document.getElementById('dt');
  const recent=[...tickets].sort((a,b)=>b.updated>a.updated?1:-1).slice(0,10);
  tb.innerHTML=recent.length?recent.map(t=>trow(t,false)).join(''):`<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--tx3)">No tickets yet</td></tr>`;
}

function renderT(){
  const q=document.getElementById('srch').value.toLowerCase();
  const fs=document.getElementById('fs').value;
  const fo=document.getElementById('fos').value;
  const rows=tickets.filter(t=>{
    if(fs&&t.status!==fs)return false;
    if(fo&&t.os_type!==fo)return false;
    if(q&&!`${t.ticket_id} ${t.nw_server} ${t.client}`.toLowerCase().includes(q))return false;
    return true;
  });
  document.getElementById('tt').innerHTML=rows.length?rows.map(t=>trow(t,true)).join(''):`<tr><td colspan="8" style="text-align:center;padding:18px;color:var(--tx3)">No tickets match</td></tr>`;
}

// ── Detail ─────────────────────────────────────────────────────────────────────
const SML={reachability:'Reachability check',os_detect:'OS identification',ssh_login:'Service account login',service_check:'Service health check',disk_check:'Disk space check',retrigger:'Retrigger backup',rdp_workorder:'RDP work order'};

function selTick(tid){
  selId=tid;
  const t=tickets.find(x=>x.ticket_id===tid);
  if(!t)return;
  go('tickets');
  document.getElementById('det').style.display='block';
  document.getElementById('d-title').textContent=`${t.ticket_id} — ${t.client}`;
  document.getElementById('d-sv').textContent=t.nw_server||'—';
  document.getElementById('d-cl').textContent=t.client||'—';
  document.getElementById('d-os').innerHTML=osBdg(t.os_type);
  document.getElementById('d-st').innerHTML=bdg(t.status);
  document.getElementById('d-run').style.display=['New','Failed'].includes(t.status)?'inline-flex':'none';
  document.getElementById('d-ai-b').style.display=t.ai_plan?.ai_planned?'inline-flex':'none';
  const rat=document.getElementById('d-rat');
  if(t.ai_plan?.rationale){rat.style.display='block';rat.innerHTML=`&#129504; ${esc(t.ai_plan.rationale)}`}else{rat.style.display='none'}
  renderSteps(t); loadLog(tid); loadCN(t); loadWO(t);
  if(t.error_summary){document.getElementById('d-err-card').style.display='block';document.getElementById('d-err').textContent=t.error_summary}else{document.getElementById('d-err-card').style.display='none'}
  if(t.status==='Running')startPoll(tid);
  renderT();
  setTimeout(()=>document.getElementById('det').scrollIntoView({behavior:'smooth',block:'start'}),80);
}

function refreshDet(){
  if(!selId)return;
  const t=tickets.find(x=>x.ticket_id===selId);
  if(!t)return;
  document.getElementById('d-st').innerHTML=bdg(t.status);
  renderSteps(t); loadCN(t); loadWO(t);
  if(t.status!=='Running')stopPoll();
}

function renderSteps(t){
  const el=document.getElementById('d-steps');
  const plan=t.steps_plan||[], res=t.step_results||[];
  const rm={}; res.forEach(r=>rm[r.step]=r);
  const all=[...new Set([...plan,...res.map(r=>r.step)])];
  if(!all.length){el.innerHTML='<div style="color:var(--tx3);font-size:12px;padding:7px">Pipeline not started yet.</div>';return}
  el.innerHTML=all.map((s,i)=>{
    const r=rm[s], isCur=t.current_step===s, isRun=t.status==='Running';
    let rc='',nc='sp',ic=String(i+1),note='Pending';
    if(r){note=r.note||'';
      if(r.status==='PASS'){rc='done';nc='sd';ic='&#10003;'}
      else if(['FAIL','ERROR'].includes(r.status)){rc='fail';nc='sf';ic='&#10007;'}
      else if(r.status==='RED'){rc='warn';nc='sw';ic='&#9679;'}
      else if(r.status==='SKIP'||r.status==='DRY_RUN'){rc='skip'}
      else if(r.status==='MANUAL'){rc='manual';nc='sm2';ic='&#128187;'}
    } else if(isCur&&isRun){rc='active';nc='sa';ic='<span class="spin">&#9696;</span>'}
    return `<div class="sr ${rc}"><div class="sn ${nc}">${ic}</div><div class="sbody"><div class="stitle">${SML[s]||s}</div><div class="snote">${esc(note)}</div></div></div>`;
  }).join('');
}

async function loadLog(tid){
  try{
    const logs=await api(`/api/tickets/${tid}/logs`);
    const box=document.getElementById('log');
    box.innerHTML=logs.map(l=>{
      let c='';
      if(l.includes('✓')||l.includes('PASS')||l.includes('complete'))c='ok';
      else if(l.includes('✗')||l.includes('FAIL')||l.includes('ERROR')||l.includes('STOP'))c='fail';
      else if(l.includes('🔴')||l.includes('RED')||l.includes('restart'))c='warn';
      else if(l.includes('AI:')||l.includes('Step')||l.includes('Pipeline'))c='info';
      return `<div class="${c}">${esc(l)}</div>`;
    }).join('');
    box.scrollTop=box.scrollHeight;
  }catch{}
}

async function loadCN(t){
  const card=document.getElementById('d-cn-card');
  if(!['Remediated','Partial','Failed','Unreachable','Manual Required'].includes(t.status)){card.style.display='none';return}
  try{const r=await api(`/api/tickets/${t.ticket_id}/close-notes`);card.style.display='block';document.getElementById('d-cn').textContent=r.close_notes||''}catch{}
}
async function loadWO(t){
  const card=document.getElementById('d-wo-card');
  if(t.os_type!=='Windows'&&!t.rdp_workorder){card.style.display='none';return}
  try{const r=await api(`/api/tickets/${t.ticket_id}/workorder`);if(r.workorder&&r.workorder!=='Not generated yet.'){card.style.display='block';document.getElementById('d-wo').textContent=r.workorder}else{card.style.display='none'}}catch{}
}

function closeDet(){selId=null;document.getElementById('det').style.display='none';stopPoll();renderT()}
function dlNotes(){dl(document.getElementById('d-cn').textContent,`close_${selId}.txt`)}
function dlWo(){dl(document.getElementById('d-wo').textContent,`rdp_${selId}.txt`)}
function startPoll(tid){stopPoll();logPoll=setInterval(()=>loadLog(tid),1200);tPoll=setInterval(refresh,2200)}
function stopPoll(){clearInterval(logPoll);clearInterval(tPoll);logPoll=null;tPoll=null}

// ── Actions ───────────────────────────────────────────────────────────────────
async function runTick(tid){
  try{const r=await api(`/api/tickets/${tid}/run`,{method:'POST'});
    if(r.error){toast(r.error,'err');return}
    toast(`Started: ${tid}`,'ok');selTick(tid);startPoll(tid);refresh()}
  catch(e){toast('Server error: '+e,'err')}
}
function runSel(){if(selId)runTick(selId)}
async function runAll(){
  const r=await api('/api/run-all',{method:'POST'});
  r.started?.length?toast(`Started ${r.started.length} ticket(s)`,'ok'):toast('No new tickets','warn');
  refresh();
}
async function delTick(tid){
  if(!confirm(`Delete ${tid}?`))return;
  await api(`/api/tickets/${tid}`,{method:'DELETE'});
  if(selId===tid)closeDet();
  toast(`Deleted ${tid}`);refresh();
}

// ── AI Parse ──────────────────────────────────────────────────────────────────
async function aiParse(){
  const raw=document.getElementById('ai-raw').value.trim();
  if(!raw){toast('Paste ticket text first','warn');return}
  const btn=event.target;btn.disabled=true;btn.textContent='Parsing...';
  try{
    const r=await api('/api/tickets/ai-parse',{method:'POST',body:{raw_text:raw}});
    parsedT=r;
    const pr=document.getElementById('pp');pr.style.display='block';
    const cc=r.confidence==='high'?'ch2':r.confidence==='medium'?'cm':'cl2';
    pr.innerHTML=`<div style="display:flex;justify-content:space-between;margin-bottom:7px"><b style="font-size:12px">&#129504; Extracted fields</b><span class="${cc}" style="font-size:11px;font-weight:600">Confidence: ${r.confidence||'?'}</span></div>
    ${pf('Ticket ID',r.ticket_id)}${pf('NW Server',r.nw_server)}${pf('Client',r.client)}${pf('OS',r.os_type)}${pf('Error',r.error_summary)}${pf('Priority',r.priority)}
    ${r.ai_note?`<div style="font-size:10px;color:var(--tx3);margin-top:5px">${r.ai_note}</div>`:''}`;
    document.getElementById('pa').style.display='block';
    r.confidence==='low'?toast('Low confidence — verify fields','warn'):toast('Parsed OK','ok');
  }catch(e){toast('AI parse failed: '+e,'err')}
  btn.disabled=false;btn.innerHTML='&#129504; Parse with AI';
}
function pf(k,v){return v?`<div class="pf"><div class="pk">${k}</div><div class="pv">${esc(v)}</div></div>`:''}
async function addParsed(){
  if(!parsedT)return;
  const r=await api('/api/tickets',{method:'POST',body:{...parsedT,raw_text:document.getElementById('ai-raw').value}});
  if(r.error){toast(r.error,'err');return}
  toast(`Added ${r.ticket_id}`,'ok');clrParse();go('tickets');refresh();
}
function clrParse(){parsedT=null;document.getElementById('ai-raw').value='';document.getElementById('pp').style.display='none';document.getElementById('pa').style.display='none'}

async function addManual(){
  const tid=document.getElementById('m-id').value.trim();
  const sv=document.getElementById('m-sv').value.trim();
  const cl=document.getElementById('m-cl').value.trim();
  if(!tid||!sv||!cl){toast('Ticket ID, Server, Client required','warn');return}
  const r=await api('/api/tickets',{method:'POST',body:{ticket_id:tid,nw_server:sv,client:cl,os_type:document.getElementById('m-os').value,error_summary:document.getElementById('m-er').value.trim()}});
  if(r.error){toast(r.error,'err');return}
  toast(`Added ${tid}`,'ok');['m-id','m-sv','m-cl','m-er'].forEach(i=>document.getElementById(i).value='');
  go('tickets');refresh();
}

// ── CSV Import ────────────────────────────────────────────────────────────────
async function doImport(file){
  if(!file)return;
  const dz=document.getElementById('dz');
  dz.innerHTML='<div style="font-size:22px">&#129504;</div><div style="font-size:13px;font-weight:600;margin-top:6px">AI parsing tickets...</div>';
  try{
    const fd=new FormData();fd.append('file',file);
    const res=await fetch('/api/tickets/import-csv',{method:'POST',body:fd});
    const data=await res.json();
    if(data.error){toast(data.error,'err')}else{
      toast(`Imported ${data.imported} tickets`,'ok');
      document.getElementById('imp-res').style.display='block';
      document.getElementById('imp-res').innerHTML=`<span style="color:var(--gn);font-weight:600">&#10003; ${data.imported} ticket(s) imported and AI-parsed</span>`;
      refresh();setTimeout(()=>go('tickets'),1000);
    }
  }catch(e){toast('Import failed: '+e,'err')}
  dz.innerHTML='<div style="font-size:28px;color:var(--tx3)">&#128193;</div><div style="font-size:13px;font-weight:600;margin-top:7px">Drop CSV or click to browse</div><div style="font-size:11px;color:var(--tx3);margin-top:3px">Any ServiceNow column layout — AI handles it</div>';
}
function doDrop(e){e.preventDefault();document.getElementById('dz').classList.remove('drag');const f=e.dataTransfer.files[0];if(f)doImport(f)}

// ── Audit ─────────────────────────────────────────────────────────────────────
async function loadAudit(){
  try{
    const lv=document.getElementById('alf').value;
    const tf=document.getElementById('atf').value.trim();
    let url=`/api/audit?limit=200${lv?'&level='+lv:''}${tf?'&ticket_id='+tf:''}`;
    const data=await api(url);
    auditData=data.entries||[];
    document.getElementById('audit-count').textContent=`${data.total} entries`;
    const lmap={INFO:'lINFO',WARN:'lWARN',ERROR:'lERROR'};
    document.getElementById('audit-rows').innerHTML=auditData.map(e=>`
      <div class="arow">
        <span class="ats">${e.ts}</span>
        <span class="alv ${lmap[e.level]||''}">${e.level}</span>
        <span class="atid">${e.ticket_id}</span>
        <span class="aact">${esc(e.action)}</span>
        <span class="adet">${esc(e.detail)}</span>
      </div>`).join('') || '<div style="text-align:center;padding:24px;color:var(--tx3)">No audit entries yet</div>';
  }catch(e){document.getElementById('audit-rows').innerHTML=`<div style="color:var(--rd3);padding:12px">Error loading audit: ${e}</div>`}
}

function exportAudit(){
  const rows=[['Timestamp','Level','Ticket ID','Action','Detail']];
  auditData.forEach(e=>rows.push([e.ts,e.level,e.ticket_id,e.action,e.detail]));
  const csv=rows.map(r=>r.map(c=>`"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
  dl(csv,`audit_${new Date().toISOString().slice(0,10)}.csv`);
}

// ── Analytics ─────────────────────────────────────────────────────────────────
async function loadAnalytics(){
  try{
    const d=await api('/api/analytics');
    renderBar('c-st',d.statuses);renderBar('c-rc',d.root_causes);
    renderBar('c-os',d.os_types);renderDayBar('c-day',d.daily_counts);
    document.getElementById('s1').textContent=d.statuses?.New||0;
    document.getElementById('s2').textContent=d.statuses?.Running||0;
    document.getElementById('s3').textContent=(d.statuses?.Remediated||0)+(d.statuses?.Partial||0);
    document.getElementById('s4').textContent=(d.statuses?.Failed||0)+(d.statuses?.Unreachable||0)+(d.statuses?.['Manual Required']||0);
  }catch{}
}
function renderBar(id,obj){
  const el=document.getElementById(id);if(!el)return;
  const e=Object.entries(obj||{}).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const mx=Math.max(...e.map(x=>x[1]),1);
  const cols={Remediated:'var(--gn)',Failed:'var(--rd)',Unreachable:'var(--rd)',New:'var(--am)',Running:'var(--bl)',Partial:'var(--am)'};
  el.innerHTML=e.map(([k,v])=>`<div class="br2"><div class="bl2" title="${k}">${k}</div><div class="btr"><div class="bfl" style="width:${Math.round(v/mx*100)}%;background:${cols[k]||'var(--bl)'}"></div></div><div class="bct">${v}</div></div>`).join('');
}
function renderDayBar(id,obj){
  const el=document.getElementById(id);if(!el)return;
  const e=Object.entries(obj||{});const mx=Math.max(...e.map(x=>x[1]),1);
  el.innerHTML=e.map(([k,v])=>`<div class="br2"><div class="bl2">${k.slice(5)}</div><div class="btr"><div class="bfl" style="width:${Math.round(v/mx*100)}%;background:var(--bl)"></div></div><div class="bct">${v}</div></div>`).join('');
}
async function runRCA(){
  const body=document.getElementById('rca-body');
  body.innerHTML='<div style="text-align:center;padding:22px;color:var(--tx3)">&#129504; Analysing patterns...</div>';
  try{
    const r=await api('/api/analytics/rca',{method:'POST'});
    if(r.error){body.innerHTML=`<div style="color:var(--rd3);padding:11px">${r.error}</div>`;return}
    let h=`<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">`;
    if(r.top_causes?.length){
      h+=`<div><div class="sec">Top causes</div>`;
      r.top_causes.forEach(c=>{h+=`<div style="padding:8px 10px;background:var(--surf2);border-radius:var(--r);margin-bottom:6px;font-size:12px"><div style="font-weight:600">${esc(c.cause)} <span style="color:var(--tx3)">(${c.count}x)</span></div><div style="color:var(--tx2);margin-top:2px">&#128161; ${esc(c.recommendation)}</div></div>`});
      h+=`</div>`;
    }
    if(r.problem_clients?.length){
      h+=`<div><div class="sec">Problem clients</div>`;
      r.problem_clients.forEach(c=>{h+=`<div style="padding:8px 10px;background:var(--rd2);border-radius:var(--r);margin-bottom:6px;font-size:12px"><div style="font-weight:600;color:var(--rd3)">${esc(c.client)}</div><div style="color:var(--tx2);margin-top:1px">${c.failure_count}x — ${esc(c.likely_cause)}</div></div>`});
      h+=`</div>`;
    }
    h+=`</div>`;
    if(r.priority_actions?.length){
      h+=`<div class="divider"></div><div class="sec">Priority actions</div><ol style="padding-left:16px;font-size:12px;color:var(--tx2);line-height:1.85">`;
      r.priority_actions.forEach(a=>{h+=`<li>${esc(a)}</li>`});h+=`</ol>`;
    }
    if(r.predicted_reduction_pct){
      h+=`<div style="margin-top:12px;padding:10px 13px;background:var(--gn2);border-radius:var(--r);font-size:12px;color:var(--gn3)"><strong>Predicted ticket reduction: ${r.predicted_reduction_pct}%</strong> if priority actions are implemented</div>`;
    }
    body.innerHTML=h;
  }catch(e){body.innerHTML=`<div style="color:var(--rd3);padding:11px">RCA failed: ${e}</div>`}
}

// ── Settings ──────────────────────────────────────────────────────────────────
function toggleSSH(){
  const m=document.getElementById('c-auth').value;
  document.getElementById('f-pass').style.display=['password','pam','ldap','radius','tacacs','key_file'].includes(m)?'':'none';
  document.getElementById('f-kpath').style.display=m==='key_file'?'':'none';
  document.getElementById('f-ktext').style.display=m==='key_text'?'':'none';
  document.getElementById('f-agent').style.display=m==='agent'?'':'none';
}
async function loadCfg(){
  try{
    const c=await api('/api/config');
    const sv=(id,k)=>{const el=document.getElementById(id);if(el)el.value=c[k]||''};
    const sc=(id,k)=>{const el=document.getElementById(id);if(el)el.checked=!!c[k]};
    sv('c-ep','azure_openai_endpoint');sv('c-dep','azure_openai_deployment');sv('c-ver','azure_openai_api_version');
    sv('c-usr','linux_username');sv('c-kpath','linux_key_path');sv('c-dom','windows_rdp_domain');
    sv('c-cmd','nw_retrigger_cmd');sv('c-disk','min_disk_gb');
    const am=document.getElementById('c-auth');if(am)am.value=c.linux_auth_method||'password';
    const ls=document.getElementById('c-svc');if(ls)ls.value=(c.linux_services||[]).join('\n');
    sc('c-auto','auto_run_new');sc('c-dry','dry_run');
    if(c.azure_openai_api_key==='__saved__'){const el=document.getElementById('c-key');if(el)el.placeholder='(saved)'}
    if(c.linux_password==='__saved__'){const el=document.getElementById('c-pass');if(el)el.placeholder='(saved)'}
    toggleSSH();
  }catch{}
}
async function saveCfg(){
  const gv=id=>{const el=document.getElementById(id);return el?el.value.trim():''};
  const gc=id=>{const el=document.getElementById(id);return el?el.checked:false};
  const c={
    azure_openai_endpoint:gv('c-ep'),azure_openai_deployment:gv('c-dep'),azure_openai_api_version:gv('c-ver'),
    linux_username:gv('c-usr'),linux_auth_method:gv('c-auth'),linux_key_path:gv('c-kpath'),
    linux_key_text:document.getElementById('c-ktext')?.value?.trim()||'',
    windows_rdp_domain:gv('c-dom'),nw_retrigger_cmd:gv('c-cmd'),
    min_disk_gb:parseFloat(document.getElementById('c-disk')?.value)||10,
    auto_run_new:gc('c-auto'),dry_run:gc('c-dry'),
    linux_services:document.getElementById('c-svc')?.value.split('\n').map(s=>s.trim()).filter(Boolean)||[],
  };
  const k=document.getElementById('c-key')?.value;if(k&&k!=='(saved)')c.azure_openai_api_key=k;
  const p=document.getElementById('c-pass')?.value;if(p&&p!=='(saved)')c.linux_password=p;
  try{
    await api('/api/config',{method:'POST',body:c});
    const el=document.getElementById('cfg-ok');el.style.display='inline';
    setTimeout(()=>el.style.display='none',2500);toast('Settings saved','ok');
  }catch(e){toast('Save failed: '+e,'err')}
}
async function testAI(){
  const el=document.getElementById('ai-res');el.style.display='inline';el.style.color='var(--tx3)';el.textContent='Testing...';
  await saveCfg();
  try{const r=await api('/api/test-ai',{method:'POST'});el.style.color=r.ok?'var(--gn)':'var(--rd)';el.textContent=(r.ok?'✓ ':'✗ ')+(r.message||r.error||'')}
  catch(e){el.style.color='var(--rd)';el.textContent='✗ Server error: '+e}
}
async function testSSH(){
  const el=document.getElementById('ssh-res');el.style.display='inline';el.style.color='var(--tx3)';el.textContent='Testing...';
  await saveCfg();
  try{const r=await api('/api/test-ssh',{method:'POST'});el.style.color=r.ok?'var(--gn)':'var(--rd)';el.textContent=(r.ok?'✓ ':'✗ ')+(r.message||r.error||'')}
  catch(e){el.style.color='var(--rd)';el.textContent='✗ Server error: '+e}
}

// ── Boot ──────────────────────────────────────────────────────────────────────
refresh();
setInterval(refresh, 6000);
</script>
</body></html>"""


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    load_all()
    c    = cfg()
    host = c.get("server_host", "0.0.0.0")
    port = int(c.get("server_port", 5050))

    # Check paramiko
    if not HAS_PARAMIKO:
        print("\n  [WARN] paramiko not installed — SSH steps will be skipped.")
        print("         Install with:  pip install paramiko\n")

    # Try alternate ports if 5050 is blocked
    for try_port in [port, 5051, 5052, 8080, 8888]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("", try_port))
            s.close()
            port = try_port
            break
        except OSError:
            print(f"  [INFO] Port {try_port} in use, trying next...")
            continue

    print("\n" + "="*50)
    print("  NetWorker Backup Remediation System")
    print(f"  http://localhost:{port}")
    print("="*50 + "\n")
    audit("APP_START", "SYSTEM", f"Application started on port {port}")
    app.run(host=host, port=port, debug=False, threaded=True)
