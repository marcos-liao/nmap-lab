import subprocess
import re
import shutil
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__, static_folder=".", static_url_path="")

ALLOWED_FLAGS = {
    "-sS", "-sT", "-sA", "-sF", "-sX", "-sN", "-sW",
    "-sU", "-sV", "-sn", "-sC", "-sI", "-O", "-A",
    "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    "-Pn", "-PS", "-PA", "-PU", "-PE", "-PP", "-PM", "-PR",
    "-p", "-F", "--top-ports", "-f", "-ff",
    "-v", "-vv", "--reason", "--open",
    "--osscan-guess", "--osscan-limit",
    "--version-intensity", "--version-light", "--version-all",
    "--script", "--data-length", "--source-port", "-g",
    "-D", "--mtu", "--spoof-mac",
    "--traceroute", "--max-retries", "--host-timeout",
    "--min-rate", "--max-rate",
    "-oN", "-oX", "-oG",
}

FLAGS_WITH_VALUES = {
    "-p", "--top-ports", "--version-intensity",
    "--script", "--data-length", "--source-port", "-g",
    "-D", "--mtu", "--spoof-mac",
    "--max-retries", "--host-timeout",
    "--min-rate", "--max-rate",
    "-oN", "-oX", "-oG",
    "-PS", "-PA", "-PU", "-sI",
}

TARGET_RE = re.compile(
    r"^[a-zA-Z0-9\.\-\:\/]+$"
)


def validate_target(target: str) -> bool:
    if not target or len(target) > 255:
        return False
    if not TARGET_RE.match(target):
        return False
    dangerous = [";", "&", "|", "`", "$", "(", ")", "{", "}", "<", ">", "!", "\n", "\r"]
    return not any(c in target for c in dangerous)


def validate_flags(flags: list[str]) -> list[str]:
    safe = []
    i = 0
    while i < len(flags):
        flag = flags[i]
        if flag in ALLOWED_FLAGS:
            safe.append(flag)
            if flag in FLAGS_WITH_VALUES and i + 1 < len(flags):
                val = flags[i + 1]
                if re.match(r"^[a-zA-Z0-9\.\,\-\_\:\/\*]+$", val) and len(val) <= 200:
                    safe.append(val)
                    i += 1
        i += 1
    return safe


@app.route("/")
def index():
    return send_from_directory(".", "index.html")


@app.route("/api/scan", methods=["POST"])
def run_scan():
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return jsonify({"error": "Nmap is not installed or not in PATH"}), 500

    data = request.get_json()
    target = data.get("target", "").strip()
    flags = data.get("flags", [])

    if not validate_target(target):
        return jsonify({"error": "Invalid target. Use IP address, hostname, or CIDR notation."}), 400

    safe_flags = validate_flags(flags)
    if not safe_flags:
        return jsonify({"error": "No valid scan flags provided."}), 400

    cmd = [nmap_path] + safe_flags + [target]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        output = result.stdout
        if result.stderr:
            output += "\n" + result.stderr
        return jsonify({
            "command": " ".join(cmd),
            "output": output,
            "exit_code": result.returncode,
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timed out after 120 seconds."}), 408
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/check", methods=["GET"])
def check_nmap():
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return jsonify({"installed": False})
    try:
        result = subprocess.run([nmap_path, "--version"], capture_output=True, text=True, timeout=5)
        version_line = result.stdout.strip().split("\n")[0] if result.stdout else "unknown"
        return jsonify({"installed": True, "version": version_line, "path": nmap_path})
    except Exception:
        return jsonify({"installed": False})


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  NmapLab — Interactive Nmap Learning Platform")
    print(f"  http://127.0.0.1:{port}\n")
    app.run(debug=True, port=port)
