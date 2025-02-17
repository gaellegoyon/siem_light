import sys
import os
import asyncio
# Ajoute le répertoire parent au PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detect_patterns import detect_ssh_bruteforce, THRESHOLD

def test_detect_alert():
    base = {
        "@timestamp": "2025-05-12T14:00:00",
        "process": {"name": "sshd"},
        "message": "Failed password for invalid user root from 1.1.1.1 port 22 ssh2"
    }
    alert = None
    for _ in range(THRESHOLD):
        alert = asyncio.run(detect_ssh_bruteforce(base))
    assert alert and alert['rule']['name'] == 'SSH brute force'