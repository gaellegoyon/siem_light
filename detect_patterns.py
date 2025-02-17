from collections import defaultdict
from datetime import datetime, timedelta

_attempts = defaultdict(list)
THRESHOLD = 5
WINDOW = timedelta(minutes=1)

async def detect_ssh_bruteforce(event):
    msg = event.get('message','')
    if event.get('process',{}).get('name')=='sshd' and 'Failed password' in msg:
        parts = msg.split()
        ip = parts[-4]  
        ts = datetime.fromisoformat(event['@timestamp'])
        _attempts[ip].append(ts)
        cutoff = ts - WINDOW
        _attempts[ip] = [t for t in _attempts[ip] if t >= cutoff]
        if len(_attempts[ip])>=THRESHOLD:
            return {
                "@timestamp": ts.isoformat(),
                "event": {"dataset": "alert.ssh_bruteforce"},
                "source": {"ip": ip},
                "rule": {"name": "SSH brute force", "threshold": THRESHOLD}
            }
    return None