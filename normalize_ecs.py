import re
import json
from datetime import datetime
from email.utils import parsedate_to_datetime
from scapy.all import IP, TCP

SYSLOG_RE = re.compile(r'''^<\d+>1\s+(?P<ts>[^\s]+)\s+(?P<host>[^\s]+)\s+(?P<app>[^\s]+)\s+-\s+-\s+(?P<msg>.+)$''')
async def normalize_syslog(line):
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    dt = datetime.strptime(m.group('ts'), "%Y-%m-%dT%H:%M:%SZ")
    return {
        "@timestamp": dt.isoformat(),
        "log": {"original": m.group('msg')},
        "host": {"hostname": m.group('host')},
        "process": {"name": m.group('app')},
        "message": m.group('msg'),
        "event": {"dataset": "syslog", "kind": "event"}
    }
async def normalize_pcap(pkt):
    return {
        "@timestamp": datetime.utcfromtimestamp(pkt.time).isoformat(),
        "source": {"ip": pkt[IP].src, "port": pkt[TCP].sport},
        "destination": {"ip": pkt[IP].dst, "port": pkt[TCP].dport},
        "network": {"transport": "tcp", "protocol": "http" if pkt[TCP].dport==80 else "ssh"},
        "event": {"dataset": "pcap", "kind": "event"}
    }

async def to_json(event):
    return json.dumps(event)