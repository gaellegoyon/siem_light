import sys
import os
import asyncio
# Ajoute le répertoire parent au PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from normalize_ecs import normalize_syslog

def test_normalize_syslog():
    line = '<34>1 2025-05-12T14:00:00Z host app - - Failed password from 1.2.3.4'
    evt = asyncio.run(normalize_syslog(line))
    print(evt)  # Debugging output
    assert evt is not None, "normalize_syslog returned None"
    assert 'host' in evt, "Key 'host' is missing in the result"
    assert evt['host']['hostname'] == 'host', "Hostname does not match"
    assert 'Failed password' in evt['message'], "Message content does not match"