import asyncio
import socket
from scapy.all import AsyncSniffer, TCP, IP

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue):
        self.queue = queue

    def datagram_received(self, data, addr):
        message = data.decode('utf-8', errors='ignore').strip()
        self.queue.put_nowait(('syslog', message))

async def ingest_syslog(queue, host='0.0.0.0', port=514):
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: SyslogUDPProtocol(queue), local_addr=(host, port)
    )
    try:
        await asyncio.Future()
    finally:
        transport.close()

async def ingest_pcap(queue, iface=None):
    def handle(pkt):
        if TCP in pkt and pkt[TCP].dport in (22, 80, 443):
            queue.put_nowait(('pcap', pkt))
    sniffer = AsyncSniffer(iface=iface, prn=handle, store=False)
    sniffer.start()
    try:
        await asyncio.Future()
    finally:
        sniffer.stop()