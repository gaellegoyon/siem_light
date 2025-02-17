import asyncio
import logging
from ingestion_async import ingest_syslog, ingest_pcap
from normalize_ecs import normalize_syslog, normalize_pcap, to_json
from detect_patterns import detect_ssh_bruteforce
from export_async import send_event

# Configuration du logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("siem_light")

async def worker(queue):
    while True:
        typ, raw = await queue.get()
        logger.debug(f"Worker received raw event type={typ}")
        if typ == 'syslog':
            evt = await normalize_syslog(raw)
        else:
            evt = await normalize_pcap(raw)

        if not evt:
            logger.warning("Événement non normalisé, je l'ignore.")
            queue.task_done()
            continue

        json_ev = await to_json(evt)
        # Envoi dans Elasticsearch
        await send_event('logs-ecs8', json_ev)
        logger.info(f"Event ingéré [{typ}] @ {evt.get('@timestamp')}")

        # Détection de pattern
        alert = await detect_ssh_bruteforce(evt)
        if alert:
            await send_event('alerts-ecs8', alert)
            logger.warning(f"Alerte détectée: {alert['event']['dataset']} from {alert['source']['ip']}")

        queue.task_done()

async def main():
    logger.info("🟢 SIEM Light démarre, en attente de logs…")
    queue = asyncio.Queue()

    # Lancement des ingestions
    tasks = [
        asyncio.create_task(ingest_syslog(queue)),
        asyncio.create_task(ingest_pcap(queue)),
        # Pool de workers
        *[asyncio.create_task(worker(queue)) for _ in range(3)]
    ]

    await asyncio.gather(*tasks)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 Arrêt demandé, fermeture du SIEM Light.")    
