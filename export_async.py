import asyncio
from elasticsearch import AsyncElasticsearch, helpers

es = AsyncElasticsearch(['http://localhost:9200'])

async def send_event(index, event_json):
    await es.index(index=index, document=event_json)

async def send_bulk(index, events):
    actions = [{"_index": index, "_source": ev} for ev in events]
    await helpers.async_bulk(es, actions)