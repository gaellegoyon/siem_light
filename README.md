# SIEM Light

## Description

SIEM Light est une solution légère pour ingérer, normaliser et détecter des patterns dans des logs réseau (Syslog, pcap), puis exporter les événements et alertes vers Elasticsearch 8 pour visualisation dans Grafana.

## Architecture

siem_light/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── pytest.ini
├── .gitignore
├── README.md
├── ingestion_async.py
├── normalize_ecs.py
├── detect_patterns.py
├── export_async.py
├── main_async.py
└── tests/
├── test_normalize.py
├── test_detect.py

## Installation

# Créez un environnement virtuel

python -m venv venv

# Linux/macOS

source venv/bin/activate

# Windows

venv\Scripts\activate

# Installez les dépendances

pip install -r requirements.txt

## Usage

### En local

python main_async.py

### Avec Docker

docker-compose up -d

Le SIEM Light écoutera sur UDP 514 et enverra les logs vers Elasticsearch.

## Tests

pytest
