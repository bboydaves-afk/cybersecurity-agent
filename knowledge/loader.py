"""Knowledge base loader with caching for CyberSecurity Agent."""

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("hacking_agent.knowledge")

_KNOWLEDGE_DIR = Path(__file__).parent
_cache: dict[str, Any] = {}


def load_knowledge(filename: str) -> dict | list:
    if filename in _cache:
        return _cache[filename]
    path = _KNOWLEDGE_DIR / filename
    if not path.exists():
        logger.warning("Knowledge file not found: %s", path)
        return {}
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    _cache[filename] = data
    logger.debug("Loaded knowledge: %s", filename)
    return data


def get_mitre_attack() -> dict:
    return load_knowledge("mitre_attack.yaml")


def get_owasp_top10() -> dict:
    return load_knowledge("owasp_top10.yaml")


def get_common_ports() -> dict:
    return load_knowledge("common_ports.yaml")


def get_password_policies() -> dict:
    return load_knowledge("password_policies.yaml")


def get_compliance_frameworks() -> dict:
    return load_knowledge("compliance_frameworks.yaml")


def get_exploit_categories() -> dict:
    return load_knowledge("exploit_categories.yaml")


def get_cloud_misconfigs() -> dict:
    return load_knowledge("cloud_misconfigs.yaml")


def clear_cache():
    _cache.clear()
