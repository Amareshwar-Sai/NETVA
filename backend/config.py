"""Application settings — loads from .env file."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Lab SSH ──
    # No hardcoded passwords: these must come from a local .env file (which
    # is gitignored and never committed). Host/port/user defaults are safe
    # to keep since they're just local-lab connection shape, not secrets --
    # only the *_pass fields are security-sensitive and have no default.
    lab_webserver_host: str = "127.0.0.1"
    lab_webserver_port: int = 2221
    lab_webserver_user: str = "admin"
    lab_webserver_pass: str = ""

    lab_appserver_host: str = "127.0.0.1"
    lab_appserver_port: int = 2222
    lab_appserver_user: str = "appuser"
    lab_appserver_pass: str = ""

    lab_database_host: str = "127.0.0.1"
    lab_database_port: int = 2223
    lab_database_user: str = "root"
    lab_database_pass: str = ""

    lab_firewall_host: str = "127.0.0.1"
    lab_firewall_port: int = 2224
    lab_firewall_user: str = "root"
    lab_firewall_pass: str = ""

    # ── AMC ──
    amc_w_vuln: float = 0.35
    amc_w_reachability: float = 0.25
    amc_w_privilege: float = 0.20
    amc_w_misconfig: float = 0.12
    amc_w_telemetry: float = 0.08

    # ── Risk Scorer ──
    risk_alpha: float = 0.25
    risk_beta: float = 0.20
    risk_gamma: float = 0.25
    risk_delta: float = 0.20
    risk_epsilon: float = 0.10

    # ── MDP Reward ──
    mdp_lambda1: float = 0.40
    mdp_lambda2: float = 0.15
    mdp_lambda3: float = 0.10
    mdp_lambda4: float = 0.35

    # ── Q-Learning ──
    ql_alpha: float = 0.10
    ql_gamma: float = 0.90
    ql_epsilon: float = 0.30
    ql_epsilon_decay: float = 0.995
    ql_epsilon_min: float = 0.01
    ql_episodes: int = 500

    # ── Server ──
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    frontend_url: str = "http://localhost:5173"

    # ── EPSS ──
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    epss_timeout: int = 10

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache
def get_settings() -> Settings:
    return Settings()