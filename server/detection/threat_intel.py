import asyncio
import logging
import ssl
import ipaddress
import aiohttp
import certifi
from datetime import datetime, timedelta
from typing import Set
from urllib.parse import urlparse

_ssl_ctx = ssl.create_default_context(cafile=certifi.where())

logger = logging.getLogger(__name__)

FEODO_C2_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text/"


class ThreatIntel:
    def __init__(self):
        self.malicious_ips: Set[str] = set()
        self.malicious_domains: Set[str] = set()
        self.last_refresh: datetime | None = None
        self._refresh_interval = timedelta(hours=4)

        # Mining pool ports
        self.mining_ports: Set[int] = {3333, 4444, 8888, 14444, 45700, 9999, 9200, 4000, 5555, 7777}

        # Known crypto miner process names (lowercase substrings)
        self.miner_names: Set[str] = {
            "xmrig",
            "minerd",
            "cpuminer",
            "t-rex",
            "phoenixminer",
            "lolminer",
            "gminer",
            "nbminer",
            "nsfminer",
            "ethminer",
            "cgminer",
            "bfgminer",
            "claymore",
            "teamredminer",
            "wildrig",
            "srbminer",
            "kawpowminer",
            "nanominer",
            "rigel",
            "bminer",
            "excavator",
            "trex",
            "minero",
        }

        # Spectrum DNS servers + common public DNS (exact IPs)
        self.trusted_dns: Set[str] = {
            "75.75.75.75",
            "75.75.76.76",  # Spectrum
            "8.8.8.8",
            "8.8.4.4",  # Google public DNS
            "1.1.1.1",
            "1.0.0.1",  # Cloudflare
            "9.9.9.9",
            "149.112.112.112",  # Quad9
            "208.67.222.222",
            "208.67.220.220",  # OpenDNS
        }
        # Trusted CIDR ranges — browsers use DNS-over-HTTPS across these,
        # so any DNS traffic to these networks is expected and not suspicious.
        self._trusted_networks = [
            ipaddress.ip_network(n)
            for n in [
                "142.250.0.0/15",  # Google (Chrome DoH, 1e100.net)
                "172.217.0.0/16",  # Google
                "172.253.0.0/16",  # Google
                "173.194.0.0/16",  # Google
                "192.178.0.0/15",  # Google
                "216.58.192.0/19",  # Google
                "104.16.0.0/13",  # Cloudflare CDN / DoH
                "17.0.0.0/8",  # Apple (Private Relay, DoH)
                "98.80.0.0/12",  # Amazon (covers 98.80–98.95)
                "52.0.0.0/8",  # Amazon AWS
                "54.0.0.0/8",  # Amazon AWS
                "3.0.0.0/8",  # Amazon AWS
                "13.32.0.0/12",  # Amazon CloudFront
                "150.171.0.0/16",  # Microsoft
                "13.64.0.0/11",  # Microsoft Azure
                "13.96.0.0/13",  # Microsoft Azure
                "13.104.0.0/14",  # Microsoft Azure
                "20.0.0.0/8",  # Microsoft Azure
                "40.0.0.0/8",  # Microsoft Azure
            ]
        ]

        # Hard allowlist — legitimate domains that should never alert even at
        # high query volume (user-facing services with no meaningful abuse signal
        # from DNS queries alone).
        self._domain_allowlist: Set[str] = {
            "google.com",
            "googleapis.com",
            "gstatic.com",
            "microsoft.com",
            "windows.com",
            "live.com",
            "apple.com",
            "icloud.com",
            "mzstatic.com",
            "amazon.com",
            "amazonaws.com",
            "cloudflare.com",
            "fastly.net",
            "akamai.net",
        }

        # Abused-but-legitimate domains — appear in URLhaus because attackers use
        # their file hosting, but a single query is normal. Alert only on unusual
        # volume (5+ queries in 2 minutes) which suggests automated payload fetching.
        self.abused_domains: Set[str] = {
            "docs.google.com",
            "drive.google.com",
            "sheets.google.com",
            "slides.google.com",
            "storage.googleapis.com",
            "calendar.google.com",
            "raw.githubusercontent.com",
            "gist.github.com",
            "githubusercontent.com",
            "pastebin.com",
            "paste.ee",
            "rentry.co",
            "hastebin.com",
            "cdn.discordapp.com",
            "media.discordapp.net",
            "discord.com",
            "dl.dropboxusercontent.com",
            "dropbox.com",
            "onedrive.live.com",
            "1drv.ms",
            "t.me",
            "telegram.org",
            "transfer.sh",
            "file.io",
            "gofile.io",
            "anonfiles.com",
        }

        # Volume threshold: N queries within WINDOW seconds triggers an alert
        # 5 was too sensitive — Google Calendar alone can hit 5 queries to
        # docs.google.com just from loading Drive integration in the background
        self.abuse_threshold = 15
        self.abuse_window_secs = 120

    async def refresh(self):
        if self.last_refresh and datetime.utcnow() - self.last_refresh < self._refresh_interval:
            return
        logger.info("Refreshing threat intelligence feeds...")
        connector = aiohttp.TCPConnector(ssl=_ssl_ctx)
        async with aiohttp.ClientSession(connector=connector) as session:
            results = await asyncio.gather(
                self._fetch_feodo(session),
                self._fetch_urlhaus(session),
                return_exceptions=True,
            )
        for r in results:
            if isinstance(r, Exception):
                logger.warning(f"Threat intel fetch error: {r}")
        self.last_refresh = datetime.utcnow()
        logger.info(
            f"Threat intel: {len(self.malicious_ips)} IPs, {len(self.malicious_domains)} domains"
        )

    async def _fetch_feodo(self, session: aiohttp.ClientSession):
        async with session.get(FEODO_C2_URL, timeout=aiohttp.ClientTimeout(total=30)) as r:
            if r.status == 200:
                text = await r.text()
                ips = {
                    line.strip()
                    for line in text.splitlines()
                    if line.strip() and not line.startswith("#")
                }
                self.malicious_ips.update(ips)
                logger.info(f"Feodo: {len(ips)} C2 IPs loaded")

    async def _fetch_urlhaus(self, session: aiohttp.ClientSession):
        async with session.get(URLHAUS_URL, timeout=aiohttp.ClientTimeout(total=30)) as r:
            if r.status == 200:
                text = await r.text()
                domains: Set[str] = set()
                for line in text.splitlines():
                    line = line.strip().lower()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("http"):
                        parsed = urlparse(line)
                        if parsed.hostname:
                            domains.add(parsed.hostname)
                    else:
                        domains.add(line)
                self.malicious_domains.update(domains)
                logger.info(f"URLhaus: {len(domains)} malicious domains loaded")

    def is_malicious_ip(self, ip: str) -> bool:
        return ip in self.malicious_ips

    def _domain_matches(self, domain: str, domain_set: Set[str]) -> bool:
        return domain in domain_set or any(
            domain == d or domain.endswith("." + d) for d in domain_set
        )

    def is_malicious_domain(self, domain: str) -> bool:
        d = domain.lower().rstrip(".")
        # Hard allowlist and abused-but-legitimate domains are handled separately
        if self._domain_matches(d, self._domain_allowlist):
            return False
        if self._domain_matches(d, self.abused_domains):
            return False
        return d in self.malicious_domains

    def is_abused_domain(self, domain: str) -> bool:
        """True if domain is a legitimate service known to be abused for payload hosting.
        Abused list takes priority over the hard allowlist."""
        d = domain.lower().rstrip(".")
        return self._domain_matches(d, self.abused_domains)

    def is_miner_process(self, name: str) -> bool:
        n = name.lower()
        return any(m in n for m in self.miner_names)

    def is_mining_port(self, port: int) -> bool:
        return port in self.mining_ports

    def is_trusted_dns(self, ip: str) -> bool:
        if ip in self.trusted_dns:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._trusted_networks)
        except ValueError:
            return False

    def status(self) -> dict:
        return {
            "malicious_ips": len(self.malicious_ips),
            "malicious_domains": len(self.malicious_domains),
            "last_refresh": self.last_refresh.isoformat() if self.last_refresh else None,
        }
