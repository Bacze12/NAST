# modules/vuln/scanner.py
import aiohttp
import asyncio
from typing import Dict, List, Optional
from dataclasses import dataclass
import logging
import json
import re
from bs4 import BeautifulSoup
import ssl
from urllib.parse import urljoin, parse_qs

@dataclass
class Vulnerability:
    """Estructura de vulnerabilidad"""
    id: str
    name: str
    severity: str
    description: str
    evidence: Optional[str] = None
    cve: Optional[List[str]] = None
    cvss: Optional[float] = None
    remediation: Optional[str] = None

class VulnerabilityScanner:
    """Escáner avanzado de vulnerabilidades"""
    
    def __init__(self):
        self.logger = logging.getLogger('VulnScanner')
        self.vulns_db = self._load_vulns_database()
        self.initialize_scanners()
        
    def initialize_scanners(self):
        """Inicializa escáneres específicos"""
        self.scanners = {
            'web': WebVulnScanner(),
            'network': NetworkVulnScanner(),
            'ssl': SSLScanner(),
            'misconfig': MisconfigScanner()
        }
        
    async def scan_target(self, target: str, scan_type: str = 'all') -> List[Vulnerability]:
        """Escaneo principal de vulnerabilidades"""
        vulnerabilities = []
        
        try:
            if scan_type == 'all':
                # Ejecutar todos los escáneres
                tasks = []
                for scanner in self.scanners.values():
                    tasks.append(scanner.scan(target))
                    
                results = await asyncio.gather(*tasks)
                for result in results:
                    vulnerabilities.extend(result)
            else:
                # Ejecutar escáner específico
                if scan_type in self.scanners:
                    vulnerabilities = await self.scanners[scan_type].scan(target)
                    
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            return []

class WebVulnScanner:
    """Escáner de vulnerabilidades web"""
    
    def __init__(self):
        self.logger = logging.getLogger('WebVulnScanner')
        self.session = aiohttp.ClientSession()
        self.visited_urls = set()
        self.vulnerabilities = []
        
    async def scan(self, url: str) -> List[Vulnerability]:
        """Escaneo de vulnerabilidades web"""
        try:
            # Crawling inicial
            await self._crawl_site(url)
            
            # Escanear cada URL descubierta
            tasks = []
            for discovered_url in self.visited_urls:
                tasks.extend([
                    self._check_sqli(discovered_url),
                    self._check_xss(discovered_url),
                    self._check_lfi(discovered_url),
                    self._check_rfi(discovered_url),
                    self._check_ssrf(discovered_url),
                    self._check_open_redirect(discovered_url)
                ])
                
            await asyncio.gather(*tasks)
            return self.vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Web scan error: {e}")
            return []
            
    async def _crawl_site(self, url: str):
        """Crawling del sitio"""
        if url in self.visited_urls:
            return
            
        self.visited_urls.add(url)
        
        try:
            async with self.session.get(url) as response:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                
                # Encontrar enlaces
                for link in soup.find_all(['a', 'form']):
                    href = link.get('href') or link.get('action')
                    if href:
                        next_url = urljoin(url, href)
                        if next_url.startswith(url):
                            await self._crawl_site(next_url)
                            
        except Exception as e:
            self.logger.error(f"Crawling error: {e}")
            
    async def _check_sqli(self, url: str):
        """Verificación de SQL Injection"""
        payloads = [
            "' OR '1'='1",
            "1' ORDER BY 1--",
            "1' UNION SELECT NULL--",
            "'; WAITFOR DELAY '0:0:5'--"
        ]
        
        for payload in payloads:
            try:
                # GET request
                async with self.session.get(url + payload) as response:
                    content = await response.text()
                    if self._is_sql_vulnerable(content):
                        self.vulnerabilities.append(
                            Vulnerability(
                                id="SQLI-01",
                                name="SQL Injection",
                                severity="High",
                                description="SQL Injection vulnerability found",
                                evidence=f"URL: {url}\nPayload: {payload}"
                            )
                        )
                        break
                        
                # POST request
                async with self.session.post(url, data={'test': payload}) as response:
                    content = await response.text()
                    if self._is_sql_vulnerable(content):
                        self.vulnerabilities.append(
                            Vulnerability(
                                id="SQLI-02",
                                name="SQL Injection (POST)",
                                severity="High",
                                description="SQL Injection vulnerability found in POST parameter",
                                evidence=f"URL: {url}\nPayload: {payload}"
                            )
                        )
                        break
                        
            except Exception:
                continue

class NetworkVulnScanner:
    """Escáner de vulnerabilidades de red"""
    
    def __init__(self):
        self.logger = logging.getLogger('NetworkVulnScanner')
        
    async def scan(self, target: str) -> List[Vulnerability]:
        """Escaneo de vulnerabilidades de red"""
        vulnerabilities = []
        
        try:
            # Verificar puertos comunes
            open_ports = await self._scan_ports(target)
            
            # Verificar cada servicio
            for port, service in open_ports.items():
                vulns = await self._check_service_vulns(target, port, service)
                vulnerabilities.extend(vulns)
                
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Network scan error: {e}")
            return []
            
    async def _scan_ports(self, target: str) -> Dict[int, str]:
        """Escaneo de puertos básico"""
        open_ports = {}
        common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432]
        
        for port in common_ports:
            try:
                reader, writer = await asyncio.open_connection(target, port)
                writer.close()
                await writer.wait_closed()
                open_ports[port] = await self._identify_service(target, port)
            except:
                continue
                
        return open_ports

class SSLScanner:
    """Escáner de vulnerabilidades SSL/TLS"""
    
    def __init__(self):
        self.logger = logging.getLogger('SSLScanner')
        
    async def scan(self, target: str) -> List[Vulnerability]:
        """Escaneo de vulnerabilidades SSL"""
        vulnerabilities = []
        
        try:
            # Verificar versiones SSL/TLS
            ssl_versions = await self._check_ssl_versions(target)
            for version, is_vulnerable in ssl_versions.items():
                if is_vulnerable:
                    vulnerabilities.append(
                        Vulnerability(
                            id=f"SSL-{version}",
                            name=f"Vulnerable SSL/TLS Version: {version}",
                            severity="High",
                            description=f"Server supports vulnerable SSL/TLS version: {version}",
                            remediation="Disable old SSL/TLS versions"
                        )
                    )
                    
            # Verificar cipher suites
            weak_ciphers = await self._check_weak_ciphers(target)
            if weak_ciphers:
                vulnerabilities.append(
                    Vulnerability(
                        id="SSL-CIPHER",
                        name="Weak Cipher Suites",
                        severity="Medium",
                        description="Server supports weak cipher suites",
                        evidence=f"Weak ciphers: {', '.join(weak_ciphers)}"
                    )
                )
                
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"SSL scan error: {e}")
            return []

class MisconfigScanner:
    """Escáner de configuraciones erróneas"""
    
    def __init__(self):
        self.logger = logging.getLogger('MisconfigScanner')
        
    async def scan(self, target: str) -> List[Vulnerability]:
        """Escaneo de configuraciones erróneas"""
        vulnerabilities = []
        
        try:
            # Verificar headers de seguridad
            headers = await self._check_security_headers(target)
            for header, status in headers.items():
                if not status['present']:
                    vulnerabilities.append(
                        Vulnerability(
                            id=f"HEADER-{header}",
                            name=f"Missing Security Header: {header}",
                            severity="Low",
                            description=f"Security header {header} is missing",
                            remediation=status['recommendation']
                        )
                    )
                    
            # Verificar directorios sensibles
            sensitive_dirs = await self._check_sensitive_dirs(target)
            for dir_info in sensitive_dirs:
                vulnerabilities.append(
                    Vulnerability(
                        id="DIR-EXPOSURE",
                        name="Sensitive Directory Exposure",
                        severity="Medium",
                        description=f"Sensitive directory found: {dir_info['path']}",
                        evidence=dir_info['evidence']
                    )
                )
                
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Misconfig scan error: {e}")
            return []
