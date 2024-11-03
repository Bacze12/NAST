# modules/recon/finder.py
import asyncio
import dns.resolver
import dns.zone
import aiohttp
from bs4 import BeautifulSoup
import re
from typing import Set, List, Dict
import logging
import ssl
import socket
from urllib.parse import urlparse

class SubdomainFinder:
    """Buscador avanzado de subdominios"""
    
    def __init__(self):
        self.logger = logging.getLogger('SubdomainFinder')
        self.subdomains = set()
        self.techniques = {
            'dns': self._dns_enumeration,
            'cert': self._cert_search,
            'bruteforce': self._subdomain_bruteforce,
            'web': self._web_scraping
        }
        self.wordlist = self._load_wordlist()
        
    def _load_wordlist(self) -> List[str]:
        """Carga lista de subdominios comunes"""
        try:
            with open('data/wordlists/subdomains.txt', 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return []
            
    async def find_subdomains(self, domain: str) -> Set[str]:
        """Busca subdominios usando múltiples técnicas"""
        tasks = []
        for technique in self.techniques.values():
            tasks.append(technique(domain))
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, set):
                self.subdomains.update(result)
                
        return self.subdomains
        
    async def _dns_enumeration(self, domain: str) -> Set[str]:
        """Enumeración mediante DNS"""
        results = set()
        try:
            # Consultas DNS
            for record_type in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']:
                try:
                    answers = await asyncio.get_event_loop().run_in_executor(
                        None, 
                        dns.resolver.resolve,
                        domain,
                        record_type
                    )
                    for rdata in answers:
                        if record_type == 'NS':
                            results.add(str(rdata.target).rstrip('.'))
                        elif record_type == 'MX':
                            results.add(str(rdata.exchange).rstrip('.'))
                        elif record_type == 'CNAME':
                            results.add(str(rdata.target).rstrip('.'))
                except:
                    continue
                    
            # Transferencia de zona
            nameservers = await self._get_nameservers(domain)
            for ns in nameservers:
                try:
                    zone = await self._zone_transfer(domain, ns)
                    if zone:
                        results.update(zone)
                except:
                    continue
                    
            return results
            
        except Exception as e:
            self.logger.error(f"DNS enumeration error: {e}")
            return set()
            
    async def _cert_search(self, domain: str) -> Set[str]:
        """Búsqueda en certificados SSL"""
        results = set()
        try:
            # Búsqueda en crt.sh
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name = entry.get('name_value', '').lower()
                            if name.endswith(domain):
                                results.add(name)
                                
            # Verificación SSL directa
            for subdomain in list(results):
                try:
                    cert = await self._get_ssl_cert(subdomain)
                    if cert:
                        for name in cert.get('subject_alt_names', []):
                            if name.endswith(domain):
                                results.add(name.lower())
                except:
                    continue
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Certificate search error: {e}")
            return set()
            
    async def _subdomain_bruteforce(self, domain: str) -> Set[str]:
        """Fuerza bruta de subdominios"""
        results = set()
        
        async def check_subdomain(subdomain: str):
            """Verifica existencia de subdominio"""
            try:
                fqdn = f"{subdomain}.{domain}"
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    socket.gethostbyname,
                    fqdn
                )
                results.add(fqdn)
            except:
                pass
                
        # Crear tareas para cada subdominio
        tasks = []
        for word in self.wordlist:
            tasks.append(check_subdomain(word))
            
        # Ejecutar en chunks para evitar sobrecarga
        chunk_size = 50
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i + chunk_size]
            await asyncio.gather(*chunk, return_exceptions=True)
            await asyncio.sleep(1)  # Delay para evitar rate limiting
            
        return results