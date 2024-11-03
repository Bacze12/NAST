# modules/network/scanner.py
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import nmap
import asyncio
import random
import time
from typing import List, Dict, Optional
import logging

class StealthScanner:
    """Escáner sigiloso de red"""
    
    def __init__(self):
        self.logger = logging.getLogger('StealthScanner')
        self.nm = nmap.PortScanner()
        
    async def scan(self, target: str, ports: List[int] = None,
                  stealth: bool = True) -> Dict:
        """Realiza escaneo"""
        results = {
            'hosts': {},
            'total_hosts': 0,
            'up_hosts': 0
        }
        
        try:
            # Configurar escaneo
            if stealth:
                args = '-sS -T2 -n -Pn'
            else:
                args = '-sS -T4 -A'
                
            if ports:
                args += f' -p {",".join(map(str, ports))}'
                
            # Ejecutar escaneo
            self.nm.scan(hosts=target, arguments=args)
            
            # Procesar resultados
            results['total_hosts'] = len(self.nm.all_hosts())
            results['up_hosts'] = len([h for h in self.nm.all_hosts() 
                                     if self.nm[h].state() == 'up'])
                                     
            for host in self.nm.all_hosts():
                results['hosts'][host] = self._process_host(host)
                
            return results
            
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            raise
            
    def _process_host(self, host: str) -> Dict:
        """Procesa información de host"""
        host_info = {
            'status': self.nm[host].state(),
            'ports': {},
            'os': self.nm[host].get('osmatch', []),
            'hostnames': self.nm[host].hostnames()
        }
        
        # Procesar puertos
        for proto in self.nm[host].all_protocols():
            for port in self.nm[host][proto]:
                host_info['ports'][port] = {
                    'state': self.nm[host][proto][port]['state'],
                    'service': self.nm[host][proto][port]['name'],
                    'product': self.nm[host][proto][port].get('product', ''),
                    'version': self.nm[host][proto][port].get('version', ''),
                    'extra': self.nm[host][proto][port].get('extrainfo', '')
                }
                
        return host_info
