# modules/services/fingerprint.py
import asyncio
import socket
import ssl
from typing import Dict, Optional
import re
import logging
from urllib.parse import urlparse

class ServiceFingerprinter:
    """Fingerprinting detallado de servicios"""
    
    def __init__(self):
        self.logger = logging.getLogger('ServiceFingerprinter')
        self.techniques = {
            'http': self._fingerprint_http,
            'https': self._fingerprint_https,
            'ssh': self._fingerprint_ssh,
            'ftp': self._fingerprint_ftp,
            'mysql': self._fingerprint_mysql,
            'postgresql': self._fingerprint_postgresql
        }
        
    async def fingerprint_service(self, host: str, port: int, 
                                service: str) -> Dict:
        """Realiza fingerprinting de servicio"""
        try:
            if service in self.techniques:
                return await self.techniques[service](host, port)
            return await self._generic_fingerprint(host, port)
        except Exception as e:
            self.logger.error(f"Fingerprinting error: {e}")
            return {}
            
    async def _fingerprint_http(self, host: str, port: int) -> Dict:
        """Fingerprinting de servidor HTTP"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://{host}:{port}"
                async with session.get(url) as response:
                    return {
                        'server': response.headers.get('Server', ''),
                        'powered_by': response.headers.get('X-Powered-By', ''),
                        'technologies': self._detect_technologies(response.headers),
                        'headers': dict(response.headers)
                    }
        except:
            return {}
            
    async def _fingerprint_https(self, host: str, port: int) -> Dict:
        """Fingerprinting de servidor HTTPS"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            async with aiohttp.ClientSession() as session:
                url = f"https://{host}:{port}"
                async with session.get(url, ssl=context) as response:
                    info = await self._fingerprint_http(host, port)
                    info['cert'] = self._get_cert_info(host, port)
                    return info
        except:
            return {}
