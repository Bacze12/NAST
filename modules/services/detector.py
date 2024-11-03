# modules/services/detector.py
import socket
import ssl
import asyncio
import aiohttp
from typing import Dict, Optional
from dataclasses import dataclass
import logging
import json
from .fingerprint import ServiceFingerprinter
from .waf import WAFDetector

@dataclass
class ServiceInfo:
    """Información de servicio detectado"""
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    fingerprint: Optional[Dict] = None
    waf_info: Optional[Dict] = None
    confidence: float = 0.0

class ServiceDetector:
    """Detector principal de servicios"""
    
    def __init__(self, stealth_level: int = 3):
        self.logger = logging.getLogger('ServiceDetector')
        self.stealth_level = stealth_level
        self.fingerprinter = ServiceFingerprinter()
        self.waf_detector = WAFDetector()
        self.load_signatures()
        
    def load_signatures(self):
        """Carga firmas de servicios"""
        try:
            with open('data/signatures/services.json', 'r') as f:
                self.signatures = json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading signatures: {e}")
            self.signatures = {}
            
    async def detect_service(self, host: str, port: int) -> ServiceInfo:
        """Detecta servicio en host:port"""
        try:
            # Detección inicial
            service_info = await self._initial_detect(host, port)
            
            # Si es web, detectar WAF
            if service_info.name in ['http', 'https']:
                service_info.waf_info = await self.waf_detector.detect(host, port)
                
            # Fingerprinting detallado
            fingerprint = await self.fingerprinter.fingerprint_service(
                host, port, service_info.name
            )
            service_info.fingerprint = fingerprint
            
            return service_info
            
        except Exception as e:
            self.logger.error(f"Detection error: {e}")
            return ServiceInfo(name="unknown")
            
    async def _initial_detect(self, host: str, port: int) -> ServiceInfo:
        """Detección inicial de servicio"""
        # Intentar banner grabbing sigiloso
        banner = await self._grab_banner(host, port)
        if banner:
            service = self._analyze_banner(banner)
            if service.confidence > 0.8:
                return service
                
        # Probar protocolos comunes
        for probe in self._get_probes():
            try:
                result = await self._send_probe(host, port, probe)
                if result.confidence > 0.5:
                    return result
            except:
                continue
                
        return ServiceInfo(name="unknown")
        
    async def _grab_banner(self, host: str, port: int) -> Optional[str]:
        """Banner grabbing sigiloso"""
        try:
            reader, writer = await asyncio.open_connection(host, port)
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=2)
                return banner.decode('utf-8', errors='ignore')
            finally:
                writer.close()
                await writer.wait_closed()
        except:
            return None
