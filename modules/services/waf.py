# modules/services/waf.py
import aiohttp
import logging
from typing import Dict, List
import re

class WAFDetector:
    """Detector de WAF y protecciones"""
    
    def __init__(self):
        self.logger = logging.getLogger('WAFDetector')
        self.waf_signatures = self._load_waf_signatures()
        
    def _load_waf_signatures(self) -> Dict:
        """Carga firmas de WAF conocidos"""
        return {
            'cloudflare': {
                'headers': ['__cfduid', 'cf-ray'],
                'cookies': ['__cfduid'],
                'server': ['cloudflare']
            },
            'imperva': {
                'headers': ['x-iinfo', 'x-cdn'],
                'cookies': ['visid_incap'],
                'server': ['incapsula']
            },
            'akamai': {
                'headers': ['x-akamai-transformed'],
                'cookies': ['ak_bmsc'],
                'server': ['akamai']
            }
        }
        
    async def detect(self, host: str, port: int) -> Dict:
        """Detecta presencia de WAF"""
        results = {
            'detected': False,
            'waf_name': None,
            'confidence': 0.0,
            'details': {}
        }
        
        try:
            # Realizar pruebas
            async with aiohttp.ClientSession() as session:
                url = f"{'https' if port == 443 else 'http'}://{host}:{port}"
                
                # Prueba normal
                normal_response = await self._test_request(session, url)
                if normal_response:
                    results.update(
                        self._analyze_response(normal_response)
                    )
                    
                # Si no se detecta, realizar pruebas adicionales
                if not results['detected']:
                    malicious_response = await self._test_malicious(session, url)
                    if malicious_response:
                        results.update(
                            self._analyze_response(malicious_response, True)
                        )
                        
            return results
            
        except Exception as e:
            self.logger.error(f"WAF detection error: {e}")
            return results
            
    async def _test_request(self, session: aiohttp.ClientSession, 
                           url: str, malicious: bool = False) -> Dict:
        """Realiza petición de prueba"""
        try:
            headers = self._get_test_headers(malicious)
            async with session.get(url, headers=headers) as response:
                return {
                    'status': response.status,
                    'headers': dict(response.headers),
                    'cookies': response.cookies,
                    'text': await response.text()
                }
        except:
            return None
            
    def _get_test_headers(self, malicious: bool = False) -> Dict:
        """Genera headers de prueba"""
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': '*/*'
        }
        
        if malicious:
            headers.update({
                'X-Forwarded-For': "' OR '1'='1",
                'Cookie': "' OR '1'='1"
            })
            
        return headers
        
    def _analyze_response(self, response: Dict, 
                         malicious: bool = False) -> Dict:
        """Analiza respuesta para detectar WAF"""
        results = {
            'detected': False,
            'waf_name': None,
            'confidence': 0.0,
            'details': {}
        }
        
        # Verificar firmas conocidas
        for waf_name, signatures in self.waf_signatures.items():
            score = 0
            matches = []
            
            # Verificar headers
            for header in signatures['headers']:
                if any(h.lower() == header.lower() 
                      for h in response['headers']):
                    score += 0.3
                    matches.append(f'Header: {header}')
                    
            # Verificar cookies
            for cookie in signatures['cookies']:
                if cookie.lower() in str(response['cookies']).lower():
                    score += 0.3
                    matches.append(f'Cookie: {cookie}')
                    
            # Verificar servidor
            server = response['headers'].get('server', '').lower()
            if any(s.lower() in server for s in signatures['server']):
                score += 0.4
                matches.append(f'Server: {server}')
                
            if score > results['confidence']:
                results.update({
                    'detected': True,
                    'waf_name': waf_name,
                    'confidence': score,
                    'details': {
                        'matches': matches,
                        'is_malicious': malicious
                    }
                })
                
        return results