# modules/ctf/solver.py
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import re
from typing import Dict, List, Optional
import logging
from .decoder import DataDecoder
import hashlib
import base64
import binascii

class CTFSolver:
    """Solucionador automático de retos CTF"""
    
    def __init__(self):
        self.logger = logging.getLogger('CTFSolver')
        self.decoder = DataDecoder()
        self.session = aiohttp.ClientSession()
        self.found_flags = set()
        
    async def solve_challenge(self, target: str, challenge_type: str = None) -> Dict:
        """Intenta resolver reto CTF"""
        results = {
            'type': challenge_type or self._detect_challenge_type(target),
            'flags': [],
            'findings': [],
            'decoded_data': []
        }
        
        try:
            if results['type'] == 'web':
                results.update(await self._solve_web(target))
            elif results['type'] == 'crypto':
                results.update(await self._solve_crypto(target))
            elif results['type'] == 'forensics':
                results.update(await self._solve_forensics(target))
            elif results['type'] == 'reversing':
                results.update(await self._solve_reversing(target))
                
            return results
            
        except Exception as e:
            self.logger.error(f"Solver error: {e}")
            return results
            
    def _detect_challenge_type(self, target: str) -> str:
        """Detecta tipo de reto"""
        if target.startswith(('http://', 'https://')):
            return 'web'
        elif self._looks_like_encoded(target):
            return 'crypto'
        elif target.endswith(('.pcap', '.img', '.png', '.jpg')):
            return 'forensics'
        elif target.endswith(('.exe', '.elf', '.bin')):
            return 'reversing'
        return 'unknown'
        
    async def _solve_web(self, url: str) -> Dict:
        """Resuelve reto web"""
        results = {
            'vulnerabilities': [],
            'endpoints': set(),
            'parameters': set(),
            'interesting_files': []
        }
        
        try:
            # Crawling inicial
            await self._crawl_site(url, results)
            
            # Buscar vulnerabilidades comunes
            for endpoint in results['endpoints']:
                # SQL Injection
                sqli = await self._check_sqli(endpoint)
                if sqli:
                    results['vulnerabilities'].append(sqli)
                    
                # XSS
                xss = await self._check_xss(endpoint)
                if xss:
                    results['vulnerabilities'].append(xss)
                    
                # LFI
                lfi = await self._check_lfi(endpoint)
                if lfi:
                    results['vulnerabilities'].append(lfi)
                    
            # Buscar archivos interesantes
            await self._find_interesting_files(url, results)
            
            # Buscar flags en resultados
            results['flags'] = list(self._find_flags(str(results)))
            
            return results
            
        except Exception as e:
            self.logger.error(f"Web solver error: {e}")
            return results
            
    async def _solve_crypto(self, data: str) -> Dict:
        """Resuelve reto criptográfico"""
        results = {
            'decoded': [],
            'possible_flags': []
        }
        
        try:
            # Intentar decodificaciones comunes
            decoded_data = self.decoder.decode_all(data)
            results['decoded'].extend(decoded_data)
            
            # Buscar flags en datos decodificados
            for decoded in decoded_data:
                flags = self._find_flags(decoded['result'])
                if flags:
                    results['possible_flags'].extend(flags)
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Crypto solver error: {e}")
            return results