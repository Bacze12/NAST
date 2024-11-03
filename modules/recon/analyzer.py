# modules/recon/analyzer.py
import aiohttp
from bs4 import BeautifulSoup
import re
from typing import Dict, List, Set
import logging
import json
from urllib.parse import urljoin

class TechDetector:
    """Detector de tecnologías web"""
    
    def __init__(self):
        self.logger = logging.getLogger('TechDetector')
        self.signatures = self._load_signatures()
        
    def _load_signatures(self) -> Dict:
        """Carga firmas de tecnologías"""
        try:
            with open('data/signatures/tech.json', 'r') as f:
                return json.load(f)
        except:
            return {}
            
    async def detect_technologies(self, url: str) -> Dict:
        """Detecta tecnologías usadas"""
        results = {
            'frameworks': set(),
            'languages': set(),
            'servers': set(),
            'cms': set(),
            'javascript': set(),
            'analytics': set(),
            'advertising': set()
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    # Analizar headers
                    headers_tech = self._analyze_headers(dict(response.headers))
                    for category, techs in headers_tech.items():
                        results[category].update(techs)
                        
                    # Analizar HTML
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    html_tech = self._analyze_html(soup)
                    for category, techs in html_tech.items():
                        results[category].update(techs)
                        
                    # Analizar JavaScript
                    js_tech = self._analyze_javascript(soup)
                    results['javascript'].update(js_tech)
                    
                    # Analizar cookies
                    cookie_tech = self._analyze_cookies(response.cookies)
                    for category, techs in cookie_tech.items():
                        results[category].update(techs)
                        
            return {k: list(v) for k, v in results.items() if v}
            
        except Exception as e:
            self.logger.error(f"Technology detection error: {e}")
            return results
            
    def _analyze_headers(self, headers: Dict) -> Dict:
        """Analiza headers en busca de tecnologías"""
        results = {
            'servers': set(),
            'frameworks': set(),
            'security': set()
        }
        
        # Server header
        if 'Server' in headers:
            server = headers['Server'].lower()
            for sig in self.signatures.get('servers', []):
                if sig['pattern'].lower() in server:
                    results['servers'].add(sig['name'])
                    
        # X-Powered-By
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By'].lower()
            for sig in self.signatures.get('frameworks', []):
                if sig['pattern'].lower() in powered_by:
                    results['frameworks'].add(sig['name'])
                    
        # Security headers
        security_headers = [
            'X-Frame-Options',
            'X-XSS-Protection',
            'Content-Security-Policy',
            'X-Content-Type-Options'
        ]
        
        for header in security_headers:
            if header in headers:
                results['security'].add(header)
                
        return results
        
    def _analyze_html(self, soup: BeautifulSoup) -> Dict:
        """Analiza HTML en busca de tecnologías"""
        results = {
            'frameworks': set(),
            'cms': set(),
            'javascript': set()
        }
        
        # Meta tags
        for meta in soup.find_all('meta'):
            if 'generator' in meta.get('name', '').lower():
                content = meta.get('content', '').lower()
                for sig in self.signatures.get('cms', []):
                    if sig['pattern'].lower() in content:
                        results['cms'].add(sig['name'])
                        
        # Script tags
        for script in soup.find_all('script'):
            src = script.get('src', '')
            if src:
                for sig in self.signatures.get('javascript', []):
                    if sig['pattern'].lower() in src.lower():
                        results['javascript'].add(sig['name'])
                        
        # Link tags
        for link in soup.find_all('link'):
            href = link.get('href', '')
            if href:
                for sig in self.signatures.get('frameworks', []):
                    if sig['pattern'].lower() in href.lower():
                        results['frameworks'].add(sig['name'])
                        
        return results
        
    def _analyze_javascript(self, soup: BeautifulSoup) -> Set[str]:
        """Analiza JavaScript en busca de tecnologías"""
        results = set()
        
        # Inline scripts
        for script in soup.find_all('script'):
            if script.string:
                content = script.string.lower()
                for sig in self.signatures.get('javascript', []):
                    if sig['pattern'].lower() in content:
                        results.add(sig['name'])
                        
        return results
        
    def _analyze_cookies(self, cookies: Dict) -> Dict:
        """Analiza cookies en busca de tecnologías"""
        results = {
            'analytics': set(),
            'advertising': set(),
            'cms': set()
        }
        
        for cookie in cookies:
            cookie_name = cookie.lower()
            # Analytics
            if 'ga' in cookie_name or 'analytics' in cookie_name:
                results['analytics'].add('Google Analytics')
            # Advertising
            elif 'ad' in cookie_name or 'pixel' in cookie_name:
                results['advertising'].add('Advertising Cookies')
            # CMS
            for sig in self.signatures.get('cms', []):
                if sig['pattern'].lower() in cookie_name:
                    results['cms'].add(sig['name'])
                    
        return results