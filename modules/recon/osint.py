# modules/recon/osint.py
import aiohttp
import logging
from typing import Dict, List, Set
from bs4 import BeautifulSoup
import re
import json
import asyncio

class OSINTGatherer:
    """Recolector de información OSINT"""
    
    def __init__(self):
        self.logger = logging.getLogger('OSINTGatherer')
        self.results = {
            'emails': set(),
            'social_media': {},
            'technologies': set(),
            'documents': [],
            'employees': set()
        }
        
    async def gather_info(self, domain: str) -> Dict:
        """Recolecta información OSINT"""
        tasks = [
            self._search_emails(domain),
            self._search_social_media(domain),
            self._search_documents(domain),
            self._search_employees(domain)
        ]
        
        await asyncio.gather(*tasks)
        return self._format_results()
        
    async def _search_emails(self, domain: str):
        """Busca correos electrónicos"""
        try:
            async with aiohttp.ClientSession() as session:
                # Búsqueda en Google
                query = f"site:{domain} + '@{domain}'"
                results = await self._google_search(session, query)
                
                # Extraer emails
                email_pattern = f"[a-zA-Z0-9._%+-]+@{domain}"
                for result in results:
                    emails = re.findall(email_pattern, result)
                    self.results['emails'].update(emails)
                    
        except Exception as e:
            self.logger.error(f"Email search error: {e}")
            
    async def _search_social_media(self, domain: str):
        """Busca perfiles de redes sociales"""
        platforms = {
            'linkedin': f"site:linkedin.com/company/{domain}",
            'twitter': f"site:twitter.com {domain}",
            'facebook': f"site:facebook.com {domain}",
            'github': f"site:github.com {domain}"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                for platform, query in platforms.items():
                    results = await self._google_search(session, query)
                    if results:
                        self.results['social_media'][platform] = results
                        
        except Exception as e:
            self.logger.error(f"Social media search error: {e}")
            
    async def _search_documents(self, domain: str):
        """Busca documentos públicos"""
        file_types = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']
        
        try:
            async with aiohttp.ClientSession() as session:
                for file_type in file_types:
                    query = f"site:{domain} filetype:{file_type}"
                    results = await self._google_search(session, query)
                    for result in results:
                        self.results['documents'].append({
                            'url': result,
                            'type': file_type
                        })
                        
        except Exception as e:
            self.logger.error(f"Document search error: {e}")
            
    async def _search_employees(self, domain: str):
        """Busca empleados"""
        try:
            async with aiohttp.ClientSession() as session:
                # Búsqueda en LinkedIn
                query = f"site:linkedin.com/in/ '{domain}'"
                results = await self._google_search(session, query)
                
                for result in results:
                    profile = await self._extract_linkedin_profile(session, result)
                    if profile:
                        self.results['employees'].add(profile)
                        
        except Exception as e:
            self.logger.error(f"Employee search error: {e}")