# modules/report/generator.py
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import json
import os
from datetime import datetime
from typing import Dict, List, Any
from jinja2 import Environment, FileSystemLoader
import matplotlib.pyplot as plt
import networkx as nx
import base64
from io import BytesIO
import logging

class ReportGenerator:
    """Generador avanzado de reportes"""
    
    def __init__(self):
        self.console = Console()
        self.logger = logging.getLogger('ReportGenerator')
        self.initialize_templates()
        
    def initialize_templates(self):
        """Inicializa entorno de plantillas"""
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=True
        )
        
    async def generate_report(self, data: Dict, output_format: str = 'html',
                            output_file: str = None) -> None:
        """Genera reporte completo"""
        try:
            # Procesar datos
            processed_data = self._process_data(data)
            
            # Generar visualizaciones
            visualizations = await self._generate_visualizations(processed_data)
            
            # Crear reporte
            report = {
                'timestamp': datetime.now().isoformat(),
                'summary': self._generate_summary(processed_data),
                'details': processed_data,
                'visualizations': visualizations,
                'recommendations': self._generate_recommendations(processed_data)
            }
            
            # Generar salida según formato
            if output_format == 'html':
                output = self._generate_html_report(report)
            elif output_format == 'json':
                output = self._generate_json_report(report)
            elif output_format == 'markdown':
                output = self._generate_markdown_report(report)
            else:
                raise ValueError(f"Formato no soportado: {output_format}")
                
            # Guardar o mostrar reporte
            if output_file:
                self._save_report(output, output_file)
            else:
                self._display_report(report)
                
        except Exception as e:
            self.logger.error(f"Error generando reporte: {str(e)}")
            raise