# core/engine.py
import argparse
import asyncio
import logging
from rich.console import Console
from ..config import settings
from ..modules.network import NetworkManager
from ..modules.services import ServiceDetector
from ..modules.recon import ReconModule
from ..modules.vuln import VulnerabilityScanner
from ..modules.traffic import TrafficAnalyzer
from ..modules.ctf import CTFModule
from ..modules.report import ReportGenerator
from ..database import DatabaseManager

class NASTEngine:
    """Motor principal de NAST"""
    
    def __init__(self):
        self.console = Console()
        self.setup_logging()
        self.initialize_components()
        
    def setup_logging(self):
        """Configura logging"""
        logging.config.dictConfig(settings.LOGGING)
        self.logger = logging.getLogger('NAST')
        
    def initialize_components(self):
        """Inicializa componentes principales"""
        self.network_manager = NetworkManager()
        self.service_detector = ServiceDetector()
        self.recon_module = ReconModule()
        self.vuln_scanner = VulnerabilityScanner()
        self.traffic_analyzer = TrafficAnalyzer()
        self.ctf_module = CTFModule()
        self.report_generator = ReportGenerator()
        self.db_manager = DatabaseManager()
        
    async def run_scan(self, args):
        """Ejecuta escaneo basado en argumentos"""
        try:
            # Configurar modo anónimo si se solicita
            if args.anonymous:
                await self.network_manager.enable_anonymous_mode(args.interface)
                
            # Ejecutar módulos seleccionados
            results = {}
            
            if 'network' in args.modules:
                results['network'] = await self.network_manager.scan_network(
                    args.target
                )
                
            if 'recon' in args.modules:
                results['recon'] = await self.recon_module.perform_recon(
                    args.target
                )
                
            if 'vuln' in args.modules:
                results['vulnerabilities'] = await self.vuln_scanner.scan_target(
                    args.target
                )
                
            if 'traffic' in args.modules:
                results['traffic'] = await self.traffic_analyzer.analyze_traffic(
                    args.interface
                )
                
            # Generar reporte
            if args.output:
                await self.report_generator.generate_report(
                    results, args.output
                )
                
            # Guardar resultados
            self.db_manager.save_scan_result(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error in scan: {str(e)}")
            raise

def main():
    """Punto de entrada principal"""
    parser = argparse.ArgumentParser(description='NAST - Network Analysis & Security Tool')
    
    # Argumentos principales
    parser.add_argument('--target', help='Target to scan')
    parser.add_argument('--interface', help='Network interface')
    parser.add_argument('--output', help='Output file')
    
    # Módulos y modos
    parser.add_argument('--modules', nargs='+', 
                      default=['network'],
                      choices=['network', 'recon', 'vuln', 'traffic', 'ctf'],
                      help='Modules to run')
    parser.add_argument('--mode', choices=['stealth', 'aggressive', 'ctf'],
                      default='stealth', help='Operation mode')
    
    # Opciones adicionales
    parser.add_argument('--anonymous', action='store_true',
                      help='Enable anonymous mode')
    parser.add_argument('--deep-scan', action='store_true',
                      help='Perform deep scan')
    
    args = parser.parse_args()
    
    # Iniciar engine y ejecutar
    engine = NASTEngine()
    try:
        results = asyncio.run(engine.run_scan(args))
        if not args.output:
            engine.console.print(results)
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()