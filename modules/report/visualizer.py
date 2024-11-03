# modules/report/visualizer.py
import matplotlib.pyplot as plt
import networkx as nx
from typing import Dict, List
import base64
from io import BytesIO

class ReportVisualizer:
    """Generador de visualizaciones para reportes"""
    
    def generate_network_graph(self, data: Dict) -> str:
        """Genera gráfico de red"""
        G = nx.Graph()
        
        # Añadir nodos
        for host, info in data['hosts'].items():
            G.add_node(host, **info)
            
        # Añadir conexiones
        for conn in data.get('connections', []):
            G.add_edge(conn['source'], conn['destination'])
            
        # Crear visualización
        plt.figure(figsize=(12, 8))
        pos = nx.spring_layout(G)
        nx.draw(G, pos, with_labels=True, node_color='lightblue',
                node_size=1500, font_size=8)
                
        # Convertir a base64
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        plt.close()
        
        return base64.b64encode(buffer.getvalue()).decode()
        
    def generate_vulnerability_chart(self, vulns: List[Dict]) -> str:
        """Genera gráfico de vulnerabilidades"""
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0
        }
        
        for vuln in vulns:
            severity = vuln.get('severity', 'Low')
            severity_counts[severity] += 1
            
        # Crear gráfico
        plt.figure(figsize=(10, 6))
        plt.bar(severity_counts.keys(), severity_counts.values(),
                color=['red', 'orange', 'yellow', 'green'])
        plt.title('Vulnerabilities by Severity')
        plt.ylabel('Count')
        
        # Convertir a base64
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        plt.close()
        
        return base64.b64encode(buffer.getvalue()).decode()
        
    def generate_traffic_analysis(self, traffic_data: Dict) -> str:
        """Genera visualización de análisis de tráfico"""
        # Preparar datos
        times = [t['timestamp'] for t in traffic_data['packets']]
        sizes = [p['size'] for p in traffic_data['packets']]
        
        # Crear gráfico
        plt.figure(figsize=(12, 6))
        plt.plot(times, sizes)
        plt.title('Network Traffic Analysis')
        plt.xlabel('Time')
        plt.ylabel('Packet Size')
        plt.xticks(rotation=45)
        
        # Convertir a base64
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        plt.close()
        
        return base64.b64encode(buffer.getvalue()).decode()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Report Generator')
    parser.add_argument('--data', required=True, help='Input data file')
    parser.add_argument('--format', choices=['html', 'json', 'markdown'],
                      default='html', help='Output format')
    parser.add_argument('--output', help='Output file')
    args = parser.parse_args()
    
    # Cargar datos
    with open(args.data) as f:
        data = json.load(f)
        
    # Generar reporte
    generator = ReportGenerator()
    generator.generate_report(data, args.format, args.output)

if __name__ == "__main__":
    main()