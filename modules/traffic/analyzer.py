# modules/traffic/analyzer.py
import scapy.all as scapy
from scapy.layers import http
from scapy.layers.inet import IP, TCP, UDP, ICMP
import asyncio
from collections import defaultdict
import logging
import json
from datetime import datetime
import threading
import queue
from typing import Dict, List, Set, Optional
from .inspector import PacketInspector

class TrafficAnalyzer:
    """Analizador avanzado de tráfico de red"""
    
    def __init__(self, interface: str):
        self.interface = interface
        self.logger = logging.getLogger('TrafficAnalyzer')
        self.packet_inspector = PacketInspector()
        self.initialize_analyzers()
        self.setup_queues()
        
    def initialize_analyzers(self):
        """Inicializa analizadores específicos"""
        self.connections = defaultdict(list)
        self.protocols = defaultdict(int)
        self.hosts = defaultdict(int)
        self.suspicious_traffic = []
        self.alerts = []
        
    def setup_queues(self):
        """Configura colas de procesamiento"""
        self.packet_queue = queue.Queue()
        self.analysis_queue = queue.Queue()
        self.should_stop = threading.Event()
        
    def start_capture(self, filter_str: str = None):
        """Inicia captura de tráfico"""
        try:
            # Iniciar hilos de procesamiento
            self.processing_thread = threading.Thread(
                target=self._process_packets
            )
            self.analysis_thread = threading.Thread(
                target=self._analyze_packets
            )
            
            self.processing_thread.daemon = True
            self.analysis_thread.daemon = True
            
            self.processing_thread.start()
            self.analysis_thread.start()
            
            # Iniciar captura
            scapy.sniff(
                iface=self.interface,
                filter=filter_str,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda _: self.should_stop.is_set()
            )
            
        except Exception as e:
            self.logger.error(f"Capture error: {e}")
            raise
            
    def stop_capture(self):
        """Detiene captura de tráfico"""
        self.should_stop.set()
        self.processing_thread.join()
        self.analysis_thread.join()
        
    def _packet_callback(self, packet):
        """Callback para cada paquete capturado"""
        try:
            self.packet_queue.put(packet)
        except Exception as e:
            self.logger.error(f"Packet callback error: {e}")
            
    def _process_packets(self):
        """Procesa paquetes en cola"""
        while not self.should_stop.is_set():
            try:
                packet = self.packet_queue.get(timeout=1)
                if IP in packet:
                    processed_data = self._process_packet(packet)
                    if processed_data:
                        self.analysis_queue.put(processed_data)
                        
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Packet processing error: {e}")
                
    def _process_packet(self, packet) -> Optional[Dict]:
        """Procesa paquete individual"""
        try:
            # Información básica
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'proto': packet[IP].proto,
                'size': len(packet),
                'layer': None,
                'data': {}
            }
            
            # Análisis por protocolo
            if TCP in packet:
                packet_info.update(self._process_tcp(packet))
            elif UDP in packet:
                packet_info.update(self._process_udp(packet))
            elif ICMP in packet:
                packet_info.update(self._process_icmp(packet))
                
            # Análisis de capa de aplicación
            if http.HTTP in packet:
                packet_info.update(self._process_http(packet))
                
            return packet_info
            
        except Exception as e:
            self.logger.error(f"Packet processing error: {e}")
            return None
            
    def _process_tcp(self, packet) -> Dict:
        """Procesa paquete TCP"""
        return {
            'layer': 'TCP',
            'data': {
                'sport': packet[TCP].sport,
                'dport': packet[TCP].dport,
                'flags': packet[TCP].flags,
                'seq': packet[TCP].seq,
                'ack': packet[TCP].ack
            }
        }
        
    def _process_udp(self, packet) -> Dict:
        """Procesa paquete UDP"""
        return {
            'layer': 'UDP',
            'data': {
                'sport': packet[UDP].sport,
                'dport': packet[UDP].dport,
                'len': packet[UDP].len
            }
        }
        
    def _process_http(self, packet) -> Dict:
        """Procesa paquete HTTP"""
        http_data = {
            'layer': 'HTTP',
            'data': {}
        }
        
        if http.HTTPRequest in packet:
            http_data['data'] = {
                'method': packet[http.HTTPRequest].Method.decode(),
                'path': packet[http.HTTPRequest].Path.decode(),
                'headers': dict(packet[http.HTTPRequest].fields)
            }
        elif http.HTTPResponse in packet:
            http_data['data'] = {
                'status_code': packet[http.HTTPResponse].Status_Code,
                'reason': packet[http.HTTPResponse].Reason,
                'headers': dict(packet[http.HTTPResponse].fields)
            }
            
        return http_data
        
    def _analyze_packets(self):
        """Analiza paquetes procesados"""
        while not self.should_stop.is_set():
            try:
                packet_data = self.analysis_queue.get(timeout=1)
                
                # Actualizar estadísticas
                self._update_statistics(packet_data)
                
                # Detectar anomalías
                if self.packet_inspector.is_suspicious(packet_data):
                    self._handle_suspicious_traffic(packet_data)
                    
                # Análisis de patrones
                self._analyze_patterns(packet_data)
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Packet analysis error: {e}")
                
    def _update_statistics(self, packet_data: Dict):
        """Actualiza estadísticas de tráfico"""
        # Protocolos
        self.protocols[packet_data['layer']] += 1
        
        # Hosts
        self.hosts[packet_data['src']] += 1
        self.hosts[packet_data['dst']] += 1
        
        # Conexiones
        conn_key = f"{packet_data['src']}:{packet_data['dst']}"
        self.connections[conn_key].append(packet_data)
        
    def _handle_suspicious_traffic(self, packet_data: Dict):
        """Maneja tráfico sospechoso"""
        self.suspicious_traffic.append(packet_data)
        
        # Generar alerta
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': 'suspicious_traffic',
            'source': packet_data['src'],
            'destination': packet_data['dst'],
            'details': packet_data
        }
        
        self.alerts.append(alert)
        self.logger.warning(f"Suspicious traffic detected: {alert}")
        
    def _analyze_patterns(self, packet_data: Dict):
        """Analiza patrones en el tráfico"""
        # Analizar comportamiento
        if self._is_scanning_behavior(packet_data):
            self._handle_scanning_detection(packet_data)
            
        # Analizar data exfiltration
        if self._is_data_exfiltration(packet_data):
            self._handle_data_exfiltration(packet_data)
            
    def get_statistics(self) -> Dict:
        """Obtiene estadísticas del análisis"""
        return {
            'total_packets': sum(self.protocols.values()),
            'protocols': dict(self.protocols),
            'top_hosts': dict(sorted(
                self.hosts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            'suspicious_count': len(self.suspicious_traffic),
            'alerts': len(self.alerts)
        }