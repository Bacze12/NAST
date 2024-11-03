# modules/traffic/inspector.py
import re
from typing import Dict, List, Set
import logging
from datetime import datetime, timedelta
from collections import defaultdict

class PacketInspector:
    """Inspector detallado de paquetes"""
    
    def __init__(self):
        self.logger = logging.getLogger('PacketInspector')
        self.patterns = self._load_patterns()
        self.recent_packets = defaultdict(list)
        self.thresholds = self._load_thresholds()
        
    def _load_patterns(self) -> Dict:
        """Carga patrones de detección"""
        return {
            'sql_injection': [
                r"(?i)(union|select|insert|delete|update).*(",
                r"(?i)(\%27)|(\')|(\-\-)|(\%23)|(#)",
                r"(?i)(drop|alter|truncate|rename|insert)"
            ],
            'xss': [
                r"(?i)(<script>|javascript:)",
                r"(?i)(alert|onclick|onload|onerror|onmouseover)",
                r"(?i)(\%3C|\%3E|\%22|\%27|\%3B|\%2C|\%2F)"
            ],
            'shell': [
                r"(?i)(sh|bash|cmd|powershell).*(\s-|\/c\s)",
                r"(?i)(nc|netcat|ncat).*(\s-e|\s-c)",
                r"(?i)(wget|curl).*(\s\||>\s)"
            ],
            'data_exfil': [
                r"(?i)(base64|hex).*(\=|\s)",
                r"(?i)(send|post|upload).*(\.(txt|doc|xls|pdf|zip))",
                r"(?i)(transfer|copy|move).*(\.(dat|bak|tmp))"
            ]
        }
        
    def _load_thresholds(self) -> Dict:
        """Carga umbrales de detección"""
        return {
            'max_packets_per_second': 100,
            'max_connections_per_minute': 60,
            'max_data_transfer': 1000000,  # 1MB
            'suspicious_ports': {80, 443, 22, 3389}
        }
        
    def is_suspicious(self, packet_data: Dict) -> bool:
        """Determina si un paquete es sospechoso"""
        try:
            # Verificar patrones
            if self._check_patterns(packet_data):
                return True
                
            # Verificar comportamiento
            if self._check_behavior(packet_data):
                return True
                
            # Verificar anomalías
            if self._check_anomalies(packet_data):
                return True
                
            return False
            
        except Exception as e:
            self.logger.error(f"Inspection error: {e}")
            return False
            
    def _check_patterns(self, packet_data: Dict) -> bool:
        """Verifica patrones maliciosos"""
        if 'data' not in packet_data:
            return False
            
        content = str(packet_data['data'])
        
        # Verificar cada tipo de patrón
        for pattern_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    self.logger.warning(
                        f"Suspicious pattern detected: {pattern_type}"
                    )
                    return True
                    
        return False
        
    def _check_behavior(self, packet_data: Dict) -> bool:
        """Verifica comportamiento sospechoso"""
        try:
            src = packet_data['src']
            timestamp = datetime.now()
            
            # Almacenar paquete reciente
            self.recent_packets[src].append({
                'timestamp': timestamp,
                'size': packet_data['size']
            })
            
            # Limpiar paquetes antiguos
            self._cleanup_old_packets(src, timestamp)
            
            # Verificar frecuencia
            packets_per_second = len(self.recent_packets[src])
            if packets_per_second > self.thresholds['max_packets_per_second']:
                return True
                
            # Verificar tamaño de transferencia
            total_size = sum(p['size'] for p in self.recent_packets[src])
            if total_size > self.thresholds['max_data_transfer']:
                return True
                
            return False
            
        except Exception as e:
            self.logger.error(f"Behavior check error: {e}")
            return False
            
    def _check_anomalies(self, packet_data: Dict) -> bool:
        """Verifica anomalías estadísticas"""
        try:
            # Verificar puertos sospechosos
            if packet_data.get('layer') == 'TCP':
                sport = packet_data['data']['sport']
                dport = packet_data['data']['dport']
                
                if sport in self.thresholds['suspicious_ports'] or \
                   dport in self.thresholds['suspicious_ports']:
                    # Verificar comportamiento en puerto
                    if self._is_port_scan(packet_data):
                        return True
                        
            return False
            
        except Exception as e:
            self.logger.error(f"Anomaly check error: {e}")
            return False
            
    def _cleanup_old_packets(self, src: str, current_time: datetime):
        """Limpia paquetes antiguos"""
        threshold = current_time - timedelta(seconds=1)
        self.recent_packets[src] = [
            p for p in self.recent_packets[src]
            if p['timestamp'] > threshold
        ]
        
    def _is_port_scan(self, packet_data: Dict) -> bool:
        """Detecta escaneo de puertos"""
        try:
            src = packet_data['src']
            recent = self.recent_packets[src]
            
            if len(recent) < 10:
                return False
                
            # Verificar múltiples puertos en poco tiempo
            ports = set()
            for packet in recent[-10:]:  # Últimos 10 paquetes
                if 'data' in packet and 'dport' in packet['data']:
                    ports.add(packet['data']['dport'])
                    
            return len(ports) > 5  # Más de 5 puertos diferentes
            
        except Exception as e:
            self.logger.error(f"Port scan check error: {e}")
            return False