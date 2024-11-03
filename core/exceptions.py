# core/exceptions.py
class NASTException(Exception):
    """Excepción base para NAST"""
    pass

class NetworkError(NASTException):
    """Error en operaciones de red"""
    pass

class ScanError(NASTException):
    """Error en escaneo"""
    pass

class ConfigError(NASTException):
    """Error en configuración"""
    pass

class ModuleError(NASTException):
    """Error en módulo"""
    pass

class DatabaseError(NASTException):
    """Error en base de datos"""
    pass