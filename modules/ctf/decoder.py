# modules/ctf/decoder.py
import base64
import binascii
import codecs
import re
from typing import List, Dict
import logging

class DataDecoder:
    """Decodificador de datos para CTF"""
    
    def __init__(self):
        self.logger = logging.getLogger('DataDecoder')
        
    def decode_all(self, data: str) -> List[Dict]:
        """Intenta todas las decodificaciones posibles"""
        results = []
        
        # Base64
        try:
            decoded = base64.b64decode(self._pad_base64(data)).decode()
            results.append({
                'type': 'base64',
                'result': decoded
            })
        except:
            pass
            
        # Hex
        try:
            decoded = bytes.fromhex(data).decode()
            results.append({
                'type': 'hex',
                'result': decoded
            })
        except:
            pass
            
        # ROT13
        try:
            decoded = codecs.decode(data, 'rot_13')
            results.append({
                'type': 'rot13',
                'result': decoded
            })
        except:
            pass
            
        # Binary
        try:
            if all(c in '01 ' for c in data):
                binary = data.replace(' ', '')
                decoded = ''.join(
                    chr(int(binary[i:i+8], 2))
                    for i in range(0, len(binary), 8)
                )
                results.append({
                    'type': 'binary',
                    'result': decoded
                })
        except:
            pass
            
        # Morse Code
        try:
            decoded = self._decode_morse(data)
            if decoded:
                results.append({
                    'type': 'morse',
                    'result': decoded
                })
        except:
            pass
            
        return results
        
    def _pad_base64(self, data: str) -> str:
        """Añade padding a base64 si es necesario"""
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return data
        
    def _decode_morse(self, data: str) -> Optional[str]:
        """Decodifica código Morse"""
        MORSE_CODE = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D',
            '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H',
            '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
            '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P',
            '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
            '-.--': 'Y', '--..': 'Z',
            '-----': '0', '.----': '1', '..---': '2', '...--': '3',
            '....-': '4', '.....': '5', '-....': '6', '--...': '7',
            '---..': '8', '----.': '9'
        }
        
        try:
            return ' '.join(
                MORSE_CODE[symbol] for symbol in data.split()
                if symbol in MORSE_CODE
            )
        except:
            return None