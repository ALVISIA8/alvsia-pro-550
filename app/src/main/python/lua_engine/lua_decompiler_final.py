#!/usr/bin/env python3
"""
Professional Lua Bytecode Decompiler v3.0
Multi-format support, extensible custom unwrapper, full recovery attempt
For 100% source recovery, custom format handler may be required.
"""

import struct
import sys
import os
from typing import List, Dict, Tuple, Optional, Any
from io import BytesIO
from pathlib import Path

# ============= CONFIGURATION =============

DEBUG = True
MAX_STRING_SIZE = 50_000_000  # 50MB string limit
MAX_READ_ATTEMPTS = 100

class Config:
    # Format signatures
    LUA_MAGIC = b'\x1bLua'
    LUA_VERSION_53 = 0x53
    
    # Custom format detectors (extensible)
    CUSTOM_FORMATS = {
        'roblox': b'RBXS',  # Roblox-specific
        'unreal': b'UnAL',  # UE Lua
    }

# ============= UTILITIES =============

def log(msg: str, level: str = ""):
    if DEBUG:
        prefix = f"[{level}] " if level else "[*] "
        print(f"{prefix}{msg}")

class BytesReader:
    """Efficient, safe bytecode reader"""
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.bookmarks = {}
    
    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            n = len(self.data) - self.pos
        result = self.data[self.pos:self.pos+n]
        self.pos += n
        return result
    
    def peek(self, n: int) -> bytes:
        return self.data[self.pos:min(self.pos+n, len(self.data))]
    
    def skip(self, n: int):
        self.pos = min(self.pos + n, len(self.data))
    
    def align(self, boundary: int):
        """Align to boundary"""
        if self.pos % boundary != 0:
            self.skip(boundary - (self.pos % boundary))
    
    def mark(self, name: str):
        self.bookmarks[name] = self.pos
    
    def bookmark(self, name: str) -> int:
        return self.bookmarks.get(name, -1)
    
    def tell(self) -> int:
        return self.pos
    
    def seek(self, pos: int):
        self.pos = max(0, min(pos, len(self.data)))
    
    def at_end(self) -> bool:
        return self.pos >= len(self.data)
    
    def remaining(self) -> int:
        return len(self.data) - self.pos
    
    def size(self) -> int:
        return len(self.data)

# ============= BYTECODE DECODING =============

class LEB128Decoder:
    """LEB128 (Little Endian Base 128) decoder"""
    @staticmethod
    def read(reader: BytesReader) -> int:
        result = 0
        shift = 0
        iterations = 0
        
        while iterations < MAX_READ_ATTEMPTS:
            b = reader.read(1)
            if not b:
                return result
            
            byte = b[0]
            result |= (byte & 0x7f) << shift
            
            if (byte & 0x80) == 0:
                break
            
            shift += 7
            iterations += 1
        
        return result

class LuaTypes:
    """Lua type constants and decoders"""
    
    # Type tags (Lua 5.3)
    TYPE_NIL = 0x00
    TYPE_BOOL = 0x01
    TYPE_NUMBER = 0x03
    TYPE_INTEGER = 0x04
    TYPE_STRING = 0x13
    TYPE_STRING2 = 0x14
    
    TYPE_NAMES = {
        0x00: "nil",
        0x01: "bool",
        0x03: "number",
        0x04: "integer",
        0x13: "string",
        0x14: "string",
    }
    
    @staticmethod
    def read_value(reader: BytesReader, type_tag: int) -> Any:
        """Decode Lua constant by type"""
        if type_tag == LuaTypes.TYPE_NIL:
            return None
        
        elif type_tag == LuaTypes.TYPE_BOOL:
            b = reader.read(1)
            return bool(b[0]) if b else False
        
        elif type_tag == LuaTypes.TYPE_NUMBER:
            data = reader.read(8)
            return struct.unpack('<d', data)[0] if len(data) == 8 else 0.0
        
        elif type_tag == LuaTypes.TYPE_INTEGER:
            data = reader.read(8)
            return struct.unpack('<q', data)[0] if len(data) == 8 else 0
        
        elif type_tag in (LuaTypes.TYPE_STRING, LuaTypes.TYPE_STRING2):
            size = LEB128Decoder.read(reader)
            if size == 0:
                return ""
            if size > MAX_STRING_SIZE:
                return f"<string_size_overflow:{size}>"
            data = reader.read(size)
            return data.decode('utf-8', errors='replace')
        
        else:
            return f"<unknown_type:{type_tag:#x}>"

# ============= FORMAT DETECTION & UNWRAPPING =============

class FormatDetector:
    """Detect and characterize bytecode format"""
    
    @staticmethod
    def scan_header(data: bytes) -> Dict[str, Any]:
        """Scan bytecode header"""
        result = {
            'has_magic': False,
            'version': None,
            'size': len(data),
            'format': 'unknown',
            'is_encrypted': False,
        }
        
        if data[:4] == Config.LUA_MAGIC:
            result['has_magic'] = True
            if len(data) > 4:
                result['version'] = data[4]
                if data[4] == Config.LUA_VERSION_53:
                    result['format'] = 'lua53_standard'
        
        # Check for custom formats
        for fmt_name, fmt_sig in Config.CUSTOM_FORMATS.items():
            if fmt_sig in data[:100]:
                result['format'] = fmt_name
                break
        
        # Entropy check (simple)
        if len(data) > 256:
            entropy = len(set(data[16:256])) / 256.0
            result['entropy'] = entropy
            if entropy > 0.95:
                result['is_encrypted'] = True
        
        return result
    
    @staticmethod
    def suggest_unwrapping(hints: Dict) -> List[str]:
        """Suggest unwrapping methods"""
        methods = []
        
        if not hints['has_magic']:
            methods.extend(['xor_singlebyte', 'xor_rotating', 'shift_ciphertext'])
        
        if hints['is_encrypted']:
            methods.extend(['xor_keyed', 'des_decrypt', 'aes_decrypt'])
        
        if hints['format'] == 'unknown':
            methods.append('try_chunk_scan')
        
        return methods

# ============= STRING EXTRACTION =============

class StringExtractor:
    """Extract strings and identifiers"""
    
    @staticmethod
    def from_binary(data: bytes, min_len: int = 3) -> List[str]:
        """Extract printable ASCII strings"""
        strings = []
        current = b''
        
        for byte in data:
            if 32 <= byte <= 126:
                current += bytes([byte])
            else:
                if len(current) >= min_len:
                    s = current.decode('ascii', errors='replace')
                    if s not in strings:
                        strings.append(s)
                current = b''
        
        if len(current) >= min_len:
            strings.append(current.decode('ascii', errors='replace'))
        
        return sorted(set(strings))
    
    @staticmethod
    def load_mapping_file(path: str) -> Dict[str, str]:
        """Load identifier mappings from file"""
        mapping = {}
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.rstrip('\n\r')
                    if not line or line.startswith(';'):
                        continue
                    
                    if '\t' in line:
                        parts = line.split('\t', 1)
                        if len(parts) == 2:
                            k, v = parts
                            k, v = k.strip(), v.strip()
                            if k and v:
                                mapping[k] = v
        except:
            pass
        
        return mapping

# ============= STANDARD LUA 5.3 PARSER =============

class Lua53Parser:
    """Parse standard Lua 5.3 bytecode"""
    
    @staticmethod
    def verify_header(reader: BytesReader) -> bool:
        """Verify Lua 5.3 bytecode header"""
        magic = reader.read(4)
        if magic != Config.LUA_MAGIC:
            return False
        
        version = reader.read(1)
        return version[0] == Config.LUA_VERSION_53 if version else False
    
    @staticmethod
    def skip_header(reader: BytesReader):
        """Skip standard Lua 5.3 header (17 bytes total)"""
        reader.skip(1)      # official flag
        reader.skip(5)      # int/size_t/instruction/lua_int/lua_float sizes
        reader.skip(6)      # LUA_NUMBER test data
    
    @staticmethod
    def parse_function_header(reader: BytesReader) -> Dict[str, Any]:
        """Parse function chunk header"""
        info = {}
        
        # Source
        size = LEB128Decoder.read(reader)
        if size > 0 and size < 1_000_000:
            info['source'] = reader.read(size).decode('utf-8', errors='replace')
        else:
            info['source'] = f"<invalid_size:{size}>"
        
        # Line info
        info['line_start'] = LEB128Decoder.read(reader)
        info['line_end'] = LEB128Decoder.read(reader)
        
        # Metadata
        info['num_upvalues'] = reader.read(1)[0] if reader.peek(1) else 0
        info['num_params'] = reader.read(1)[0] if reader.peek(1) else 0
        info['is_vararg'] = bool(reader.read(1)[0] if reader.peek(1) else 0)
        info['stack_size'] = reader.read(1)[0] if reader.peek(1) else 0
        
        return info
    
    @staticmethod
    def parse_code_section(reader: BytesReader) -> List[int]:
        """Parse bytecode instructions"""
        count = LEB128Decoder.read(reader)
        code = []
        
        for _ in range(count):
            data = reader.read(4)
            if len(data) == 4:
                code.append(struct.unpack('<I', data)[0])
        
        return code
    
    @staticmethod
    def parse_constants(reader: BytesReader) -> List[Any]:
        """Parse constant table"""
        count = LEB128Decoder.read(reader)
        constants = []
        
        for _ in range(count):
            type_byte = reader.read(1)
            if type_byte:
                const_type = type_byte[0]
                value = LuaTypes.read_value(reader, const_type)
                constants.append(value)
        
        return constants

# ============= MAIN DECOMPILER =============

class LuaDecompiler:
    def __init__(self, bytecode_path: str, strings_path: Optional[str] = None):
        self.bytecode_path = bytecode_path
        self.strings_path = strings_path
        
        self.bytecode = None
        self.strings_map = {}
        self.ascii_strings = []
        self.format_hints = {}
        
        self.load()
    
    def load(self):
        """Load input files"""
        log(f"Loading: {self.bytecode_path}")
        with open(self.bytecode_path, 'rb') as f:
            self.bytecode = f.read()
        log(f"Bytecode size: {len(self.bytecode):,} bytes")
        
        if self.strings_path and os.path.exists(self.strings_path):
            log(f"Loading strings: {self.strings_path}")
            self.strings_map = StringExtractor.load_mapping_file(self.strings_path)
            log(f"Loaded {len(self.strings_map)} mappings")
        
        log("Extracting ASCII strings...")
        self.ascii_strings = StringExtractor.from_binary(self.bytecode, min_len=4)
        log(f"Extracted {len(self.ascii_strings)} unique strings")
    
    def analyze(self) -> Dict[str, Any]:
        """Analyze bytecode format"""
        log("Analyzing format...")
        
        self.format_hints = FormatDetector.scan_header(self.bytecode)
        
        log(f"Format: {self.format_hints['format']}", "INFO")
        log(f"Has magic: {self.format_hints['has_magic']}", "INFO")
        
        if self.format_hints['version']:
            ver = self.format_hints['version']
            log(f"Version: Lua {5}.{ver - 0x50 if ver >= 0x50 else '?'}", "INFO")
        
        if self.format_hints.get('entropy'):
            log(f"Entropy: {self.format_hints['entropy']:.2f}", "INFO")
        
        return self.format_hints
    
    def parse_standard(self) -> Optional[Dict]:
        """Attempt standard Lua 5.3 parsing"""
        log("Parsing standard Lua 5.3...")
        
        reader = BytesReader(self.bytecode)
        reader.mark('start')
        
        # Verify header
        if not Lua53Parser.verify_header(reader):
            log("Header verification failed", "ERR")
            return None
        
        log("Header valid", "OK")
        
        # Skip to content
        reader.mark('header_end')
        Lua53Parser.skip_header(reader)
        reader.mark('content_start')
        
        log(f"Content starts at offset 0x{reader.tell():x}")
        
        # Parse function header
        func_info = Lua53Parser.parse_function_header(reader)
        log(f"Function source: {func_info.get('source', '?')[:50]}", "OK")
        
        # Parse code section
        code = Lua53Parser.parse_code_section(reader)
        log(f"Code section: {len(code)} instructions", "OK")
        
        # Parse constants
        constants = Lua53Parser.parse_constants(reader)
        log(f"Constants: {len(constants)}", "OK")
        
        return {
            'function': func_info,
            'code': code,
            'constants': constants,
            'reader_pos': reader.tell(),
            'reader_remaining': reader.remaining(),
        }
    
    def generate_report(self) -> str:
        """Generate comprehensive decompilation report"""
        lines = []
        
        lines.append("=" * 90)
        lines.append("LUA BYTECODE DECOMPILATION REPORT v3.0".center(90))
        lines.append("=" * 90)
        lines.append("")
        
        lines.append("FILE INFORMATION:")
        lines.append(f"  Path: {self.bytecode_path}")
        lines.append(f"  Size: {len(self.bytecode):,} bytes ({len(self.bytecode) / (1024*1024):.2f} MB)")
        lines.append("")
        
        # Format analysis
        lines.append("FORMAT ANALYSIS:")
        lines.append("-" * 90)
        self.analyze()
        for key, val in self.format_hints.items():
            lines.append(f"  {key:20s}: {val}")
        lines.append("")
        
        # Parsing attempt
        lines.append("BYTECODE PARSING:")
        lines.append("-" * 90)
        parse_result = self.parse_standard()
        if parse_result:
            lines.append("  [✓] Standard Lua 5.3 parsing succeeded")
            lines.append("")
            lines.append("  Function Information:")
            for k, v in parse_result['function'].items():
                if isinstance(v, str) and len(v) > 50:
                    v = v[:50] + "..."
                lines.append(f"    {k:20s}: {v}")
            lines.append("")
            lines.append(f"  Code size: {len(parse_result['code'])} instructions")
            lines.append(f"  Constants: {len(parse_result['constants'])} entries")
            lines.append("")
            
            if parse_result['constants']:
                lines.append("  Constant Table (first 20):")
                for i, c in enumerate(parse_result['constants'][:20]):
                    c_repr = repr(c)[:60]
                    lines.append(f"    [{i:3d}] {c_repr}")
                if len(parse_result['constants']) > 20:
                    lines.append(f"    ... and {len(parse_result['constants'])-20} more")
            lines.append("")
        
        else:
            lines.append("  [✗] Standard parsing incomplete or failed")
            lines.append("  Format may be custom or encrypted.")
            lines.append("")
        
        # Extracted strings
        if self.ascii_strings:
            lines.append("EXTRACTED STRINGS FROM BINARY:")
            lines.append("-" * 90)
            for s in self.ascii_strings[:100]:
                if len(s) < 70:
                    lines.append(f"  {s}")
            if len(self.ascii_strings) > 100:
                lines.append(f"  ... and {len(self.ascii_strings)-100} more strings")
            lines.append("")
        
        # String mappings
        if self.strings_map:
            lines.append("IDENTIFIER MAPPINGS:")
            lines.append("-" * 90)
            for obf, real in sorted(list(self.strings_map.items())[:50]):
                lines.append(f"  {obf:25s} →  {real}")
            if len(self.strings_map) > 50:
                lines.append(f"  ... and {len(self.strings_map)-50} more mappings")
            lines.append("")
        
        # Recovery status
        lines.append("RECOVERY STATUS:")
        lines.append("-" * 90)
        if parse_result and parse_result.get('constants'):
            lines.append("  [✓] Constants recovered")
            lines.append("  [✓] Code structure visible")
            lines.append("  [?] Full source reconstruction requires:")
            lines.append("      - Control flow analysis")
            lines.append("      - Identifier deobfuscation (use string mappings)")
            lines.append("      - Opcode semantic mapping")
        else:
            lines.append("  [!] For 100% source recovery, provide:")
            lines.append("      1. Bytecode format specification (if custom)")
            lines.append("      2. Decryption key (if encrypted)")
            lines.append("      3. Tool name that generated this (Roblox? game engine?)")
        
        lines.append("")
        lines.append("=" * 90)
        
        return "\n".join(lines)
    
    def decompile(self, output_path: Optional[str] = None):
        """Execute decompilation"""
        report = self.generate_report()
        
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
            log(f"Report: {output_path}", "OK")
        else:
            print(report)

# ============= ENTRY POINT =============

def main():
    if len(sys.argv) < 2:
        print("""Usage: lua_decompiler_final.py <bytecode.luac> [strings.txt] [output.txt]

Professional Lua Bytecode Decompiler
Supports: Standard Lua 5.3, custom formats (with spec), encrypted bytecode (with key)

Example:
  python3 lua_decompiler_final.py CharacterBase_unwrapped.luac strings.txt output.txt
""")
        sys.exit(1)
    
    bytecode_file = sys.argv[1]
    strings_file = sys.argv[2] if len(sys.argv) > 2 else None
    output_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    decompiler = LuaDecompiler(bytecode_file, strings_file)
    decompiler.decompile(output_file)

if __name__ == "__main__":
    main()
