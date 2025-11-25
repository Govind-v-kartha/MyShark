"""
Custom packet filter language parser and compiler.

Supports:
  - proto:<tcp|udp|icmp|arp>
  - port:<number>
  - ip:<address>
  - Boolean operators: and, or, not
  - Parentheses for grouping
"""

import re
from typing import Callable, Any, List, Tuple, Optional


class ParseError(Exception):
    """Raised when filter expression parsing fails."""
    pass


class Token:
    """Represents a token in the filter expression."""
    def __init__(self, type_: str, value: str):
        self.type = type_
        self.value = value
    
    def __repr__(self):
        return f"Token({self.type}, {self.value})"


class Lexer:
    """Tokenizes custom filter expressions."""
    
    KEYWORDS = {"and", "or", "not"}
    
    def __init__(self, expr: str):
        self.expr = expr
        self.pos = 0
        self.tokens: List[Token] = []
    
    def tokenize(self) -> List[Token]:
        """Tokenize the expression."""
        while self.pos < len(self.expr):
            self._skip_whitespace()
            if self.pos >= len(self.expr):
                break
            
            ch = self.expr[self.pos]
            
            if ch == "(":
                self.tokens.append(Token("LPAREN", "("))
                self.pos += 1
            elif ch == ")":
                self.tokens.append(Token("RPAREN", ")"))
                self.pos += 1
            else:
                # Try to match keyword or predicate
                self._parse_atom()
        
        return self.tokens
    
    def _skip_whitespace(self):
        while self.pos < len(self.expr) and self.expr[self.pos].isspace():
            self.pos += 1
    
    def _parse_atom(self):
        """Parse keyword or filter predicate."""
        start = self.pos
        
        # Match word characters and : for predicates like proto:tcp
        while self.pos < len(self.expr) and (
            self.expr[self.pos].isalnum() or 
            self.expr[self.pos] in ".:|-"
        ):
            self.pos += 1
        
        atom = self.expr[start:self.pos]
        
        if not atom:
            raise ParseError(f"Unexpected character at position {self.pos}")
        
        if atom.lower() in self.KEYWORDS:
            self.tokens.append(Token("KEYWORD", atom.lower()))
        elif ":" in atom:
            # It's a predicate like proto:tcp or port:80
            self.tokens.append(Token("PREDICATE", atom))
        else:
            raise ParseError(f"Unknown token: {atom}")


class Parser:
    """Parses tokenized filter expressions into an AST."""
    
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.pos = 0
    
    def parse(self) -> Callable:
        """Parse tokens and return a compiled filter function."""
        if not self.tokens:
            return lambda packet: True
        
        ast = self._parse_or()
        
        if self.pos < len(self.tokens):
            raise ParseError(f"Unexpected token at position {self.pos}")
        
        return ast
    
    def _current_token(self) -> Optional[Token]:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return None
    
    def _consume(self, expected_type: Optional[str] = None) -> Token:
        token = self._current_token()
        if token is None:
            raise ParseError("Unexpected end of expression")
        if expected_type and token.type != expected_type:
            raise ParseError(f"Expected {expected_type}, got {token.type}")
        self.pos += 1
        return token
    
    def _parse_or(self) -> Callable:
        """Parse OR expression (lowest precedence)."""
        left = self._parse_and()
        
        while self._current_token() and self._current_token().type == "KEYWORD" and self._current_token().value == "or":
            self._consume()
            right = self._parse_and()
            left = self._make_or(left, right)
        
        return left
    
    def _parse_and(self) -> Callable:
        """Parse AND expression (medium precedence)."""
        left = self._parse_not()
        
        while self._current_token() and self._current_token().type == "KEYWORD" and self._current_token().value == "and":
            self._consume()
            right = self._parse_not()
            left = self._make_and(left, right)
        
        return left
    
    def _parse_not(self) -> Callable:
        """Parse NOT expression (high precedence)."""
        if self._current_token() and self._current_token().type == "KEYWORD" and self._current_token().value == "not":
            self._consume()
            operand = self._parse_not()
            return self._make_not(operand)
        
        return self._parse_primary()
    
    def _parse_primary(self) -> Callable:
        """Parse primary expression (predicate or parenthesized expression)."""
        token = self._current_token()
        
        if token is None:
            raise ParseError("Unexpected end of expression")
        
        if token.type == "LPAREN":
            self._consume()
            expr = self._parse_or()
            self._consume("RPAREN")
            return expr
        elif token.type == "PREDICATE":
            pred_token = self._consume()
            return self._compile_predicate(pred_token.value)
        else:
            raise ParseError(f"Unexpected token: {token}")
    
    @staticmethod
    def _compile_predicate(pred_str: str) -> Callable:
        """Compile a single predicate into a filter function."""
        parts = pred_str.split(":")
        if len(parts) != 2:
            raise ParseError(f"Invalid predicate format: {pred_str}")
        
        key, value = parts
        key = key.lower().strip()
        value = value.lower().strip()
        
        if key == "proto":
            return lambda pkt: _match_proto(pkt, value)
        elif key == "port":
            try:
                port = int(value)
                return lambda pkt: _match_port(pkt, port)
            except ValueError:
                raise ParseError(f"Port must be an integer, got {value}")
        elif key == "ip":
            return lambda pkt: _match_ip(pkt, value)
        else:
            raise ParseError(f"Unknown predicate key: {key}")
    
    @staticmethod
    def _make_and(left: Callable, right: Callable) -> Callable:
        return lambda pkt: left(pkt) and right(pkt)
    
    @staticmethod
    def _make_or(left: Callable, right: Callable) -> Callable:
        return lambda pkt: left(pkt) or right(pkt)
    
    @staticmethod
    def _make_not(operand: Callable) -> Callable:
        return lambda pkt: not operand(pkt)


def _match_proto(packet: Any, proto: str) -> bool:
    """Check if packet matches the given protocol."""
    proto_lower = proto.lower()
    
    try:
        from scapy.layers.inet import TCP, UDP, ICMP
        from scapy.layers.l2 import ARP
        
        if proto_lower == "tcp":
            return packet.haslayer(TCP)
        elif proto_lower == "udp":
            return packet.haslayer(UDP)
        elif proto_lower == "icmp":
            return packet.haslayer(ICMP)
        elif proto_lower == "arp":
            return packet.haslayer(ARP)
        else:
            return False
    except Exception:
        return False


def _match_port(packet: Any, port: int) -> bool:
    """Check if packet matches the given port (src or dst)."""
    try:
        from scapy.layers.inet import TCP, UDP
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            return tcp_layer.sport == port or tcp_layer.dport == port
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            return udp_layer.sport == port or udp_layer.dport == port
        
        return False
    except Exception:
        return False


def _match_ip(packet: Any, ip_addr: str) -> bool:
    """Check if packet matches the given IP address (src or dst)."""
    try:
        from scapy.layers.inet import IP
        
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            return ip_layer.src == ip_addr or ip_layer.dst == ip_addr
        
        return False
    except Exception:
        return False


def compile_custom(expr: str) -> Callable[[Any], bool]:
    """
    Compile a custom filter expression into a callable filter function.
    
    Args:
        expr: Filter expression string (e.g., "proto:tcp and port:80")
    
    Returns:
        A callable that takes a packet and returns True/False
    
    Raises:
        ParseError: If the expression is invalid
    """
    if not expr or not expr.strip():
        return lambda packet: True
    
    lexer = Lexer(expr)
    tokens = lexer.tokenize()
    parser = Parser(tokens)
    return parser.parse()
