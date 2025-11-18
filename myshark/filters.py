"""
Custom filter parser and compiler for post-capture packet filtering.

Supports a simple domain-specific language (DSL):
  - proto:<tcp|udp|icmp|arp>     : Match protocol type
  - port:<number>                 : Match source or destination port
  - ip:<address>                  : Match source or destination IP
  - Boolean operators: and, or, not, parentheses ()

Example: proto:tcp and (port:80 or port:443) and not ip:192.168.1.1
"""

import re
from typing import Callable, Dict, Any, Union


class FilterParseError(Exception):
    """Raised when filter expression cannot be parsed."""
    pass


class FilterCompileError(Exception):
    """Raised when filter cannot be compiled to valid checker function."""
    pass


def tokenize(expr: str) -> list[str]:
    """
    Tokenize a custom filter expression.
    
    Args:
        expr: Filter expression string
        
    Returns:
        List of tokens
        
    Raises:
        FilterParseError: If expression contains invalid characters
    """
    expr = expr.strip()
    tokens = []
    i = 0
    while i < len(expr):
        if expr[i].isspace():
            i += 1
        elif expr[i] in '()':
            tokens.append(expr[i])
            i += 1
        elif expr[i:i+3] == 'and':
            if i + 3 < len(expr) and not expr[i+3].isspace() and expr[i+3] not in '()':
                # Part of a larger word, treat as identifier
                j = i
                while j < len(expr) and (expr[j].isalnum() or expr[j] == ':' or expr[j] == '.'):
                    j += 1
                tokens.append(expr[i:j])
                i = j
            else:
                tokens.append('and')
                i += 3
        elif expr[i:i+2] == 'or':
            if i + 2 < len(expr) and not expr[i+2].isspace() and expr[i+2] not in '()':
                # Part of a larger word
                j = i
                while j < len(expr) and (expr[j].isalnum() or expr[j] == ':' or expr[j] == '.'):
                    j += 1
                tokens.append(expr[i:j])
                i = j
            else:
                tokens.append('or')
                i += 2
        elif expr[i:i+3] == 'not':
            if i + 3 < len(expr) and not expr[i+3].isspace() and expr[i+3] not in '()':
                # Part of a larger word
                j = i
                while j < len(expr) and (expr[j].isalnum() or expr[j] == ':' or expr[j] == '.'):
                    j += 1
                tokens.append(expr[i:j])
                i = j
            else:
                tokens.append('not')
                i += 3
        else:
            # Identifier: proto:tcp, port:80, ip:1.2.3.4, etc.
            j = i
            while j < len(expr) and (expr[j].isalnum() or expr[j] in ':.*-_'):
                j += 1
            if i == j:
                raise FilterParseError(f"Invalid character at position {i}: '{expr[i]}'")
            tokens.append(expr[i:j])
            i = j
    return tokens


class FilterParser:
    """Recursive descent parser for custom filter expressions."""
    
    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.pos = 0
    
    def peek(self) -> Union[str, None]:
        """Return current token without consuming."""
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None
    
    def consume(self, expected: Union[str, None] = None) -> str:
        """Consume and return current token."""
        if self.pos >= len(self.tokens):
            raise FilterParseError("Unexpected end of expression")
        token = self.tokens[self.pos]
        if expected and token != expected:
            raise FilterParseError(f"Expected '{expected}', got '{token}'")
        self.pos += 1
        return token
    
    def parse_or(self) -> Callable:
        """Parse or-expression (lowest precedence)."""
        left = self.parse_and()
        while self.peek() == 'or':
            self.consume('or')
            right = self.parse_and()
            left = lambda p, l=left, r=right: l(p) or r(p)
        return left
    
    def parse_and(self) -> Callable:
        """Parse and-expression."""
        left = self.parse_not()
        while self.peek() == 'and':
            self.consume('and')
            right = self.parse_not()
            left = lambda p, l=left, r=right: l(p) and r(p)
        return left
    
    def parse_not(self) -> Callable:
        """Parse not-expression."""
        if self.peek() == 'not':
            self.consume('not')
            expr = self.parse_not()
            return lambda p, e=expr: not e(p)
        return self.parse_atom()
    
    def parse_atom(self) -> Callable:
        """Parse atomic expression (predicate or parenthesized expression)."""
        token = self.peek()
        if token == '(':
            self.consume('(')
            expr = self.parse_or()
            self.consume(')')
            return expr
        elif token:
            return self.parse_predicate()
        else:
            raise FilterParseError("Expected predicate or '('")
    
    def parse_predicate(self) -> Callable:
        """Parse a predicate (proto:tcp, port:80, ip:1.2.3.4, etc.)."""
        token = self.consume()
        return create_predicate(token)


def create_predicate(spec: str) -> Callable:
    """
    Create a predicate function from a spec string.
    
    Args:
        spec: Specification like "proto:tcp", "port:80", "ip:1.2.3.4"
        
    Returns:
        Function that takes a parsed packet dict and returns bool
        
    Raises:
        FilterParseError: If spec format is invalid
    """
    if ':' not in spec:
        raise FilterParseError(f"Invalid predicate format: '{spec}' (expected 'key:value')")
    
    key, value = spec.split(':', 1)
    key = key.lower().strip()
    value = value.strip()
    
    if key == 'proto':
        return create_proto_predicate(value)
    elif key == 'port':
        return create_port_predicate(value)
    elif key == 'ip':
        return create_ip_predicate(value)
    else:
        raise FilterParseError(f"Unknown filter key: '{key}'")


def create_proto_predicate(proto: str) -> Callable:
    """Create predicate to match protocol."""
    proto = proto.lower()
    valid = {'tcp', 'udp', 'icmp', 'arp'}
    if proto not in valid:
        raise FilterParseError(f"Invalid protocol: '{proto}' (expected one of {valid})")
    
    return lambda p: p.get('l4_proto', '').lower() == proto


def create_port_predicate(port_str: str) -> Callable:
    """Create predicate to match port (src or dst)."""
    try:
        port = int(port_str)
    except ValueError:
        raise FilterParseError(f"Invalid port number: '{port_str}'")
    
    if not (0 <= port <= 65535):
        raise FilterParseError(f"Port out of range: {port}")
    
    return lambda p: p.get('sport') == port or p.get('dport') == port


def create_ip_predicate(ip_addr: str) -> Callable:
    """Create predicate to match IP address (src or dst)."""
    # Basic validation: check it looks like an IP
    if not is_valid_ipv4(ip_addr):
        raise FilterParseError(f"Invalid IP address: '{ip_addr}'")
    
    return lambda p: p.get('ip_src') == ip_addr or p.get('ip_dst') == ip_addr


def is_valid_ipv4(addr: str) -> bool:
    """Check if string is a valid IPv4 address."""
    parts = addr.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if not (0 <= num <= 255):
                return False
        except ValueError:
            return False
    return True


def compile_custom(expr: str) -> Callable[[Dict[str, Any]], bool]:
    """
    Compile a custom filter expression into a checker function.
    
    Args:
        expr: Filter expression (e.g., "proto:tcp and port:80")
        
    Returns:
        Function that takes a parsed packet dict and returns True/False
        
    Raises:
        FilterParseError: If expression is invalid
    """
    if not expr or not expr.strip():
        # Empty filter matches everything
        return lambda p: True
    
    tokens = tokenize(expr)
    if not tokens:
        return lambda p: True
    
    parser = FilterParser(tokens)
    predicate = parser.parse_or()
    
    if parser.pos < len(tokens):
        raise FilterParseError(f"Unexpected tokens at position {parser.pos}: {tokens[parser.pos:]}")
    
    return predicate
