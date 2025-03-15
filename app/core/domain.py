import re
import socket
import whois
import concurrent.futures
from functools import wraps
from typing import Tuple, Dict, Any, Optional

def is_valid_domain_name(domain: str) -> bool:
    """Validate domain name format."""
    if not domain or not isinstance(domain, str):
        return False
        
    # Clean input
    domain = domain.strip().lower()
    
    # Basic validation
    if not domain or len(domain) > 63:
        return False
        
    # Check for invalid characters first
    if re.search(r'[^a-z0-9-]', domain):
        return False
        
    # Must start and end with alphanumeric
    if domain.startswith('-') or domain.endswith('-'):
        return False
        
    # Check for consecutive hyphens
    if '--' in domain:
        return False
        
    # Final regex check for overall format
    return bool(re.match(r'^[a-z0-9][a-z0-9-]*[a-z0-9]$', domain))

def is_valid_tld(tld: str) -> bool:
    """Validate TLD format."""
    if not tld or not isinstance(tld, str):
        return False
        
    # Clean input
    tld = tld.strip().lstrip('.').lower()
    
    # Basic validation
    if not tld or len(tld) < 2:
        return False
        
    # Check for invalid characters first
    if re.search(r'[^a-z]', tld):
        return False
        
    # Final regex check for overall format
    return bool(re.match(r'^[a-z]{2,}$', tld))

def clean_domain_input(domain_name: str, tld: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Clean and validate domain input."""
    if not domain_name:
        return None, None, "Missing domain parameter"
        
    # Clean inputs
    domain_name = domain_name.strip().lower()
    
    # Handle TLD
    if tld is None:
        tld = "com"  # Use default TLD if none provided
    else:
        tld = tld.strip().lstrip('.').lower()
        if not tld:  # Empty string after cleaning
            return None, None, "Invalid TLD format"
    
    # Validate domain name
    if not is_valid_domain_name(domain_name):
        return None, None, "Invalid domain name format"
        
    # Validate TLD if not using default
    if tld != "com" and not is_valid_tld(tld):
        return None, None, "Invalid TLD format"
        
    return domain_name, tld, None

def with_timeout(timeout: int):
    """Decorator to add timeout to functions."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            result = {"status": "error", "error": "Timeout"}
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(func, *args, **kwargs)
                try:
                    result = future.result(timeout=timeout)
                except concurrent.futures.TimeoutError:
                    return "timeout"
                except Exception as e:
                    return "error"
            return result
        return wrapper
    return decorator

@with_timeout(5)  # 5 seconds timeout
def check_whois(domain: str) -> Dict[str, Any]:
    """Check WHOIS for domain availability."""
    try:
        w = whois.whois(domain)
        if w.domain_name:
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            return {
                "status": "taken",
                "expiration_date": expiration_date.strftime("%Y-%m-%d") if expiration_date else None,
                "registrar": w.registrar
            }
        return {"status": "available"}
    except whois.parser.PywhoisError:
        return {"status": "available"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

@with_timeout(3)  # 3 seconds timeout
def check_dns(domain: str) -> Dict[str, Any]:
    """Check DNS resolution for domain availability."""
    try:
        ip = socket.gethostbyname(domain)
        return {"status": "taken", "ip": ip}
    except socket.gaierror:
        return {"status": "available"}
    except Exception as e:
        return {"status": "error", "error": str(e)} 