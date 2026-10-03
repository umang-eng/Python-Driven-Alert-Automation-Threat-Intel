import re
import ipaddress
from typing import List, Dict

# Pre-compile regular expressions for maximum performance during bulk processing
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')

def is_public_ip(ip_str: str) -> bool:
    """
    Validates if an IPv4 address is routable and public, filtering out RFC 1918 internal IPs.
    
    >>> is_public_ip('8.8.8.8')
    True
    >>> is_public_ip('192.168.1.5')
    False
    >>> is_public_ip('10.0.0.1')
    False
    >>> is_public_ip('127.0.0.1')
    False
    """
    try:
        ip = ipaddress.IPv4Address(ip_str)
        # is_global checks if it's not private, loopback, or reserved
        return ip.is_global and not ip.is_unspecified
    except ipaddress.AddressValueError:
        return False

def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Scans a block of text for public IPs, MD5, and SHA256 hashes.
    
    >>> text = "Connection from 8.8.8.8 and 10.0.0.2 with hash 44d88612fea8a8f36de82e1278abb02f"
    >>> extract_iocs(text)
    {'ips': ['8.8.8.8'], 'md5': ['44d88612fea8a8f36de82e1278abb02f'], 'sha256': []}
    """
    # Extract raw matches
    raw_ips = IPV4_REGEX.findall(text)
    md5_hashes = MD5_REGEX.findall(text)
    sha256_hashes = SHA256_REGEX.findall(text)

    # Filter out internal IPs
    public_ips = [ip for ip in raw_ips if is_public_ip(ip)]

    return {
        "ips": public_ips,
        "md5": md5_hashes,
        "sha256": sha256_hashes
    }