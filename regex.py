
import re
from typing import List

def compile_regex_patterns() -> List[re.Pattern]:
    """
    Compile and return a list of regex patterns to match against strings.

    :rtype: List[re.Pattern]
    """
    tldstr = '|'.join(['com', 'org', 'net', 'bit', 'dev', 'onion'])  # Example TLDs, replace with actual list
    fqdn_base = r'(([a-z0-9_-]{1,63}\.){1,10}(%s))' % tldstr
    fqdn_str = fqdn_base + r'(?:\W|$)'

    patterns = [
        re.compile(r'^[A-Fa-f0-9]{32}$'),  # MD5
        re.compile(r'^[A-Fa-f0-9]{40}$'),  # SHA1
        re.compile(r'^[A-Fa-f0-9]{64}$'),  # SHA256
        re.compile(r'\w+://[^ \'"\t\n\r\f\v]+'),  # URL
        re.compile(r'\\\\n$'),  # Line feed
        re.compile(r'[A-Z|a-z]\:\\\\[A-Za-z0-9]'),  # Path
        re.compile(r'\w+\.pdb\b'),  # PDB
        re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89ab][0-9a-fA-F]{3}-[0-9a-fA-F]{12}'),  # GUID
        re.compile(r'On(?!User|Board|Media|Global)(?:[A-Z][a-z]+)+'),  # Event
        re.compile(r'\[[A-Za-z0-9\_\-\+ ]{2,13}\]'),  # Keylogger
        re.compile(r'((0\.([0-5]|9))|(1\.[0-3])|(2\.(([0-2][0-8])|(4[0-2])|(4[8-9])|(5[0-2])|(999))))(\.[0-9])+'),  # OID
        re.compile(r'\w+\.[a-z]{3,4}\b'),  # File extension
        re.compile(r'[0-9]{5}-[0-9A-Z]{3}-[0-9]{7}-[0-9]{5}'),  # Product ID
        re.compile(r'Se[A-Z][A-z]+Privilege'),  # Privilege
        re.compile(r'[DSO]:.+;;;.+$'),  # SDDL
        re.compile(r'S-(?:[0-5]|9|(11)|(12)|(16))-'),  # SID
        re.compile(r'\s+'),  # Whitespace
        re.compile(r'[^A-Za-z]'),  # Non-letters
        re.compile(r'(?:\(| |^)[A-Z]+(?:\_[A-Z]+)+(?:\)| |$)'),  # Uppercase variable name
        re.compile(r'(?:\(| |^)[a-z]{2,}(?:\.[a-z]{2,})+(?:\)| |$)'),  # Period delimited variable name
        re.compile(fqdn_str, re.I),  # FQDN
        re.compile(r'^' + fqdn_base + r'$', re.I),  # Strict FQDN
        re.compile(r'([a-z0-9_\.\-+]{1,256}@%s)' % fqdn_base, re.I),  # Email
        re.compile(r'(?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])(?:\.(?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])){3}'),  # IPv4
        re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):[0-9]{1,5}'),  # Service
        re.compile(r'-----BEGIN ([a-zA-Z0-9 ]+)-----'),  # PKCS
        re.compile(r'%[-|\+|#|0]?([\*|0-9])?(\.[\*|0-9])?[h|l|j|z|t|L]?[diuoxXfFeEgGaAcspn%]'),  # Format specifier
        re.compile(r'\b(?:[a-z]?upx|[A-Z]?UPX)(?:\d|\b)'),  # UPX
        re.compile(r'\b(?:rsa|aes|rc4|salt|md5)\b'),  # Crypto common
        re.compile(r'[\w\-]+\/[\w\-]+\.[\w\-]+(?:\.[\w\-])* ?(?:\[[a-z]{2}\] )?\((?:.+[:;\-].+|[+ ]?http://.+)\)'),  # User agents
        re.compile(r'[^0-9a-zA-Z](?:hkcu|hklm|hkey\_current\_user|hkey\_local\_machine)[^0-9a-zA-Z]'),  # Hive
        re.compile(r'\\\\\.\\.*'),  # Namespace
        re.compile(r'Word\.Document'),  # MS Word
        re.compile(r'PR\_(?:[A-Z][a-z]{2,})+'),  # Mozilla API
        re.compile(r'SE\_(?:[A-Z]+\_)+NAME'),  # Privilege constant
        re.compile(r'\b[A-Za-z0-9]+\{[^}]+\}'),  # Flag
        re.compile(r'\b\w+\.(?:bin|exe|ps1|batch|sh|pdf|docx|zip|tar|tar\.gz|7z|rar|gz|png|jpg|jpeg|txt|log|iso|dmg|pkg|deb|rpm|apk|msi|py|js|html|css|json|xml|sql|db|bak|conf|ini|yml|yaml|md)\b', re.IGNORECASE),  # Noms de fichiers
    ]
    return patterns