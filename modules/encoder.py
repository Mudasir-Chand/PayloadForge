import urllib.parse
import base64

def encode_payload(payload, method):
    if method == 'url':
        return urllib.parse.quote(payload)
    elif method == 'base64':
        return base64.b64encode(payload.encode()).decode()
    elif method == 'unicode':
        return ''.join('\\u{:04x}'.format(ord(c)) for c in payload)
    elif method == 'hex':
        return ''.join('\\x{:02x}'.format(ord(c)) for c in payload)
    return payload
