MVP_SQL_INJECTION_PAYLOADS = (
    "' OR 1=1--",
    "' UNION SELECT 1, name FROM users--",
    "' OR 'a'='a",
    "1; SELECT sleep(5)",
    "admin'/*",
)
