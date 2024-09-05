import re

def sanitize_log(log_string):
    patterns = [
        (r'(password=)[^&,\s]+', r'\1*****'),
        (r'(token=)[^&,\s]+', r'\1*****'),
        (r'(email=)[^&,\s]+@[^&,\s]+', r'\1*****@*****')
    ]
    
    for pattern, replacement in patterns:
        log_string = re.sub(pattern, replacement, log_string)
    
    return log_string
