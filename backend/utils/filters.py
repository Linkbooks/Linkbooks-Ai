from datetime import datetime

def datetimeformat(value, format='%Y-%m-%d %H:%M:%S'):
    if not value:
        return "N/A"
    return datetime.fromisoformat(value).strftime(format)
