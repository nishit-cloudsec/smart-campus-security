def get_risk(port):
    if port == 22:
        return "High"
    elif port == 3389:
        return "Critical"
    elif port == 80:
        return "Medium"
    else:
        return "Low"