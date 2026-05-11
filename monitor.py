from ping3 import ping

def get_device_status(ip):
    try:
        response = ping(ip, timeout=1)
        return "Online" if response else "Offline"
    except:
        return "Offline"