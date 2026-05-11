import nmap

def scan_ports(ip):

    results = []

    try:
        nm = nmap.PortScanner()

        print("Starting scan on:", ip)

        nm.scan(hosts=ip, arguments='-Pn')

        if ip not in nm.all_hosts():
            print("Host not found")
            return []

        for proto in nm[ip].all_protocols():

            ports = nm[ip][proto].keys()

            for port in ports:

                service = nm[ip][proto][port]['name']

                results.append({
                    "port": port,
                    "service": service
                })

        return results

    except Exception as e:
        print("Scanner Error:", e)
        return []