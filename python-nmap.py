import nmap

nm= nmap.PortScanner()

target = "45.33.32.156"
options = "-sV -sC scan_results"

nm.scan(target, arguments=options)

for host in nm.all_hosts():
    print("Host: %s (%s)" % (host, nm[host].hostname()))
    print("State: %s" % nm[host].state())
    for proto in nm[host].all_protocols():
        print("Protocol: %s" % proto)
        port_info= nm[host][proto]
        for port in lport,state in port_info.items():
            print("Port: %s\tState: %s" % (port, state))
            
    print("\n")