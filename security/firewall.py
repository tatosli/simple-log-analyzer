def export_iptables(ips, filename="blacklist_iptables.sh"):
    with open(filename, "w") as f:
        f.write("#!/bin/bash\n\n")
        for ip in ips:
            f.write(f"iptables -A INPUT -s {ip} -j DROP\n")


def export_ufw(ips, filename="blacklist_ufw.txt"):
    with open(filename, "w") as f:
        for ip in ips:
            f.write(f"ufw deny from {ip}\n")
