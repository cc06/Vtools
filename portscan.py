#portscan module
#sergio@infosegura.net
#ip=ip you want to scan
#port=port number to scan
#timeout=timeout in seconds. Experiment to find optimal timeout in your network. Use a port you know to be closed, and if
# the result is "timeout", increase the value until you get "closed".

from socket import *

status={0:"open",10049:"address not available",10061:"closed",10060:"timeout",10056:"already connected",10035:"filtered",11001:"IP not found",10013:"permission denied"}

def scan(ip,port,timeout):
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(timeout)
        try:
            result= s.connect_ex((ip, port))
        except:
            print "Cannot connect to IP"
            return
        s.close()
        return status[result]
