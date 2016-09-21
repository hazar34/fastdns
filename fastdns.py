import random
import socket
from dns import resolver
from dns.exception import DNSException
from multiprocessing.dummy import Pool as ThreadPool
from requests.packages.urllib3.connection import HTTPConnection


class FastDns:
    resolvers_pool = []
    default_dns = ('8.8.8.8', '8.8.4.4', '208.67.222.222', '208.67.220.220')
    dsnbl_providers = [
        'b.barracudacentral.org',
        'sbl.spamhaus.org',
        'xbl.spamhaus.org',
        'zen.spamhaus.org',
        'pbl.spamhaus.org',
        'bad.psky.me',
        'bl.spamcannibal.org',
        'cbl.abuseat.org'
    ]

    def __init__(self, dns_servers=default_dns, timeout=5, lifetime=10):
        for ip in dns_servers:
            r = resolver.Resolver()
            r.nameservers = [ip]
            r.lifetime = lifetime
            r.timeout = timeout
            self.resolvers_pool.append(r)

    def resolve(self, host):
        try:
            return str(random.choice(self.resolvers_pool).query(str(host).strip(), 'A')[0])
        except (DNSException, KeyError):
            return None

    def check_blacklist(self, ip):
        def process(prov):
            try:
                random.choice(self.resolvers_pool).query('.'.join(reversed(str(ip).split('.'))) + '.' + prov, 'A')
                return prov
            except DNSException:
                return None

        return list(filter(None, ThreadPool(len(self.dsnbl_providers)).map(process, self.dsnbl_providers)))


# ALL urllib3 dns requests via FastDns
def monkey_path_dns(dns_resolver=FastDns()):
    def patched_new_conn(self):
        ip = dns_resolver.resolve(self.host)
        conn = socket.create_connection((ip, self.port), self.timeout, self.source_address)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return conn

    HTTPConnection._new_conn = patched_new_conn
