# module db.py in your program
from psycopg_pool import ConnectionPool

def get_pool(conninfo = "host=localhost port=5432 dbname=tls_clienthellos13 user=postgres password=lQ9JM9dC9Y connect_timeout=10"):
    return ConnectionPool(conninfo)

import psycopg

class FakeConnPool(object):
    def __init__(self, dbname, user, password, host, port):
        self.dbname = dbname
        self.user = user
        self.password = password
        self.host = host
        self.port = port
    
    def connection(self):
        return psycopg.connect(dbname=self.dbname, user=self.user, password=self.password, host=self.host, port=self.port)
    
    def cursor(self):
        return self.connection().cursor()

def get_fake_pool():
    return FakeConnPool(dbname="tls_clienthellos13", user="postgres", password="lQ9JM9dC9Y", host='localhost', port=5432)