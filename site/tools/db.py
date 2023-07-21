# module db.py in your program
from psycopg_pool import ConnectionPool

def get_pool(conninfo = "host=localhost port=5432 dbname=tls_clienthellos13 user=postgres password=lQ9JM9dC9Y connect_timeout=10"):
    return ConnectionPool(conninfo)
