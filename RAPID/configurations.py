"""
Configurations for Databases and Accounts used by RAPID
"""


class PostgresConfig():
    db_name = ''
    host = '127.0.0.1'
    port = 5432
    username = ''
    password = ''


class AMQPConfig():
    url = 'amqp://guest:guest@localhost:5672//'


class RapidEmailConfig():
    tls = True
    host = ''
    user = ''
    password = ''
    port = 587


class InternetIdentityCredentials():
    username = ''
    password = ''


class ApiKeys():
    passive_total = ''