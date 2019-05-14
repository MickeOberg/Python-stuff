import datetime
import OpenSSL
import ssl, socket


def cert_lookup(hostname):
    port = 443

    context = ssl.create_default_context()

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
            der_cert = sslsock.getpeercert(True)
            cert = ssl.DER_cert_to_PEM_cert(der_cert)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
            x509info = x509.get_notAfter()
            ssl_date_fmt = r'%Y%m%d%H%M%SZ'
            expires = datetime.datetime.strptime(str(x509info)[2:-1], ssl_date_fmt)
            remaining = (expires - datetime.datetime.utcnow()).days
            reply = "{} expires in {} days, ({})".format(hostname, remaining, expires)
            return reply
						
						
print(cert_look("google.com")
