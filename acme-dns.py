# There's a lack of sample code for acme/Let's Encrypt out there, and
# this is an attempt to at least slightly remedy that.  It's the result
# of my first day's hacking on this stuff, so almost certainly contains
# errors and oversights.
#
# It's not designed to be specifically useful if what you want is
# just a cert -- certbot or dehydrated are better for that.  It is sample
# code for people who are building automated systems to deal with large
# numbers of Let's Encrypt certificates to play with.
#
# request_cert will create a new user on Let's Encrypt's staging server,
# then apply for a certificate for the given domain.  Production systems
# would more probably have a persistent private key for the user; the
# reason this code doesn't is just to make it self-contained.
#
# It only handles HTTP-based verification; when it is ready for you
# to do so, it will present you with a URL where you'll need to serve
# a particular bit of text.
#
# The code is Python 2.7, and needs you to "pip install acme".
#
# See http://www.gilesthomas.com/2018/11/python-code-to-generate-lets-encrypt-certificates/
# for a code walkthrough.

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from OpenSSL import crypto
from OpenSSL.SSL import FILETYPE_PEM
import time
import os.path

from acme import client
from acme import messages
import josepy

DIRECTORY_URL = 'https://acme-staging.api.letsencrypt.org/directory'
KEY_SIZE = 2048


def save_key(jwk, filename):
    save_path = "e:/cert/"
    jwk_file = os.path.join(save_path, filename + ".jwk")
    with open(jwk_file, 'w') as jwk_out:
        jwk_out.write(jwk.json_dumps())


def get_dns_challenge(authzr):
    for challenge in authzr.body.challenges:
        if challenge.chall.typ == 'dns-01':
            return challenge
    else:
        raise Exception("Could not find an DNS challenge!")


def request_cert(domain):
    domain = domain.lower()
    print("Generating user key")
    user_key = josepy.JWKRSA(
        key=rsa.generate_private_key(
            public_exponent=65537,
            key_size=KEY_SIZE,
            backend=default_backend()
        )
    )
    save_key(user_key, domain)
    print("Connecting to Let's Encrypt on {}".format(DIRECTORY_URL))
    acme = client.Client(DIRECTORY_URL, user_key)
    print("Registering")
    regr = acme.register()
    print("Agreeing to ToS")
    acme.agree_to_tos(regr)

    print("Requesting challenges")
    authzr = acme.request_challenges(
        identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=domain)
    )

    print("Looking for DNS challenge")
    challenge = get_dns_challenge(authzr)

    print("You need to set up the challenge response.")
    print("DNS (TXT) record: _acme-challenge.{}".format(domain))
    print("Content: {}".format(challenge.chall.validation(user_key)))

    response = challenge.chall.response(user_key)
    while not response.simple_verify(challenge.chall, domain, user_key.public_key()):
        input("It doesn't look like it's set up yet; press return when it is.")

    print("Authorizing -- here goes...")
    auth_response = acme.answer_challenge(challenge, challenge.chall.response(user_key))
    print("Response was {}".format(auth_response.body.status.name))

    print("Waiting for authorization to become valid")
    while True:
        print("Polling")
        authzr, authzr_response = acme.poll(authzr)
        challenge = get_dns_challenge(authzr)
        if challenge.status.name == "valid":
            break
        print("DNS challenge is currently {}".format(challenge.status.name))
        time.sleep(10)
    print("Auth valid")

    print("Generating CSR")
    certificate_key = crypto.PKey()
    certificate_key.generate_key(crypto.TYPE_RSA, 2048)
    csr = crypto.X509Req()
    csr.get_subject().CN = domain
    csr.set_pubkey(certificate_key)
    csr.sign(certificate_key, "sha256")

    print("Requesting certificate")
    certificate_response = acme.request_issuance(josepy.util.ComparableX509(csr), [authzr])
    print("Got it!")

    print("Fetching chain")
    chain = acme.fetch_chain(certificate_response)
    print("Done!")

    print("Here are the details:")

    print("Private key:")
    print(crypto.dump_privatekey(FILETYPE_PEM, certificate_key))

    print("Combined cert:")
    print(crypto.dump_certificate(FILETYPE_PEM, certificate_response.body.wrapped))
    for cert in chain:
        print(crypto.dump_certificate(FILETYPE_PEM, cert.wrapped))
