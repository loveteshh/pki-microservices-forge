import OpenSSL
from OpenSSL import crypto
import sys

def pkcs12_to_pem(pfx_file, pfx_password, pem_output):
    with open(pfx_file, 'rb') as f:
        pfx_data = f.read()
    
    p12 = crypto.load_pkcs12(pfx_data, pfx_password.encode())
    
    with open(pem_output, 'wb') as pem_out:
        pem_out.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, p12.get_privatekey()))
        pem_out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate()))
        for ca in p12.get_ca_certificates() or []:
            pem_out.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))

def pem_to_pkcs12(cert_file, key_file, pfx_password, pfx_output):
    with open(cert_file, 'rb') as f:
        cert_data = f.read()
    with open(key_file, 'rb') as f:
        key_data = f.read()

    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
    key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)

    p12 = crypto.PKCS12()
    p12.set_certificate(cert)
    p12.set_privatekey(key)

    with open(pfx_output, 'wb') as f:
        f.write(p12.export(passphrase=pfx_password.encode()))

def crt_to_pem(crt_file, pem_output):
    with open(crt_file, 'rb') as f:
        crt_data = f.read()

    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, crt_data)

    with open(pem_output, 'wb') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

if __name__ == "__main__":
    # pkcs12_to_pem('certificate.pfx', 'password', 'output.pem')
    # pem_to_pkcs12('cert.pem', 'key.pem', 'password', 'output.pfx')
    # crt_to_pem('certificate.crt', 'output.pem')
    pass
