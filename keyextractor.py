import OpenSSL
from OpenSSL import crypto
import sys


def extract_public_key_from_cert(cert_file, output_file=None):
    """
    Extracts the public key from a certificate (PEM or DER) and writes it to an output file if specified.
    If the certificate is in DER format, it will be auto-detected.

    :param cert_file: Path to the certificate file (PEM or DER)
    :param output_file: (Optional) File to write the public key
    """
    # Attempt to load as PEM
    with open(cert_file, 'rb') as f:
        cert_data = f.read()
    
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
    except crypto.Error:
        # If it fails, try DER format
        cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_data)

    pub_key_obj = cert.get_pubkey()
    # Convert the public key to PEM for saving
    pub_key_pem = crypto.dump_publickey(crypto.FILETYPE_PEM, pub_key_obj)

    if output_file:
        with open(output_file, 'wb') as out:
            out.write(pub_key_pem)
        print(f"Public key extracted and saved to {output_file}.")
    else:
        print(pub_key_pem.decode())


def extract_private_key_from_pem(pem_file, passphrase=None, output_file=None):
    """
    Extracts the private key from a PEM file. If there's a passphrase, provide it.

    :param pem_file: Path to the PEM file containing the private key
    :param passphrase: (Optional) Passphrase for the private key
    :param output_file: (Optional) File to write the private key
    """
    with open(pem_file, 'rb') as f:
        pem_data = f.read()

    try:
        if passphrase:
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, pem_data, passphrase.encode())
        else:
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, pem_data)
    except crypto.Error:
        print("Error loading the private key. Check if the passphrase is correct or if the file is valid.")
        return

    private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    if output_file:
        with open(output_file, 'wb') as out:
            out.write(private_key_pem)
        print(f"Private key extracted and saved to {output_file}.")
    else:
        print(private_key_pem.decode())


def extract_private_key_from_pfx(pfx_file, passphrase=None, output_file=None):
    """
    Extracts the private key from a PFX (PKCS#12) file. If there's a passphrase, provide it.

    :param pfx_file: Path to the PFX file
    :param passphrase: (Optional) Passphrase for the PFX
    :param output_file: (Optional) File to write the private key
    """
    with open(pfx_file, 'rb') as f:
        pfx_data = f.read()

    try:
        p12 = crypto.load_pkcs12(pfx_data, passphrase.encode() if passphrase else None)
    except crypto.Error:
        print("Error loading the PFX file. Check if the passphrase is correct or if the file is valid.")
        return

    key = p12.get_privatekey()
    if not key:
        print("No private key found in the PFX file.")
        return

    private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    if output_file:
        with open(output_file, 'wb') as out:
            out.write(private_key_pem)
        print(f"Private key extracted and saved to {output_file}.")
    else:
        print(private_key_pem.decode())


if __name__ == "__main__":
    # In-progress: Need to define based on the type of certs later
    pass