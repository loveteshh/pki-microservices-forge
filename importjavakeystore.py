#!/usr/bin/env python3

import jks
import base64
import sys
import os

def jks_to_pem(keystore_path, keystore_password, output_dir):

    # Load the JKS keystore
    keystore = jks.KeyStore.load(keystore_path, keystore_password)

    # Ensure output directory exists
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    # Extract certificates from "trusted cert entries"
    for alias, cert_obj in keystore.certs.items():
        cert_der = cert_obj.cert
        # Convert DER to PEM
        pem_str = der_to_pem(cert_der)
        pem_path = os.path.join(output_dir, f"{alias}_cert.pem")
        with open(pem_path, "w") as pem_file:
            pem_file.write(pem_str)
        print(f"[INFO] Wrote certificate for alias '{alias}' to {pem_path}")

    # Certificates can also be found in "private key entries"
    # If there are any private key entries with certificate chains, we can extract them here
    for alias, pk_obj in keystore.private_keys.items():
        for idx, cert_der in enumerate(pk_obj.cert_chain):
            pem_str = der_to_pem(cert_der[1])  # cert_chain is list of (type, cert_bytes)
            chain_alias = f"{alias}_chain_{idx}"
            pem_path = os.path.join(output_dir, f"{chain_alias}.pem")
            with open(pem_path, "w") as pem_file:
                pem_file.write(pem_str)
            print(f"[INFO] Wrote certificate in chain for alias '{alias}' to {pem_path}")


def der_to_pem(der_bytes):
    """
    Convert DER-encoded certificate bytes to a PEM-formatted string.
    """
    pem_str = "-----BEGIN CERTIFICATE-----\n"
    pem_str += base64.encodebytes(der_bytes).decode("ascii")
    pem_str += "-----END CERTIFICATE-----\n"
    return pem_str


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: jks_to_pem.py <keystore.jks> <keystore_password> <output_directory>")
        sys.exit(1)
    
    keystore_path = sys.argv[1]
    keystore_password = sys.argv[2]
    output_dir = sys.argv[3]

    jks_to_pem(keystore_path, keystore_password, output_dir)
