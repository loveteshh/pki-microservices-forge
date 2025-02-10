#!/usr/bin/env python3
"""
This module provides functions for extracting public and private keys from various SSL certificate formats.

Functions:
    extract_public_key_from_cert(cert_file, output_file=None):
        Extract the public key from a certificate (PEM or DER) and optionally save to a file.

    extract_private_key_from_pem(pem_file, passphrase=None, output_file=None):
        Extract the private key from a PEM file with an optional passphrase.

    extract_private_key_from_pfx(pfx_file, passphrase=None, output_file=None):
        Extract the private key from a PFX (PKCS#12) file with an optional passphrase.

Example usage:
    python extract_keys.py --action=pubkey --cert_file=certificate.der --out=public_key.pem
    python extract_keys.py --action=privkeypem --pem_file=private_key.pem --passphrase=MySecret --out=extracted_key.pem
    python extract_keys.py --action=privkeypfx --pfx_file=keystore.pfx --passphrase=MyPFXPass --out=extracted_key.pem

"""

import argparse
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
        print(f"[+] Public key extracted and saved to {output_file}.")
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
        print("[-] Error loading the private key. Check if the passphrase is correct or if the file is valid.")
        return

    private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    if output_file:
        with open(output_file, 'wb') as out:
            out.write(private_key_pem)
        print(f"[+] Private key extracted and saved to {output_file}.")
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
        print("[-] Error loading the PFX file. Check if the passphrase is correct or if the file is valid.")
        return

    key = p12.get_privatekey()
    if not key:
        print("[-] No private key found in the PFX file.")
        return

    private_key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

    if output_file:
        with open(output_file, 'wb') as out:
            out.write(private_key_pem)
        print(f"[+] Private key extracted and saved to {output_file}.")
    else:
        print(private_key_pem.decode())


def main():
    parser = argparse.ArgumentParser(description="Extract public/private keys from certificates.")
    parser.add_argument("--action", required=True, choices=["pubkey", "privkeypem", "privkeypfx"],
                        help="Action to perform: 'pubkey' (extract public key), 'privkeypem' (extract private key from PEM), 'privkeypfx' (extract private key from PFX)")

    parser.add_argument("--cert_file", help="Path to the certificate file (for action=pubkey)")
    parser.add_argument("--pem_file", help="Path to the PEM file (for action=privkeypem)")
    parser.add_argument("--pfx_file", help="Path to the PFX file (for action=privkeypfx)")
    parser.add_argument("--passphrase", help="Passphrase for the file if needed")
    parser.add_argument("--out", help="Output file for the extracted key")

    args = parser.parse_args()

    if args.action == "pubkey":
        if not args.cert_file:
            print("[-] --cert_file is required for pubkey action.")
            sys.exit(1)
        extract_public_key_from_cert(args.cert_file, args.out)

    elif args.action == "privkeypem":
        if not args.pem_file:
            print("[-] --pem_file is required for privkeypem action.")
            sys.exit(1)
        extract_private_key_from_pem(args.pem_file, args.passphrase, args.out)

    elif args.action == "privkeypfx":
        if not args.pfx_file:
            print("[-] --pfx_file is required for privkeypfx action.")
            sys.exit(1)
        extract_private_key_from_pfx(args.pfx_file, args.passphrase, args.out)

if __name__ == "__main__":
    main()
