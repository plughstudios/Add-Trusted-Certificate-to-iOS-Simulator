# -*- coding: utf-8 -*-
'''
    add_ca_to_iossim.py v0.1
    Copyright (C) 2011 Ron Gutierrez

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

'''
import os
import sqlite3
import subprocess

__usage__ = """
Please supply required arguments: <CA Certificate Path>

    add_ca_to_iossim.py <CA Certificate Path>
"""

simulator_dir = os.getenv('HOME')+"/Library/Application Support/iPhone Simulator/"
truststore_path = "/Library/Keychains/TrustStore.sqlite3"


def cert_fingerprint_via_openssl(cert_location):
    output = subprocess.check_output(["openssl", "x509", "-noout", "-in", cert_location, "-fingerprint"])
    fingerprint_with_colons = output.split("=")[1]
    return fingerprint_with_colons.replace(':','')


def cert_fingerprint(cert_location):
    try:
        from M2Crypto import X509   
        cert = X509.load_cert(cert_location)
        return cert.get_fingerprint('sha1')
    except ImportError:
        return cert_fingerprint_via_openssl(cert_location)  


def add_to_truststore(sdk_dir, cert_fingerprint):
    tpath = simulator_dir+sdk_dir+truststore_path

    sha1="X'"+cert_fingerprint.strip()+"'"

    try:
        conn = sqlite3.connect(simulator_dir+sdk_dir+truststore_path)
        c = conn.cursor()
        sql = 'insert into tsettings values (%s,%s,%s,%s)'%(sha1, "randomblob(16)", "randomblob(16)", "randomblob(16)")
        c.execute(sql)
        conn.commit()

        c.close()
        conn.close()
        print("Successfully added CA to %s" % tpath) 
    except sqlite3.OperationalError:
        print("Error adding CA to %s" % tpath )
        print("Mostly likely failed because Truststore does not exist..skipping\n")
        return
    except sqlite3.IntegrityError:
        print("Error adding CA to %s" % tpath )
        print("Table already has an entry with the same CA SHA1 fingerprint..skipping\n")
        return

if __name__ == "__main__":
    import sys

    if not sys.argv[1:]:
        print(__usage__)
        sys.exit(1)

    for sdk_dir in os.listdir(simulator_dir):
        for cert_location in sys.argv[1:]:

            cert_fingerprint = cert_fingerprint(cert_location)

            if not sdk_dir.startswith('.') and sdk_dir != 'User':
                add_to_truststore(sdk_dir, cert_fingerprint)
