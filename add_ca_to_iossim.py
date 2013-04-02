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
from M2Crypto import X509   
import os
import sqlite3
import sys


__usage__ = """Please supply required arguments: <CA Certificate Path>

Usage: %s [CA Certificate Path ...]""" % (sys.argv[0], )


SIMULATOR_HOME = os.path.join(os.getenv('HOME'), 'Library',
                              'Application Support', 'iPhone Simulator')
TRUSTSTORE_PATH = '/Library/Keychains/TrustStore.sqlite3'


def add_certificates_to_truststore(truststore, *certificates):
    conn = sqlite3.connect(truststore)

    try:
        for certificate in certificates:
            sha1 = "X'{0}'".format(certificate.get_fingerprint('sha1'))
            subj = "X'{0}'".format(certificate.get_subject().as_der().encode('hex'))
            tset = "X'{0}'".format("""<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><array/></plist>""".encode('hex'))
            data = "X'{0}'".format(certificate.as_der().encode('hex'))

            try:
                c = conn.cursor()
                c.execute('INSERT INTO tsettings VALUES (?, ?, ?, ?)',
                          (sha1, subj, tset, data))
                print("Successfully added CA to %s" % (truststore, )) 
            except sqlite3.OperationalError as e:
                print("Error adding CA to %s: %s" % (truststore, e))
                print("Mostly likely failed because TrustStore does not exist..skipping\n")
            except sqlite3.IntegrityError as e:
                print("Error adding CA to %s: %s" % (truststore, e))
                print("Table already has an entry with the same CA SHA1 fingerprint: %s..skipping\n" % (sha1, ))
            finally:
                c.close()

    finally:
        conn.close()
    return


if __name__ == "__main__":
    if not sys.argv[1:]:
        print(__usage__)
        sys.exit(1)

    certificates = []

    for certfile in sys.argv[1:]:
        certext = os.path.splitext(certfile)[-1].lower()
        if certext == '.der':
            certificates.append(X509.load_cert(certfile, X509.FORMAT_DER))
        elif certext == '.pem':
            certificates.append(X509.load_cert(certfile, X509.FORMAT_PEM))

    for sdk_dir in os.listdir(SIMULATOR_HOME):
        if not sdk_dir.startswith('.') and sdk_dir != 'User':
            truststore = os.path.join(SIMULATOR_HOME, sdk_dir,
                    *TRUSTSTORE_PATH.split('/'))
            add_certificates_to_truststore(truststore, *certificates)
