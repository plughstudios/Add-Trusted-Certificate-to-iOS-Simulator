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

def normalize_subject(subject):
    # normalize the subject to make Apple happy - subject is forced to all caps (possibly other transformations?) when trusted by Apple - simulate this
    new_subject = X509.X509_Name()

    interesting_keys = ['C','ST','L','O','OU','CN','Email','serialNumber','SN','GN']
    for key in interesting_keys:
      v = getattr(subject, key)
      if v is not None:
        setattr(new_subject, key, v.upper())

    return new_subject

def subject_as_der(subject):
    subject_der = subject.as_der()
    # subject der encoding is returning two leading bytes (0x30, 0x70) that Apple doesn't grok - pop them off
    # TODO: determine what these leading bytes are and if we can get rid of them a saner way
    subject_der = subject_der[2:]

    return subject_der

def add_certificates_to_truststore(truststore, *certificates):
    conn = sqlite3.connect(truststore)

    try:
        for certificate in certificates:
            subject = normalize_subject(certificate.get_subject())
            subject_der = subject_as_der(subject)

            sha1 = sqlite3.Binary(certificate.get_fingerprint('sha1').decode('hex'))
            subj = sqlite3.Binary(subject_der)
            tset = sqlite3.Binary("""<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><array/></plist>""")
            data = sqlite3.Binary(certificate.as_der())

            try:
                c = conn.cursor()
                c.execute('INSERT INTO tsettings VALUES (?, ?, ?, ?)',
                          (sha1, subj, tset, data))
                conn.commit()
                print("Successfully added CA to %s" % (truststore, )) 
            except sqlite3.OperationalError as e:
                print("Error adding CA to %s: %s" % (truststore, e))
                print("Mostly likely failed because TrustStore does not exist..skipping\n")
            except sqlite3.IntegrityError as e:
                print("Error adding CA to %s: %s" % (truststore, e))
                print("Table already has an entry with the same CA SHA1 fingerprint: %s..skipping\n" % (certificate.get_fingerprint('sha1'), ))
            except Error as e:
                print("Error: %s\n" % (e, ))
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
        if certext == '.der' or certext == '.cer':
            certificates.append(X509.load_cert(certfile, X509.FORMAT_DER))
        elif certext == '.pem' or certext == '.crt':
            certificates.append(X509.load_cert(certfile, X509.FORMAT_PEM))
        else:
            print('fallback')
            certificates.append(X509.load_cert(certfile))

    add_certificates_to_truststore('TrustStore.sqlite3', *certificates)
