"""
Carnegie Mellon University
18733 Applied Cryptography 2017 Mini Project
certificates_template.py

credit to Kyle Soska
"""

from Crypto.PublicKey import RSA
import sha256_template
import urllib
import struct

gihyuk_public = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqP1Im3QSIeuB2JBXq7Ip\nRoFXvT8HVDIBsQnGPiTylMpFw2cmZbNgEUlRQI0ne2OJv+HWis/ZGAA98fMwYbOo\nd5cxbCVEYpOpggaDMbUw9PBfEtzqcXB3FKR/Nz3uwJ/GIWurr95nxB2Kcvb6XVWs\nAkwJbpc9eWDSrtjmjIQi0RpGtsBm+vyQbRhdPadeticQCIdqNMqfwZ++2ltJYC2L\nkw8wCJPppdwFB8doDMk3Np0F7PjWD4Q0dEBnLYhkFNrECJhKjv6Dy3S5F5C0zK4Q\ncIPWqwBGOC+It9GYRGx4tnGdnOVfl5s+n8Jff1H72oOyhMqSLZrm3qeJFdu50hHb\nYwIDAQAB\n-----END PUBLIC KEY-----"

class_public = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu4/FPM7qqOoUlfIYxuB/\nMQVlLVW4+qubaEpJHOKFMl+1PoZ7vboaJx+EupwPgWcnBAJ7AOSZ4RNVlVq2ISKU\n0i+a2xDw/WFTdP/85S3Wi5D+VAvpT7S4UTXIWA+u/VYAZvqrLX7Pvj2aLOaxleD3\nMfkYpYGfBkC9AjiCrOH+HXY6J3sbLW2NmFthAqVRjRBp2+B8Z5UHh4FR2ht/j2JY\n/BH5/pyc5FFRSUxrvTGHrOJM7CG7JsSVwEwuXNIf3R6ol+d6AsMV051BnLX352IU\n+1yEHe1LY7m3X/GSl1dX5MrrmjUCvizRDjGw8dzXn761ZkHxBdnqiMjyP97mLm4q\n5wIDAQAB\n-----END PUBLIC KEY-----"

class_private = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAu4/FPM7qqOoUlfIYxuB/MQVlLVW4+qubaEpJHOKFMl+1PoZ7\nvboaJx+EupwPgWcnBAJ7AOSZ4RNVlVq2ISKU0i+a2xDw/WFTdP/85S3Wi5D+VAvp\nT7S4UTXIWA+u/VYAZvqrLX7Pvj2aLOaxleD3MfkYpYGfBkC9AjiCrOH+HXY6J3sb\nLW2NmFthAqVRjRBp2+B8Z5UHh4FR2ht/j2JY/BH5/pyc5FFRSUxrvTGHrOJM7CG7\nJsSVwEwuXNIf3R6ol+d6AsMV051BnLX352IU+1yEHe1LY7m3X/GSl1dX5MrrmjUC\nvizRDjGw8dzXn761ZkHxBdnqiMjyP97mLm4q5wIDAQABAoIBAQCIovj+DoMWoMh0\nX9S69QrTrGmDuEI0otVpCUzv9PkxtFV2AkSc97lbrPNlepE1JO9gVWpEQUT0mcAs\nONQbmXSvFi0Kz/GvtLo2rtIOJvF35R3SHodOIIpx5utXc714IrHSU2RmlU5D+d6a\nPUk7tZJ/XkcdMyulQ34t4vsXdN9Jl/raiRXb9Qymc4Rb9gf4fUtC9oXrDI03Lf4q\noxsPgt/L3ZOMdnWUfErznXH6myZBQhwfgvnzCq/nemyx4u1pWVXJYetK9ePqlRUh\ntUlyYBE0GeMlGUDgyZHOjCqu80gR17f1Gr1lS1kc3qU6Fu1o8rALmITaO1U8GCJe\n9x22Y1vJAoGBANOo7lWuB0sdmcXjwD4Yw9PttRHuXj8W0vTGye8vZSiOBnzinPSK\neD08oJnaN+jWBzzyTYNj+AW4bcYSW87NS4BP4LHINg3Fw0PuxlYK7R1AQEPyNHQj\n1VPutqktLjNnYlI8MhtkJsN8fw+CljFakvHD4/Yk2gEB/A6PdRwVElozAoGBAOLa\neiGClGLWNdslcfVrMAi8VJ+0bKzpsih1sG5Lvgcs+te7qKcjsoc7ZjTm3gMV+cjs\n7Wf+DpSTrUpHIQbCLa8Zx8vEr9ZO0sqPEIWveNNEorJ7993L4ceAtILM955c8qra\nkr5BvCaxynhAD/b22NnZANgiW0ol9brGtLyHx2B9AoGBAIEcVi4Ll0VZzBhrYjQ+\n1Q2svbwvZGwllw9bR4jQp2tCn3CEp2uAH/JyziCrfVlZXVbvExtn2r5ajxO41Snk\nDv85On4X++kQzpjcyT1pMtSaAdmwoBCMXy/wuJmgBsOyd8ZkE8ijogWzJqqmZMm8\nT1CMxry6JAVjWYbkOXKk4+oDAoGAfsFK2qyG0w8UOqYaneHNjiQFONNsodVWuerA\nsXBa9tF4O9DcdL+qgot7GXYieSDvWAiiwqefZ/94JXfHCWq4cg16qO32vk1+1LXJ\nqpkYbxv7uLUyE1lXh8zvj+KNPYx7/2Fv+yTpx8kx86z//qOBGYB6S0ovLig1vK5I\n0MshaVUCgYBwmuK0qWXvCZd7fY5qgmRvgO6sClUt1fJ+yxe2q+GSw2ZzdErI+sU5\njSAAierwe769HE8jFzCFtFArC0lTGQYiqrze4DTd82Vdjd0aGzYV19t9vwjYUCwx\nlFBvGaymLYeiX2c80/+w4nwFZGgm2ud/GAGbG1BjV86EmWF/y6w9cg==\n-----END RSA PRIVATE KEY-----"

#Certificate for the class signed by Gihyuk's private key
class_certificate = "1.0,1,sha256-18RSA,Gihyuk Ko,1458864000,1460332800,18733 Students,RSA2048,-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu4/FPM7qqOoUlfIYxuB/\nMQVlLVW4+qubaEpJHOKFMl+1PoZ7vboaJx+EupwPgWcnBAJ7AOSZ4RNVlVq2ISKU\n0i+a2xDw/WFTdP/85S3Wi5D+VAvpT7S4UTXIWA+u/VYAZvqrLX7Pvj2aLOaxleD3\nMfkYpYGfBkC9AjiCrOH+HXY6J3sbLW2NmFthAqVRjRBp2+B8Z5UHh4FR2ht/j2JY\n/BH5/pyc5FFRSUxrvTGHrOJM7CG7JsSVwEwuXNIf3R6ol+d6AsMV051BnLX352IU\n+1yEHe1LY7m3X/GSl1dX5MrrmjUCvizRDjGw8dzXn761ZkHxBdnqiMjyP97mLm4q\n5wIDAQAB\n-----END PUBLIC KEY-----,0,,,2a3142594b2290b29bffd5b0b953758cfce12bf9d961114c6ba3358dadd4955a8d91b9172bc89ae5c63d18d490755b67b2174b4dfa5115d7ff7d266ce039b6ae8a811245e4087f733f5848b5df409daacef7dcde7b1f236673acdbf6b1ab89fcf860fd0bd72a6eab38b71d0c01af6461fbc221d0e1179a573b395d0b0b98e8458b8da518439e1987550e4c3d27ffeed5fd4ecdc24400d01fb8446f048e7f3a3b4df1e7b7f101650a6e8aa5b1b7f8c77d989aa10c4aa12ef7fc0c97cfc1cd12a1628219a188475adc3e11ee16906212dafec2d09078b33fe415db8df4f5012127169e56ae94b29e9bfab026f29e103a7b538208c8573e0e26593bc333855071d3"


def createCertificate(version = 1.0, serial = 1, sig_algorithm = "sha256-18RSA", issuer = "Gihyuk Ko", validity_start = 1458864000, validity_end = 1460332800, subject_name = "18733 Students", subject_public_key_algorithm = "RSA2048", subject_public_key = "0", is_ca = 1, issuer_unique_id = "", subject_unique_id = "", signer_private_key_str = ""):

    privKeyObj = RSA.importKey(signer_private_key_str)

    cert = "" #This is the string that will become the certificate
    cert += str(version) + ","
    cert += str(serial) + ","
    cert += str(sig_algorithm) + ","
    cert += str(issuer) + ","
    cert += str(validity_start) + ","
    cert += str(validity_end) + ","
    cert += str(subject_name) + ","
    cert += str(subject_public_key_algorithm) + ","
    cert += str(subject_public_key) + ","
    cert += str(is_ca) + ","
    cert += str(issuer_unique_id) + ","
    cert += str(subject_unique_id)
    cert += "," + str(format(privKeyObj.sign(sha256_template.sha256(cert).digest(), K = "")[0], 'x'))
    return cert


def verifyCertificate(cert, pk_str):

    version = float(cert.split(",")[0])
    serial = int(cert.split(",")[1])
    sig_algorithm = cert.split(",")[2]
    issuer = cert.split(",")[3]
    validity_start = int(cert.split(",")[4])
    validity_end = int(cert.split(",")[5])
    subject_name = cert.split(",")[6]
    print "Subject name: " + str(subject_name)
    subject_public_key_algorithm = cert.split(",")[7]
    subject_public_key = cert.split(",")[8]
    is_ca = int(cert.split(",")[9])
    issuer_unique_id = cert.split(",")[10]
    subject_unique_id = cert.split(",")[11]
    sig = (long(cert.split(",")[12], 16),)

    pk = RSA.importKey(pk_str)
    return pk.verify(sha256_template.sha256(cert[:(cert.rfind(","))]).digest(), sig)


def urlencodeCertificate(cert):
    return urllib.quote_plus(cert)

### a function to test certifcates ###
def testCertificates():
    # verify a certificate generated from class_private key is valid
    cert = createCertificate(subject_public_key = class_public, signer_private_key_str = class_private)
    print ("Created Certificate: " + str(cert))
    print ("Certificate Verify: " + str(verifyCertificate(cert, class_public)))
    
    # verify given class_certificate is valid
    print ("Class Verify: " + str(verifyCertificate(class_certificate, gihyuk_public)))
    print ("URL Encoded Cert: " + str(urlencodeCertificate(class_certificate)))