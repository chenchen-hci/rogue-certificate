"""
Name: Chen Chen
Andrew ID: chenc5
Note: the program may run for a long time.
Please be patient!
"""

from z3 import *

import sha256_template
import certificates_template
import sys
import struct
import random
from Crypto.PublicKey import RSA
import urllib

numbers = '0123456789'

MINUS_ONE = 0xFFFFFFFFL

gihyuk_public = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqP1Im3QSIeuB2JBXq7Ip\nRoFXvT8HVDIBsQnGPiTylMpFw2cmZbNgEUlRQI0ne2OJv+HWis/ZGAA98fMwYbOo\nd5cxbCVEYpOpggaDMbUw9PBfEtzqcXB3FKR/Nz3uwJ/GIWurr95nxB2Kcvb6XVWs\nAkwJbpc9eWDSrtjmjIQi0RpGtsBm+vyQbRhdPadeticQCIdqNMqfwZ++2ltJYC2L\nkw8wCJPppdwFB8doDMk3Np0F7PjWD4Q0dEBnLYhkFNrECJhKjv6Dy3S5F5C0zK4Q\ncIPWqwBGOC+It9GYRGx4tnGdnOVfl5s+n8Jff1H72oOyhMqSLZrm3qeJFdu50hHb\nYwIDAQAB\n-----END PUBLIC KEY-----"

class_public = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu4/FPM7qqOoUlfIYxuB/\nMQVlLVW4+qubaEpJHOKFMl+1PoZ7vboaJx+EupwPgWcnBAJ7AOSZ4RNVlVq2ISKU\n0i+a2xDw/WFTdP/85S3Wi5D+VAvpT7S4UTXIWA+u/VYAZvqrLX7Pvj2aLOaxleD3\nMfkYpYGfBkC9AjiCrOH+HXY6J3sbLW2NmFthAqVRjRBp2+B8Z5UHh4FR2ht/j2JY\n/BH5/pyc5FFRSUxrvTGHrOJM7CG7JsSVwEwuXNIf3R6ol+d6AsMV051BnLX352IU\n+1yEHe1LY7m3X/GSl1dX5MrrmjUCvizRDjGw8dzXn761ZkHxBdnqiMjyP97mLm4q\n5wIDAQAB\n-----END PUBLIC KEY-----"

class_private = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAu4/FPM7qqOoUlfIYxuB/MQVlLVW4+qubaEpJHOKFMl+1PoZ7\nvboaJx+EupwPgWcnBAJ7AOSZ4RNVlVq2ISKU0i+a2xDw/WFTdP/85S3Wi5D+VAvp\nT7S4UTXIWA+u/VYAZvqrLX7Pvj2aLOaxleD3MfkYpYGfBkC9AjiCrOH+HXY6J3sb\nLW2NmFthAqVRjRBp2+B8Z5UHh4FR2ht/j2JY/BH5/pyc5FFRSUxrvTGHrOJM7CG7\nJsSVwEwuXNIf3R6ol+d6AsMV051BnLX352IU+1yEHe1LY7m3X/GSl1dX5MrrmjUC\nvizRDjGw8dzXn761ZkHxBdnqiMjyP97mLm4q5wIDAQABAoIBAQCIovj+DoMWoMh0\nX9S69QrTrGmDuEI0otVpCUzv9PkxtFV2AkSc97lbrPNlepE1JO9gVWpEQUT0mcAs\nONQbmXSvFi0Kz/GvtLo2rtIOJvF35R3SHodOIIpx5utXc714IrHSU2RmlU5D+d6a\nPUk7tZJ/XkcdMyulQ34t4vsXdN9Jl/raiRXb9Qymc4Rb9gf4fUtC9oXrDI03Lf4q\noxsPgt/L3ZOMdnWUfErznXH6myZBQhwfgvnzCq/nemyx4u1pWVXJYetK9ePqlRUh\ntUlyYBE0GeMlGUDgyZHOjCqu80gR17f1Gr1lS1kc3qU6Fu1o8rALmITaO1U8GCJe\n9x22Y1vJAoGBANOo7lWuB0sdmcXjwD4Yw9PttRHuXj8W0vTGye8vZSiOBnzinPSK\neD08oJnaN+jWBzzyTYNj+AW4bcYSW87NS4BP4LHINg3Fw0PuxlYK7R1AQEPyNHQj\n1VPutqktLjNnYlI8MhtkJsN8fw+CljFakvHD4/Yk2gEB/A6PdRwVElozAoGBAOLa\neiGClGLWNdslcfVrMAi8VJ+0bKzpsih1sG5Lvgcs+te7qKcjsoc7ZjTm3gMV+cjs\n7Wf+DpSTrUpHIQbCLa8Zx8vEr9ZO0sqPEIWveNNEorJ7993L4ceAtILM955c8qra\nkr5BvCaxynhAD/b22NnZANgiW0ol9brGtLyHx2B9AoGBAIEcVi4Ll0VZzBhrYjQ+\n1Q2svbwvZGwllw9bR4jQp2tCn3CEp2uAH/JyziCrfVlZXVbvExtn2r5ajxO41Snk\nDv85On4X++kQzpjcyT1pMtSaAdmwoBCMXy/wuJmgBsOyd8ZkE8ijogWzJqqmZMm8\nT1CMxry6JAVjWYbkOXKk4+oDAoGAfsFK2qyG0w8UOqYaneHNjiQFONNsodVWuerA\nsXBa9tF4O9DcdL+qgot7GXYieSDvWAiiwqefZ/94JXfHCWq4cg16qO32vk1+1LXJ\nqpkYbxv7uLUyE1lXh8zvj+KNPYx7/2Fv+yTpx8kx86z//qOBGYB6S0ovLig1vK5I\n0MshaVUCgYBwmuK0qWXvCZd7fY5qgmRvgO6sClUt1fJ+yxe2q+GSw2ZzdErI+sU5\njSAAierwe769HE8jFzCFtFArC0lTGQYiqrze4DTd82Vdjd0aGzYV19t9vwjYUCwx\nlFBvGaymLYeiX2c80/+w4nwFZGgm2ud/GAGbG1BjV86EmWF/y6w9cg==\n-----END RSA PRIVATE KEY-----"

#Certificate for the class signed by Gihyuk's private key
class_certificate = "1.0,1,sha256-18RSA,Gihyuk Ko,1458864000,1460332800,18733 Students,RSA2048,-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu4/FPM7qqOoUlfIYxuB/\nMQVlLVW4+qubaEpJHOKFMl+1PoZ7vboaJx+EupwPgWcnBAJ7AOSZ4RNVlVq2ISKU\n0i+a2xDw/WFTdP/85S3Wi5D+VAvpT7S4UTXIWA+u/VYAZvqrLX7Pvj2aLOaxleD3\nMfkYpYGfBkC9AjiCrOH+HXY6J3sbLW2NmFthAqVRjRBp2+B8Z5UHh4FR2ht/j2JY\n/BH5/pyc5FFRSUxrvTGHrOJM7CG7JsSVwEwuXNIf3R6ol+d6AsMV051BnLX352IU\n+1yEHe1LY7m3X/GSl1dX5MrrmjUCvizRDjGw8dzXn761ZkHxBdnqiMjyP97mLm4q\n5wIDAQAB\n-----END PUBLIC KEY-----,0,,,2a3142594b2290b29bffd5b0b953758cfce12bf9d961114c6ba3358dadd4955a8d91b9172bc89ae5c63d18d490755b67b2174b4dfa5115d7ff7d266ce039b6ae8a811245e4087f733f5848b5df409daacef7dcde7b1f236673acdbf6b1ab89fcf860fd0bd72a6eab38b71d0c01af6461fbc221d0e1179a573b395d0b0b98e8458b8da518439e1987550e4c3d27ffeed5fd4ecdc24400d01fb8446f048e7f3a3b4df1e7b7f101650a6e8aa5b1b7f8c77d989aa10c4aa12ef7fc0c97cfc1cd12a1628219a188475adc3e11ee16906212dafec2d09078b33fe415db8df4f5012127169e56ae94b29e9bfab026f29e103a7b538208c8573e0e26593bc333855071d3"


rol = lambda val, r_bits, max_bits: \
            (val << r_bits%max_bits) & (2**max_bits-1) | \
                ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
            ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
                (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def random_str(size):
    """
    generating random string of size size.
    """
    string = ""
    for i in range(size):
        string = string + random.choice(numbers)
    return str(string)

def createCertificate(version = 1.0, serial = 1, sig_algorithm = "sha256-18RSA", issuer = "Gihyuk Ko", validity_start = 1458864000, validity_end = 1460332800, subject_name = "18733 Students", subject_public_key_algorithm = "RSA2048", subject_public_key = "0", is_ca = 1, issuer_unique_id = "", subject_unique_id = "", signer_private_key_str = ""):
    """
    adopted from template code.
    """
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
    """
    adopted from template code.
    """
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
    """
    adopted from template code.
    """
    return urllib.quote_plus(cert)

def testCertificates(_cert):
    """
    modified based on template code.
    """
    # verify a certificate generated from class_private key is valid
    cert = createCertificate(subject_public_key = class_public, signer_private_key_str = class_private)
    print ("Created Certificate: " + str(cert))
    print ("Certificate Verify: " + str(verifyCertificate(cert, class_public)))
    
    # verify given class_certificate is valid
    print ("Class Verify: " + str(verifyCertificate(_cert, gihyuk_public)))
    print ("URL Encoded Cert: " + str(urlencodeCertificate(_cert)))

def find_sha_256_collision(output, _h_):
    """
    find collision input of sha_256
    modified based on provided template.
    Some technique of loop unrolling is used for enhancing performance.
    """
    s = Solver()
    _k = (0x428a2f98L, 0x71374491L, 0xb5c0fbcfL, 0xe9b5dba5L,
          0x3956c25bL, 0x59f111f1L, 0x923f82a4L, 0xab1c5ed5L,
          0xd807aa98L, 0x12835b01L, 0x243185beL, 0x550c7dc3L,
          0x72be5d74L, 0x80deb1feL, 0x9bdc06a7L, 0xc19bf174L,
          0xe49b69c1L, 0xefbe4786L, 0x0fc19dc6L, 0x240ca1ccL,
          0x2de92c6fL, 0x4a7484aaL, 0x5cb0a9dcL, 0x76f988daL,
          0x983e5152L, 0xa831c66dL, 0xb00327c8L, 0xbf597fc7L,
          0xc6e00bf3L, 0xd5a79147L, 0x06ca6351L, 0x14292967L,
          0x27b70a85L, 0x2e1b2138L, 0x4d2c6dfcL, 0x53380d13L,
          0x650a7354L, 0x766a0abbL, 0x81c2c92eL, 0x92722c85L,
          0xa2bfe8a1L, 0xa81a664bL, 0xc24b8b70L, 0xc76c51a3L,
          0xd192e819L, 0xd6990624L, 0xf40e3585L, 0x106aa070L,
          0x19a4c116L, 0x1e376c08L, 0x2748774cL, 0x34b0bcb5L,
          0x391c0cb3L, 0x4ed8aa4aL, 0x5b9cca4fL, 0x682e6ff3L,
          0x748f82eeL, 0x78a5636fL, 0x84c87814L, 0x8cc70208L,
          0x90befffaL, 0xa4506cebL, 0xbef9a3f7L, 0xc67178f2L)

    _h = _h_

    a = Array('a', IntSort(), BitVecSort(32))
    b = Array('b', IntSort(), BitVecSort(32))
    c = Array('c', IntSort(), BitVecSort(32))
    d = Array('d', IntSort(), BitVecSort(32))
    e = Array('e', IntSort(), BitVecSort(32))
    f = Array('f', IntSort(), BitVecSort(32))
    g = Array('g', IntSort(), BitVecSort(32))
    h = Array('h', IntSort(), BitVecSort(32))
    t1 = Array('t1', IntSort(), BitVecSort(32))
    t2 = Array('t2', IntSort(), BitVecSort(32))
    s0 = Array('s0', IntSort(), BitVecSort(32))
    s1 = Array('s1', IntSort(), BitVecSort(32))
    ch = Array('ch', IntSort(), BitVecSort(32))
    maj = Array('maj', IntSort(), BitVecSort(32))
    ss0 = Array('ss0', IntSort(), BitVecSort(32))
    ss1 = Array('ss1', IntSort(), BitVecSort(32))
    w = Array('w', IntSort(), BitVecSort(32))

    s.add(a[0] == _h[0])
    s.add(b[0] == _h[1])
    s.add(c[0] == _h[2])
    s.add(d[0] == _h[3])
    s.add(e[0] == _h[4])
    s.add(f[0] == _h[5])
    s.add(g[0] == _h[6])
    s.add(h[0] == _h[7])
 
    for i in range(16,18):
        s.add( RotateRight(w[i - 15], 7) ^ RotateRight(w[i - 15], 18) ^ LShR(w[i - 15],3) == ss0[i] )
        s.add( RotateRight(w[i-2], 17) ^ RotateRight(w[i-2], 19) ^ LShR(w[i-2], 10) == ss1[i] )
        s.add(((w[i-16] + ss0[i] + w[i-7] + ss1[i]) & MINUS_ONE) == w[i] )
                        
    for i in range(18):
        s.add(RotateRight(a[i], 2) ^ RotateRight(a[i], 13) ^ RotateRight(a[i], 22) == s0[i])
        s.add((a[i] & b[i]) ^ (a[i] & c[i]) ^ (b[i] & c[i]) == maj[i])
        s.add(s0[i] + maj[i] == t2[i])
        s.add(RotateRight(e[i], 6) ^ RotateRight(e[i], 11) ^ RotateRight(e[i], 25) == s1[i])
        s.add((e[i] & f[i]) ^ ((~e[i]) & g[i]) == ch[i])
        s.add(h[i] + s1[i] + ch[i] + _k[i] + w[i] == t1[i])

        s.add(g[i] == h[i+1])
        s.add(f[i] == g[i+1])
        s.add(e[i] == f[i+1])
        s.add(((d[i] + t1[i]) & MINUS_ONE) == e[i+1])
        s.add(c[i] == d[i+1])
        s.add(b[i] == c[i+1])
        s.add(a[i] == b[i+1])
        s.add(((t1[i] + t2[i]) & MINUS_ONE) == a[i+1])

    _h = [(MINUS_ONE & (x + y)) for x, y in zip(_h, [a[18], b[18], c[18], d[18], e[18], f[18], g[18], h[18]])]

    s.add(_h[0] == output[0])
    s.add(_h[1] == output[1])
    s.add(_h[2] == output[2])
    s.add(_h[3] == output[3])
    s.add(_h[4] == output[4])
    s.add(_h[5] == output[5])
    s.add(_h[6] == output[6])
    s.add(_h[7] == output[7])

    s.check()
    m = s.model()

    input_ = str(m[w])

    inputMap = {}
    input_ = input_[1:len(input_) - 1]
    inputTemp = input_.split(",");

    for i in range(len(inputTemp)):
        inputTemp[i] = inputTemp[i].strip()
        temp = inputTemp[i].split("->")
        if temp[0].strip() != 'else':
            inputMap[int(temp[0].strip())] = int(temp[1].strip())

    # reassemble string
    return_input = ""
    for i in range(16):
        return_input = return_input + struct.pack("!L", inputMap[i])
    return return_input

def generate_rogue_CA_Cert():
    """
    question 2: generate rogue CA certificate.
    """

    class_cert = str(class_certificate)
    
    class_cert_tokens = class_cert.split(",")
    sig = class_cert_tokens[-1]
    class_cert_tokens = class_cert_tokens[:-2]
    rogue_cert_tokens = list(class_cert_tokens)
    rogue_cert_tokens[-1] = "279238925818396635815754904017768317795137217199"     # add random string
    rogue_cert_tokens[-2] = "1"
    
    class_cert = ','.join([str(elem) for elem in class_cert_tokens]) + ','
    rogue_cert = ','.join([str(elem) for elem in rogue_cert_tokens]) + ','
        
    sha_class_cert = sha256_template.new(class_cert)
    sha_rogue_cert = sha256_template.new(rogue_cert)
        
    rogue_input = find_sha_256_collision(sha_class_cert._h, sha_rogue_cert._h) # in string format
    
    rogue_cert = rogue_cert + rogue_input + "," + sig

    return str(rogue_cert)

def find_collision_input(_random_str):
    """
    question 1: finding collision output.
    """
    _h = (0x6a09e667L, 0xbb67ae85L, 0x3c6ef372L, 0xa54ff53aL,
          0x510e527fL, 0x9b05688cL, 0x1f83d9abL, 0x5be0cd19L)
    old_input = _random_str
    output = sha256_template.new(old_input)
    new_input = find_sha_256_collision(output._h, _h)
    print ("Original Input: " + old_input)
    print ("Collision Input: " + new_input)
    print ("Collision input: " + new_input.encode('hex')) # print in hex format
    print ("Output: " + output.hexdigest())
    if sha256_template.new(new_input).hexdigest() == output.hexdigest():
        print ("[INFO QUESTION 1] A collision has been found!")
    return str(new_input)

def verify_hash_collision(input1='8273997829644757547679116927658198779823688000907452478797313315', input2='5508753bb61659315fe5a4e392b2147470fc9b23deeb7ac53338bce538e76a0eb844c99493b5af00be59630df7bc65190519889e0ca79dd9a86c005c766d889a'):
    """
    since running the program takes a significant amount of time.
    using this function can verify my output more efficiently.
    input 1: original input
    input 2: encoded by hex
    """
    print("input 1: " + input1)
    print("input 2: " + input2)
    output1 = sha256_template.new(input1)
    output2 = sha256_template.new(input2.decode('hex'))    
    print(output1.hexdigest() == output2.hexdigest())

def main():
    # find hash collision
    old_input = random_str(64)
    new_input = find_collision_input(old_input)
    verify_hash_collision(old_input, new_input.encode('hex'))
    
    # generate rogue certificate
    rogue_cert = generate_rogue_CA_Cert()
    testCertificates(rogue_cert)
  
if __name__== "__main__":
    main()



