# Generating Rogue Certificate Via Finding Hash Collisions
CMU 18733 Mini Project (Spring 2017)

## Brief:
The idea of "rogue certificate" attack proposed by Sotirov et. al. in <a href="https://www.win.tue.nl/hashclash/rogue-ca/downloads/md5-collisions-1.0.pdf" target="_blank">this presentation</a> shows that the attacker is able to obtain a valid certificate for a rogue intermediate CA, which includes the certificate that is allowed to be used to endorse ither certificate, giving attackers virtually unlimited power. This mini-project aims to generate a rougue certificate by replacing certain fields of a valid endorsed certificate such that the entire hash remains unchanged. This means the signatures on the old certificate will be same as that on the new.

## Getting Started:
### Installing Z3 SMT Solver:
See https://github.com/Z3Prover/z3

### Run:
```
sudo python main.py
```

### SHA:
The SHA used in this mini project is a simplified version of SHA-256, named SHA-256-18, where only 18 rounds and special padding scheme has been removed. The full version of SHA-256-18 can be referred to `sha256_template.py`. 
