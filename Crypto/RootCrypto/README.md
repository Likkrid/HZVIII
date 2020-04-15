RootCrypto
==========

Presentation
----------

RootCrypto is the fruit of many years of work. The author is a crypto addict that likes RSA but he is in love with roots..
Can you get his flag ?

Vulnerability
----------

This challenge is about [Rabin Cryptosystem][rb] with some modifications:

  - Major modification : Use of 3 primes
  - Minor change : Not sticking to specific choices of primes that yield simple deterministic
algorithm for finding square roots ( p ≡ 3 (mod 4),  p ≡ 5 (mod 8) )

Distribution
-----------

src/rabin.py

Flag
-----------

HZVIII{Ton3ll1_5haNkS_&_CRT_SM4sH3d_RabiN_3_SqUar3_R0o7s}

References
----------

   [rb]: <https://en.wikipedia.org/wiki/Rabin_cryptosystem>
