# wep_rc4_chop_chop
Chop-Chop Attack on WEPs RC4 implementation

# Tested systems
Debian 8 (up-to-date) with python 3

# Usage with default test values
&> python3 rc4.py


# Info
The python script contains a demo main function, with values you are free to change


# A l'intention de M. Perret

== Exercices ==
1) CRC32:=proc(M)
-> status : fontionnel
-> nom : crc32(), ligne 79

2) RC4KSA:=proc(K)
-> status : fontionnel
-> nom : rc4_ksa(), ligne 116

3) RC4PRGA:=proc(R,t)
-> status : fontionnel
-> nom : rc4_prga(), ligne 135

4) RC4:=proc(M, K)
-> status : fontionnel
-> nom : rc4_crypt(), ligne 155

5) RandomIV:=proc()
-> status : fontionnel
-> nom : random_iv(), ligne 185

6) Trame:=proc(M, K)
-> status : fontionnel
-> nom : wep_make_frame(), ligne 216
-> fonctions supplémentaires : wep_rc4_encrypt(), ligne 195

7) Decrypt:=proc(K,T)
-> status : fontionnel
-> nom : rc4_decrypt(), ligne 237

8) Inject:=proc(M’,M,T)
-> status : fonctionnel
-> nom : inject(), ligne 270

9) ChopChop
-> status : non-fonctionnel


