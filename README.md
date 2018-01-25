# wep_rc4_chop_chop
Chop-Chop Attack on WEPs RC4 implementation

# dependancies
python3

# Tested systems
Debian 8 (up-to-date)

# Usage
&> python3 rc4.py


# Info
The python script contains a demo main function, with values you are free to change


# A l'intention de M. Perret

== Exercices ==
1) CRC32:=proc(M)
-> status : fontionnel
-> nom : crc32(), ligne 52

2) RC4KSA:=proc(K)
-> status : fontionnel
-> nom : rc4_ksa(), ligne 86

3) RC4PRGA:=proc(R,t)
-> status : fontionnel
-> nom : rc4_prga(), ligne 105

4) RC4:=proc(M, K)
-> status : fontionnel
-> nom : rc4_crypt(), ligne 125

5) RandomIV:=proc()
-> status : fontionnel
-> nom : random_iv(), ligne 146

6) Trame:=proc(M, K)
-> status : fontionnel
-> nom : wep_make_frame(), ligne 177
-> fonctions supplémentaires : wep_rc4_encrypt(), ligne 156

7) Decrypt:=proc(K,T)
-> status : fontionnel
-> nom : rc4_decrypt(), ligne 198

8) Inject:=proc(M’,M,T)
-> status : non-fonctionnel
-> nom : inject(), ligne 280
-> Problème :
Je n'ai pas réussi à valider la linéarité du crc32. Pour le tester, la fonction check_crc_linearity() à la ligne 231 devrait afficher un résultat positif sur crc(m1^m2) = crc(m1) ^ crc(m2). Or, la propriété n'est pas vérifié, rendant ainsi l'injection de message impossible.

9) ChopChop
-> status : non-fonctionnel


