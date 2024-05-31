package io.vacco.jwt;

import java.util.Objects;

public class JwtKey {

  public Alg alg;
  public int keySize;
  public String keyB64;

  public static JwtKey of(Alg alg, int keySize, String keyB64) {
    var k = new JwtKey();
    k.alg = Objects.requireNonNull(alg);
    k.keySize = keySize;
    k.keyB64 = Objects.requireNonNull(keyB64);
    return k;
  }

}
