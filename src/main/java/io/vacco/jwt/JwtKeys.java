package io.vacco.jwt;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import static io.vacco.jwt.Jwt.HMAC;
import static io.vacco.jwt.Jwt.RSA;

public class JwtKeys {

  public static JwtKey generateKey(Alg alg, int keySize) {
    try {
      if (alg.type.equals(HMAC)) {
        return generateHMACKey(alg, keySize);
      } else if (alg.type.equals(Jwt.RSA)) {
        return generateRSAKey(alg, keySize);
      } else {
        throw new UnsupportedOperationException("Unsupported algorithm type");
      }
    } catch (Exception ex) {
      throw new IllegalStateException(ex);
    }
  }

  private static JwtKey generateRSAKey(Alg alg, int keySize) throws NoSuchAlgorithmException {
    var keyPairGenerator = KeyPairGenerator.getInstance(RSA);
    keyPairGenerator.initialize(keySize);
    var keyPair = keyPairGenerator.generateKeyPair();
    var privateKey = keyPair.getPrivate();
    var keyB64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
    return JwtKey.of(alg, keySize, keyB64);
  }

  private static JwtKey generateHMACKey(Alg alg, int keySize) throws NoSuchAlgorithmException {
    var keyGenerator = KeyGenerator.getInstance(alg.algName);
    keyGenerator.init(keySize);
    var secretKey = keyGenerator.generateKey();
    var keyB64 = Base64.getEncoder().encodeToString(secretKey.getEncoded());
    return JwtKey.of(alg, keySize, keyB64);
  }

  public static PrivateKey getRSAPrivateKeyFromB64(String keyB64) throws NoSuchAlgorithmException, InvalidKeySpecException {
    var keyBytes = Base64.getDecoder().decode(keyB64);
    var keySpec = new PKCS8EncodedKeySpec(keyBytes);
    var keyFactory = KeyFactory.getInstance(RSA);
    return keyFactory.generatePrivate(keySpec);
  }

  public static PublicKey getRSAPublicKeyFromPrivateKey(String privateKeyB64) throws NoSuchAlgorithmException, InvalidKeySpecException {
    var privateKey = getRSAPrivateKeyFromB64(privateKeyB64);
    var keyFactory = KeyFactory.getInstance(RSA);
    var privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateCrtKeySpec.class);
    var publicKeySpec = new RSAPublicKeySpec(privateKeySpec.getModulus(), privateKeySpec.getPublicExponent());
    return keyFactory.generatePublic(publicKeySpec);
  }

  public static SecretKey getHMACKeyFromB64(String keyB64, Alg alg) {
    var keyBytes = Base64.getDecoder().decode(keyB64);
    return new SecretKeySpec(keyBytes, alg.algName);
  }

}
