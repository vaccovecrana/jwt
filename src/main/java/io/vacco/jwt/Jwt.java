package io.vacco.jwt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public class Jwt {

  public static final String HMAC = "HMAC", RSA = "RSA";

  private Alg alg;
  private byte[] key;
  public  int keyLen;

  private Map<String, Object> grants;
  private Map<String, Object> headers;

  public Jwt() {
    this.alg = Alg.NONE;
    this.grants = new LinkedHashMap<>();
    this.headers = new LinkedHashMap<>();
  }

  public String encode(JsonOut out) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException {
    var headerJson = out.toJson(headers);
    var payloadJson = out.toJson(grants);
    var headerB64 = base64UrlEncode(headerJson);
    var payloadB64 = base64UrlEncode(payloadJson);
    var token = headerB64 + "." + payloadB64;
    if (alg != Alg.NONE) {
      var signature = sign(token.getBytes(StandardCharsets.UTF_8));
      token += "." + signature;
    }
    return token;
  }

  private String sign(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException {
    if (alg.type.equals(HMAC)) {
      var mac = Mac.getInstance(alg.algName);
      var secretKeySpec = new SecretKeySpec(key, alg.algName);
      mac.init(secretKeySpec);
      return base64UrlEncode(mac.doFinal(data));
    } else if (alg.type.equals(RSA)) {
      var signature = Signature.getInstance(alg.algName);
      signature.initSign(KeyFactory.getInstance(RSA).generatePrivate(new PKCS8EncodedKeySpec(key)));
      signature.update(data);
      return base64UrlEncode(signature.sign());
    }
    throw new UnsupportedOperationException("Unsupported algorithm");
  }

  public boolean verify(String token) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException {
    var parts = token.split("\\.");
    if (parts.length != 3) {
      return false;
    }

    var data = parts[0] + "." + parts[1];
    var signature = base64UrlDecode(parts[2]);

    if (alg.type.equals(HMAC)) {
      var mac = Mac.getInstance(alg.algName);
      var secretKeySpec = new SecretKeySpec(key, alg.algName);
      mac.init(secretKeySpec);
      var expectedSignature = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
      return MessageDigest.isEqual(signature, expectedSignature);
    } else if (alg.type.equals(RSA)) {
      var sig = Signature.getInstance(alg.algName);
      sig.initVerify(KeyFactory.getInstance(RSA).generatePublic(new X509EncodedKeySpec(key)));
      sig.update(data.getBytes(StandardCharsets.UTF_8));
      return sig.verify(signature);
    }
    throw new UnsupportedOperationException("Unsupported algorithm");
  }

  public static Jwt decode(String token, JsonIn in) {
    var parts = token.split("\\.");
    if (parts.length < 2) {
      throw new IllegalArgumentException("Invalid JWT token format");
    }

    var headerJson = new Jwt().base64UrlDecodeToString(parts[0]);
    var payloadJson = new Jwt().base64UrlDecodeToString(parts[1]);

    var jwt = new Jwt();
    jwt.headers = in.fromJson(headerJson, Map.class);
    jwt.headers = in.fromJson(headerJson, Map.class);
    jwt.grants = in.fromJson(payloadJson, Map.class);

    return jwt;
  }

  public Alg getAlg() {
    return alg;
  }

  public void setAlg(Alg alg, byte[] key) {
    this.alg = alg;
    this.key = key != null ? key.clone() : null;
    this.keyLen = key != null ? key.length : 0;
  }

  public void addGrant(String grant, Object value) {
    grants.put(grant, value);
  }

  public Object getGrant(String grant) {
    return grants.get(grant);
  }

  public void addHeader(String header, String value) {
    headers.put(header, value);
  }

  public Object getHeader(String header) {
    return headers.get(header);
  }

  private String base64UrlEncode(byte[] input) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(input);
  }

  private byte[] base64UrlDecode(String input) {
    return Base64.getUrlDecoder().decode(input);
  }

  private String base64UrlEncode(String input) {
    return base64UrlEncode(input.getBytes(StandardCharsets.UTF_8));
  }

  private String base64UrlDecodeToString(String input) {
    return new String(base64UrlDecode(input), StandardCharsets.UTF_8);
  }

  public long nowSec() {
    return System.currentTimeMillis() / 1000;
  }

  public long nowPlus(int sec) {
    return nowSec() + sec;
  }

  public long nowMinus(int sec) {
    return nowSec() - sec;
  }

}
