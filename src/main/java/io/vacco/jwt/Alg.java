package io.vacco.jwt;

public enum Alg {

  NONE("none", null),
  HS256("HmacSHA256", Jwt.HMAC),
  HS384("HmacSHA384", Jwt.HMAC),
  HS512("HmacSHA512", Jwt.HMAC),
  RS256("SHA256withRSA", Jwt.RSA),
  RS384("SHA384withRSA", Jwt.RSA),
  RS512("SHA512withRSA", Jwt.RSA);

  public final String algName;
  public final String type;

  Alg(String algName, String type) {
    this.algName = algName;
    this.type = type;
  }

}
