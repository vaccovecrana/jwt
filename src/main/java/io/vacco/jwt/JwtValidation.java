package io.vacco.jwt;

import java.util.HashMap;
import java.util.Map;

public class JwtValidation {

  public static final int SUCCESS = 0;
  public static final int ERROR = 1;
  public static final int ALG_MISMATCH = 2;
  public static final int EXPIRED = 4;
  public static final int TOO_NEW = 8;
  public static final int GRANT_MISMATCH = 16;

  private Alg alg;
  private long nbfLeeway;
  private long expLeeway;
  private int hdr;
  private Map<String, Object> reqGrants;
  private int status;

  public JwtValidation(Alg alg) {
    this.alg = alg;
    this.reqGrants = new HashMap<>();
    this.status = ERROR;
  }

  public void setNbfLeeway(long nbfLeeway) {
    this.nbfLeeway = nbfLeeway;
  }

  public void setExpLeeway(long expLeeway) {
    this.expLeeway = expLeeway;
  }

  public void addGrant(String grant, Object value) {
    reqGrants.put(grant, value);
  }

  public int validate(Jwt jwt) {
    if (jwt == null) {
      this.status = ERROR;
      return this.status;
    }

    this.status = SUCCESS;

    // Validate algorithm
    if (this.alg != jwt.getAlg()) {
      this.status |= ALG_MISMATCH;
    }

    // Validate expiration
    long exp = jwt.getGrant("exp") instanceof Number ? ((Number) jwt.getGrant("exp")).longValue() : -1;
    var nowSec = jwt.nowSec();
    var nowMinusLeeway = nowSec - this.expLeeway;
    if (exp != -1 && nowMinusLeeway >= exp) {
      this.status |= EXPIRED;
    }

    // Validate not before
    long nbf = jwt.getGrant("nbf") instanceof Number ? ((Number) jwt.getGrant("nbf")).longValue() : -1;
    var nowPlusLeeway = nowSec + this.nbfLeeway;
    if (nbf != -1 && nowPlusLeeway < nbf) {
      this.status |= TOO_NEW;
    }

    // Validate required grants
    for (Map.Entry<String, Object> entry : reqGrants.entrySet()) {
      if (!entry.getValue().equals(jwt.getGrant(entry.getKey()))) {
        this.status |= GRANT_MISMATCH;
      }
    }

    return this.status;
  }

  public static String toString(int status) {
    var sb = new StringBuilder();
    if (status == SUCCESS) sb.append("SUCCESS ");
    if ((status & ERROR) == ERROR) sb.append("ERROR ");
    if ((status & ALG_MISMATCH) == ALG_MISMATCH) sb.append("ALG_MISMATCH ");
    if ((status & EXPIRED) == EXPIRED) sb.append("EXPIRED ");
    if ((status & TOO_NEW) == TOO_NEW) sb.append("TOO_NEW ");
    if ((status & GRANT_MISMATCH) == GRANT_MISMATCH) sb.append("GRANT_MISMATCH ");
    return sb.toString().trim();
  }

}
