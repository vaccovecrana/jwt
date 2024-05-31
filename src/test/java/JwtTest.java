import com.google.gson.Gson;
import io.vacco.jwt.*;
import j8spec.annotation.DefinedOrder;
import j8spec.junit.J8SpecRunner;
import org.junit.runner.RunWith;

import static j8spec.J8Spec.*;
import static io.vacco.jwt.JwtKeys.*;

@DefinedOrder
@RunWith(J8SpecRunner.class)
public class JwtTest {

  private static final Gson g = new Gson();
  private static final JwtKey rk = JwtKeys.generateKey(Alg.RS384, 2048);
  private static final JwtKey hk = JwtKeys.generateKey(Alg.HS384, 384);

  static {
    it("(RSA) Decodes and verifies a JWT token", () -> {
      // Create a JWT and set its algorithm to RS256
      var jwt = new Jwt();
      jwt.setAlg(rk.alg, getRSAPrivateKeyFromB64(rk.keyB64).getEncoded());
      jwt.addGrant("sub", "1234567890");
      jwt.addGrant("name", "John Doe");
      jwt.addGrant("admin", "true");

      // Encode the JWT
      var token = jwt.encode(g::toJson);
      System.out.println("Encoded JWT: " + token);

      // Decode and verify the JWT
      var decodedJwt = Jwt.decode(token, g::fromJson);
      decodedJwt.setAlg(rk.alg, getRSAPublicKeyFromPrivateKey(rk.keyB64).getEncoded());

      var isValid = decodedJwt.verify(token);
      System.out.println("Is JWT valid? " + isValid);
    });

    it("(RSA) Validates a JWT token", () -> {
      // Create a JWT and set its algorithm to RS256
      var jwt = new Jwt();
      jwt.setAlg(rk.alg, getRSAPrivateKeyFromB64(rk.keyB64).getEncoded());
      jwt.addGrant("sub", "1234567890");
      jwt.addGrant("name", "John Doe");
      jwt.addGrant("admin", true);
      jwt.setExpiration(jwt.nowPlus(3600));

      // Encode the JWT
      var token = jwt.encode(g::toJson);
      System.out.println("Encoded JWT: " + token);

      // Decode the JWT
      var decodedJwt = Jwt.decode(token, g::fromJson);
      decodedJwt.setAlg(rk.alg, getRSAPublicKeyFromPrivateKey(rk.keyB64).getEncoded());

      // Verify the JWT signature
      var isSignatureValid = decodedJwt.verify(token);
      System.out.println("Is JWT signature valid? " + isSignatureValid);

      if (isSignatureValid) {
        // Validate the JWT claims
        var jwtValidation = new JwtValidation(rk.alg);
        jwtValidation.setExpLeeway(60); // 1 minute leeway for expiration
        jwtValidation.addGrant("admin", true); // require "admin" to be true

        var validationStatus = jwtValidation.validate(decodedJwt);
        var isValid = validationStatus == JwtValidation.SUCCESS;

        System.out.println("Is JWT valid? " + isValid);
        System.out.println("Validation errors: " + JwtValidation.toString(validationStatus));
      }
    });

    it("(HMAC) Creates, verifies and validates a JWT token", () -> {
      // Create a JWT and set its algorithm to HS256
      var jwt = new Jwt();
      jwt.setAlg(hk.alg, getHMACKeyFromB64(hk.keyB64, hk.alg).getEncoded());
      jwt.addGrant("sub", "1234567890");
      jwt.addGrant("name", "John Doe");
      jwt.addGrant("admin", true);
      jwt.setExpiration(jwt.nowPlus(3600));

      // Encode the JWT
      var token = jwt.encode(g::toJson);
      System.out.println("Encoded JWT: " + token);

      // Decode the JWT
      var decodedJwt = Jwt.decode(token, g::fromJson);
      decodedJwt.setAlg(hk.alg, getHMACKeyFromB64(hk.keyB64, hk.alg).getEncoded());

      // Verify the JWT signature
      var isSignatureValid = decodedJwt.verify(token);
      System.out.println("Is JWT signature valid? " + isSignatureValid);

      if (isSignatureValid) {
        // Validate the JWT claims
        var jwtValidation = new JwtValidation(hk.alg);
        jwtValidation.setExpLeeway(60); // 1 minute leeway for expiration
        jwtValidation.addGrant("admin", true); // require "admin" to be true

        int validationStatus = jwtValidation.validate(decodedJwt);
        var isValid = validationStatus == JwtValidation.SUCCESS;

        System.out.println("Is JWT valid? " + isValid);
        if (!isValid) {
          System.out.println("Validation errors: " + JwtValidation.toString(validationStatus));
        }
      }
    });
  }
}
