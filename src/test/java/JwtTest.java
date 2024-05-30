import com.google.gson.Gson;
import io.vacco.jwt.*;
import j8spec.annotation.DefinedOrder;
import j8spec.junit.J8SpecRunner;
import org.junit.runner.RunWith;
import java.security.*;
import java.security.interfaces.*;

import static j8spec.J8Spec.*;

@DefinedOrder
@RunWith(J8SpecRunner.class)
public class JwtTest {

  private static final Gson g = new Gson();

  static {
    it("Decodes and verifies a JWT token", () -> {
      // Generate RSA key pair for testing
      var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();

      var privateKey = (RSAPrivateKey) keyPair.getPrivate();
      var publicKey = (RSAPublicKey) keyPair.getPublic();

      // Example payload
      var payload = "{ \"sub\": \"1234567890\", \"name\": \"John Doe\", \"admin\": true }";

      // Create a JWT and set its algorithm to RS256
      var jwt = new Jwt();
      jwt.setAlg(Alg.RS256, privateKey.getEncoded());
      jwt.addGrant("sub", "1234567890");
      jwt.addGrant("name", "John Doe");
      jwt.addGrant("admin", "true");

      // Encode the JWT
      var token = jwt.encode(g::toJson);
      System.out.println("Encoded JWT: " + token);

      // Decode and verify the JWT
      var decodedJwt = Jwt.decode(token, g::fromJson);
      decodedJwt.setAlg(Alg.RS256, publicKey.getEncoded());

      var isValid = decodedJwt.verify(token);
      System.out.println("Is JWT valid? " + isValid);
    });

    it("Validates a JWT token", () -> {
      // Generate RSA key pair for testing
      var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      var keyPair = keyPairGenerator.generateKeyPair();

      var privateKey = (RSAPrivateKey) keyPair.getPrivate();
      var publicKey = (RSAPublicKey) keyPair.getPublic();

      // Create a JWT and set its algorithm to RS256
      var jwt = new Jwt();
      jwt.setAlg(Alg.RS256, privateKey.getEncoded());
      jwt.addGrant("sub", "1234567890");
      jwt.addGrant("name", "John Doe");
      jwt.addGrant("admin", true);
      jwt.addGrant("exp", jwt.nowPlus(3600)); // 1 hour expiry

      // Encode the JWT
      var token = jwt.encode(g::toJson);
      System.out.println("Encoded JWT: " + token);

      // Decode the JWT
      var decodedJwt = Jwt.decode(token, g::fromJson);
      decodedJwt.setAlg(Alg.RS256, publicKey.getEncoded());

      // Verify the JWT signature
      var isSignatureValid = decodedJwt.verify(token);
      System.out.println("Is JWT signature valid? " + isSignatureValid);

      if (isSignatureValid) {
        // Validate the JWT claims
        var jwtValidation = new JwtValidation(Alg.RS256);
        jwtValidation.setExpLeeway(60); // 1 minute leeway for expiration
        jwtValidation.addGrant("admin", true); // require "admin" to be true

        var validationStatus = jwtValidation.validate(decodedJwt);
        var isValid = validationStatus == JwtValidation.SUCCESS;

        System.out.println("Is JWT valid? " + isValid);
        System.out.println("Validation errors: " + JwtValidation.toString(validationStatus));
      }
    });
  }
}
