package com.example.util;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.springframework.security.crypto.codec.Hex;

public class KeyExchange {

  private final KeyPair keyPair;

  public KeyExchange() {
    try {
      var keyPairGenerator = KeyPairGenerator.getInstance("EC");
      keyPairGenerator.initialize(256);
      this.keyPair = keyPairGenerator.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public String getPublicKey() {
    byte[] publicKey = keyPair.getPublic().getEncoded();
    return new String(Hex.encode(publicKey));
  }

  public byte[] establishAes256bitKey(String peerPublicKey) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance("EC");
      var publicKeySpec = new X509EncodedKeySpec(Hex.decode(peerPublicKey));
      var publicKey = keyFactory.generatePublic(publicKeySpec);
      return establishAes256bitKey(publicKey);
    } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }

  private byte[] establishAes256bitKey(PublicKey peerPublicKey)
      throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
    var keyAgreement = KeyAgreement.getInstance("ECDH");
    keyAgreement.init(keyPair.getPrivate());

    keyAgreement.doPhase(peerPublicKey, true);
    var generatedSecret = keyAgreement.generateSecret();
    return deriveAes256bitKey(generatedSecret);
  }

  private byte[] deriveAes256bitKey(byte[] input)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    var secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    var keySpec = new PBEKeySpec(new String(input).toCharArray(), input, 1024, 256);
    return secretKeyFactory.generateSecret(keySpec).getEncoded();
  }
}
