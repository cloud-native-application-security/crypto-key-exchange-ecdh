package com.example.util;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class KeyExchangeTest {

  @Test
  void testKeyExchange() {
    var alice = new KeyExchange();
    var bob = new KeyExchange();

    var key1 = alice.establishAes256bitKey(bob.getPublicKey());
    var key2 = bob.establishAes256bitKey(alice.getPublicKey());

    Assertions.assertThat(key1).isEqualTo(key2);
    Assertions.assertThat(key1.length).isEqualTo(32);
  }
}
