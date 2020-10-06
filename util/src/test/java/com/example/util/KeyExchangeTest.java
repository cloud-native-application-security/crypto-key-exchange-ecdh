package com.example.util;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class KeyExchangeTest {

  @Test
  void testKeyExchange() {
    var alice = new KeyExchange();
    var bob = new KeyExchange();

    var key1 = alice.establishAes256bitKey(bob.getPublicKey());
    var key2 = bob.establishAes256bitKey(alice.getPublicKey());

    assertThat(key1).isEqualTo(key2);
    assertThat(key1.length).isEqualTo(32);
  }
}
