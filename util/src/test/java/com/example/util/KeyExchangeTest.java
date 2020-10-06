package com.example.util;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class KeyExchangeTest {

  @Test
  void testKeyExchange() {
    var alice = new KeyExchange();
    var bob = new KeyExchange();

    var key1 = alice.establishKey(bob.getPublicKey());
    var key2 = bob.establishKey(alice.getPublicKey());

    Assertions.assertThat(key1).isEqualTo(key2);
  }
}
