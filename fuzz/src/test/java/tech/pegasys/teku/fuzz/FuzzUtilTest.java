/*
 * Copyright 2020 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package tech.pegasys.teku.fuzz;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.Long;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.junit.BouncyCastleExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.util.Optional;


@ExtendWith(BouncyCastleExtension.class)
class FuzzUtilTest {

  // Basic sanity tests for Fuzzing Harnesses

  private final FuzzUtil fuzzUtil = new FuzzUtil(true, true);

  // *************** START Shuffling Tests ***************

  @Test
  void shuffleInsufficientInput() {
    byte[] emptyInput = new byte[0];
    assertThat(fuzzUtil.fuzzShuffle(emptyInput)).isEmpty();
    assertThat(fuzzUtil.fuzzShuffle(Bytes.random(15).toArrayUnsafe())).isEmpty();
    // minimum length is 34
    assertThat(fuzzUtil.fuzzShuffle(Bytes.random(33).toArrayUnsafe())).isEmpty();
  }

  @Test
  void shuffleSufficientInput() {
    // minimum length is 34, and should succeed
    assertThat(fuzzUtil.fuzzShuffle(Bytes.random(34).toArrayUnsafe())).isPresent();
    assertThat(fuzzUtil.fuzzShuffle(Bytes.random(80).toArrayUnsafe())).isPresent();

    // first 2 bytes (little endian) % 100 provide the count, the rest the seed
    // 1000 = 16 (little endian)
    byte[] input = Bytes.fromHexString("0x10000000000000000000000000000000000000000000000000000000000000000000").toArrayUnsafe();
    assertThat(fuzzUtil.fuzzShuffle(input)).hasValueSatisfying(b -> {
        assertThat(b).hasSize(16 * Long.BYTES);
    });
  }

  // *************** END Shuffling Tests *****************
}
