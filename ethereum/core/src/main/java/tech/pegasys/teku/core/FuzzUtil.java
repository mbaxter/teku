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

package tech.pegasys.artemis.statetransition.util;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.Optional;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.artemis.datastructures.operations.Attestation;
import tech.pegasys.artemis.datastructures.state.BeaconState;
import tech.pegasys.artemis.datastructures.state.BeaconStateImpl;
import tech.pegasys.artemis.datastructures.state.MutableBeaconState;
import tech.pegasys.artemis.datastructures.util.BeaconStateUtil;
import tech.pegasys.artemis.datastructures.util.CommitteeUtil;
import tech.pegasys.artemis.datastructures.util.SimpleOffsetSerializer;
import tech.pegasys.artemis.util.SSZTypes.SSZContainer;
import tech.pegasys.artemis.util.config.Constants;
import tech.pegasys.artemis.util.sos.ReflectionInformation;
import tech.pegasys.artemis.util.sos.SimpleOffsetSerializable;
import tech.pegasys.artemis.util.SSZTypes.SSZList;

// TODO a Java FuzzHarness interface? - that way type safety can be checked at compile time
// JNI removes type safety
public class FuzzUtil {
  // TODO set config as initialization param here? see
  // util/src/main/java/tech/pegasys/artemis/util/config/Constants.java setConstants
  // though is a global setting so kinda weird to allow that side-effect within a constructor
  // a static "initialize" function could make more sense, but doesn't set a requirement that it is
  // called before any
  // fuzzing harness
  //
  // Could also have these all in separate classes, which implement a "FuzzHarness" interface

  // Size of ValidatorIndex returned by shuffle
  // private static final int VALIDATOR_INDEX_BYTES = Integer.BYTES;
  private static final int OUTPUT_INDEX_BYTES = Long.BYTES;

  // NOTE: this uses primitive values as parameters to more easily call via JNI
  public FuzzUtil(final boolean useMainnetConfig, final boolean disable_bls) {
    // NOTE: makes global Constants/config changes
    if (useMainnetConfig) {
      Constants.setConstants("mainnet");
    } else {
      Constants.setConstants("minimal");
    }
    // TODO check if these are needed after setting constants:
    BeaconStateImpl.resetSSZType(); // TODO getSSZType() is not directly used for deserialization but I'm guessing this might be necessary soon?
    SimpleOffsetSerializer.setConstants();
    System.out.println("Here!");
    SimpleOffsetSerializer.classReflectionInfo.put(AttestationFuzzInput.class, new ReflectionInformation(AttestationFuzzInput.class));

    if (disable_bls) {
      // TODO enable/disable BLS verification
      // TODO implement
    }
  }

  public Optional<byte[]> fuzzShuffle(final byte[] input) {
    if (input.length < (32 + 2)) {
      return Optional.empty();
    }
    // TODO check that these are the same
    int count = ((int) (0xFFFFFFFFL & BeaconStateUtil.bytes_to_int(Bytes.wrap(input, 0, 2)))) % 100;
    // System.out.printf("Java Count: %d\n", count);
    /*
    // little endian decoding of first 2 bytes to an "unsigned" int, then round to 100
    int count = ((0x000000FF & ((int)input[0])) | (0x000000FF & ((int)input[1]) << 8)) % 100;
    // could also use bytes_to_int but would need to still mask it to make it positive.
    */

    Bytes32 seed = Bytes32.wrap(input, 2);
    // System.out.println("JSeed: "+ seed.toHexString());

    // NOTE: could use the following, but that is not used by the current implementation
    // int[] shuffled = BeaconStateUtil.shuffle(count, seed);
    // TODO shuffle returns an int (int32), but should be uint64 == (java long is int64)
    // so does this break if validator indexes are negative integers?
    // use a google UnsignedLong?
    // anything weird with signedness here?
    // any risk here? - not for this particular fuzzing as we only count <= 100

    // NOTE: although compute_shuffled_index returns an int, we save as a long for consistency
    ByteBuffer result_bb = ByteBuffer.allocate(count * OUTPUT_INDEX_BYTES);
    // Convert to little endian bytes
    result_bb.order(ByteOrder.LITTLE_ENDIAN);

    for (int i = 0; i < count; i++) {
      result_bb.putLong(CommitteeUtil.compute_shuffled_index(i, count, seed));
    }
    // Bytes tmp = Bytes.wrapByteBuffer(result_bb);
    // System.out.println("Result: " + tmp.toHexString());
    return Optional.of(result_bb.array());
  }

  public Optional<byte[]> fuzzAttestation(final byte[] input) {
    // allow exception to propagate on failure - indicates a preprocessing or deserializing error
    AttestationFuzzInput structuredInput = SimpleOffsetSerializer.deserialize(Bytes.wrap(input), AttestationFuzzInput.class);
    if (structuredInput == null) {
      throw new RuntimeException("Failed to deserialize input. Likely a preprocessing or deserialization bug.");
    }
    // TODO remove
    System.out.println("Successfully deserialized!");
    MutableBeaconState state = structuredInput.getState().createWritableCopy();
    // process attestation and return post state
    try {
      BlockProcessorUtil.process_attestations(state, SSZList.singleton(structuredInput.getAttestation()));
    } catch (BlockProcessingException e) {
      // "expected error"
      return Optional.empty();
    }
    Bytes output = SimpleOffsetSerializer.serialize(state);
    return Optional.of(output.toArrayUnsafe());
  }

  /** ******************** Input Classes **********************/

  // TODO common abstract class for all operations that are state + op?
  // TODO move to separate package?
  // NOTE: not obvious how to have a generic "OperationFuzzInput" class because the get_fixed_parts and get_variable_parts
  // implementations can be different
  private static class AttestationFuzzInput implements SimpleOffsetSerializable, SSZContainer {

    // TODO should this be a BeaconState or BeaconStateImpl?
    private BeaconStateImpl state;
    private Attestation attestation;

    public AttestationFuzzInput(final BeaconStateImpl state, final Attestation attestation) {
      this.state = state;
      this.attestation = attestation;
    }

    // NOTE: empty constructor is needed for reflection/introspection
    public AttestationFuzzInput() {
      this(new BeaconStateImpl(), new Attestation());
    }


    @Override
    public int getSSZFieldCount() {
      return state.getSSZFieldCount() + attestation.getSSZFieldCount();
    }

    // Since its both fields are variable we leave untouched?
    /*@Override
    public List<Bytes> get_fixed_parts() {
    List<Bytes> fixedPartsList = new ArrayList<>();
    fixedPartsList.addAll(state.get_fixed_parts());
    fixedPartsList.addAll(attestation.get_fixed_parts());
    return fixedPartsList;
    }*/

    @Override
    public List<Bytes> get_variable_parts() {
      // Because we know both fields are variable and registered, we can just serialize.
      return List.of(
          SimpleOffsetSerializer.serialize(state), SimpleOffsetSerializer.serialize(attestation));
    }

    /** ******************* * GETTERS & SETTERS * * ******************* */
    public Attestation getAttestation() {
      return attestation;
    }

    public BeaconState getState() {
      return state;
    }
  }
}
