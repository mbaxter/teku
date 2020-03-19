package tech.pegasys.artemis.statetransition.util;

import java.util.ArrayList;
import java.util.List;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.LongBuffer;
import java.nio.ByteOrder;
import java.util.Optional;
import java.lang.Long;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.artemis.datastructures.util.CommitteeUtil;
import tech.pegasys.artemis.datastructures.util.BeaconStateUtil;
import tech.pegasys.artemis.datastructures.util.SimpleOffsetSerializer;
import tech.pegasys.artemis.statetransition.util.BlockProcessingException;
import tech.pegasys.artemis.util.SSZTypes.SSZContainer;
import tech.pegasys.artemis.util.sos.SimpleOffsetSerializable;
import tech.pegasys.artemis.util.config.Constants;
import tech.pegasys.artemis.datastructures.state.BeaconState;
import tech.pegasys.artemis.datastructures.state.BeaconStateWithCache;
import tech.pegasys.artemis.datastructures.operations.Attestation;
import tech.pegasys.artemis.util.reflectionInformation.ReflectionInformation;

// TODO a Java FuzzHarness interface? - that way type safety can be checked at compile time
// JNI removes type safety
public class FuzzUtil {
  // TODO set config as initialization param here? see util/src/main/java/tech/pegasys/artemis/util/config/Constants.java setConstants
  // though is a global setting so kinda weird to allow that side-effect within a constructor
  // a static "initialize" function could make more sense, but doesn't set a requirement that it is called before any
  // fuzzing harness
  //
  // Could also have these all in separate classes, which implement a "FuzzHarness" interface

  // Size of ValidatorIndex returned by shuffle
  // private static final int VALIDATOR_INDEX_BYTES = Integer.BYTES;
  private static final int OUTPUT_INDEX_BYTES = Long.BYTES;

  // NOTE: this uses primitive values as parameters to more easily call via JNI
  public FuzzUtil(boolean useMainnetConfig, boolean disable_bls) {
    if (useMainnetConfig) {
      Constants.setConstants("mainnet");
    } else {
      Constants.setConstants("minimal");
    }
    if (disable_bls) {
      // TODO enable/disable BLS verification
      // TODO implement
    }
    // Only absent if this class has already been instantiated
    SimpleOffsetSerializer.classReflectionInfo.computeIfAbsent(FuzzAttestationInput.class, cls -> new ReflectionInformation(cls));
  }

  // Make them instance methods if we need to pass initialization e.g. to what config to use or disable bls
  // final?
  public Optional<byte[]> fuzzShuffle(final byte[] input){
    if (input.length < (32 + 2)) {
      return Optional.empty();
    }
    // TODO check that these are the same
    int count = ((int) (0xFFFFFFFFL & BeaconStateUtil.bytes_to_int(Bytes.wrap(input, 0, 2)))) % 100;
    //System.out.printf("Java Count: %d\n", count);
    /*
    // little endian decoding of first 2 bytes to an "unsigned" int, then round to 100
    int count = ((0x000000FF & ((int)input[0])) | (0x000000FF & ((int)input[1]) << 8)) % 100;
    // could also use bytes_to_int but would need to still mask it to make it positive.
    */

    Bytes32 seed = Bytes32.wrap(input, 2);
    //System.out.println("JSeed: "+ seed.toHexString());

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
    //Bytes tmp = Bytes.wrapByteBuffer(result_bb);
    //System.out.println("Result: " + tmp.toHexString());
    return Optional.of(result_bb.array());
  }

  public  Optional<byte[]> fuzzAttestation(final byte[] input) {
    // allow exception to propagate on failure - indicates a preprocessing or deserializing error
    FuzzAttestationInput structuredInput = SimpleOffsetSerializer.deserialize(Bytes.wrap(input), FuzzAttestationInput.class);
    BeaconState state = BeaconStateWithCache.fromBeaconState(structuredInput.getState());
    // TODO remove
    System.out.println("Successfully deserialized!");
    List<Attestation> attestations = new ArrayList<>();
    attestations.add(structuredInput.getAttestation());

    // process attestation and return post state
    try {
      BlockProcessorUtil.process_attestations(state, attestations);
    } catch (BlockProcessingException e) {
      // "expected error"
      return Optional.empty();
    }
    Bytes output = SimpleOffsetSerializer.serialize(state);
    return Optional.of(output.toArrayUnsafe());
  }



  // TODO common abstract class for all operations that are state + op?
  // TODO move to separate package?

  private static class FuzzAttestationInput implements SimpleOffsetSerializable, SSZContainer {

    private BeaconState state;
    private Attestation attestation;

    public FuzzAttestationInput(final BeaconState state, final Attestation attestation) {
      this.state = state;
      this.attestation = attestation;
    }

    @Override
    public int getSSZFieldCount() {
      return state.getSSZFieldCount() + attestation.getSSZFieldCount();
    }

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
      return List.of(SimpleOffsetSerializer.serialize(state), SimpleOffsetSerializer.serialize(attestation));
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
