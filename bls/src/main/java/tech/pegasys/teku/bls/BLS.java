/*
 * Copyright 2019 ConsenSys AG.
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

package tech.pegasys.teku.bls;

import static com.google.common.base.Preconditions.checkArgument;

import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.apache.tuweni.bytes.Bytes;
import tech.pegasys.teku.bls.mikuli.BLS12381;
import tech.pegasys.teku.bls.mikuli.BLS12381.BatchSemiAggregate;
import tech.pegasys.teku.bls.mikuli.PublicKey;

/**
 * Implements the standard BLS functions used in Eth2 as defined in
 * https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02
 *
 * <p>This package strives to implement the BLS standard as used in the Eth2 specification and is
 * the entry-point for all BLS signature operations in Teku. Do not rely on any of the classes used
 * by this one conforming to the specification or standard.
 */
public class BLS {

  /*
   * The following are the methods used directly in the Ethereum 2.0 specifications. These strictly adhere to the standard.
   */

  /**
   * Generates a BLSSignature from a private key and message.
   *
   * <p>Implements https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.2.1
   *
   * @param secretKey The secret key, not null
   * @param message The message to sign, not null
   * @return The Signature, not null
   */
  public static BLSSignature sign(BLSSecretKey secretKey, Bytes message) {
    return new BLSSignature(BLS12381.sign(secretKey.getSecretKey(), message));
  }

  /**
   * Verifies the given BLS signature against the message bytes using the public key.
   *
   * <p>Implements https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.2.2
   *
   * @param publicKey The public key, not null
   * @param message The message data to verify, not null
   * @param signature The signature, not null
   * @return True if the verification is successful, false otherwise.
   */
  public static boolean verify(BLSPublicKey publicKey, Bytes message, BLSSignature signature) {
    return BLS12381.coreVerify(publicKey.getPublicKey(), message, signature.getSignature());
  }

  /**
   * Aggregates a list of BLSSignatures into a single BLSSignature.
   *
   * <p>Implements https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-2.8
   *
   * <p>The standard says to return INVALID if the list of signatures is empty. We choose to throw
   * an exception in this case. In addition, BLS12381.aggregate will throw an
   * IllegalArgumentException if any of the signatures is not a valid G2 curve point.
   *
   * @param signatures the list of signatures to be aggregated
   * @return the aggregated signature
   */
  public static BLSSignature aggregate(List<BLSSignature> signatures) {
    checkArgument(signatures.size() > 0, "Aggregating zero signatures is invalid.");
    return new BLSSignature(
        BLS12381.aggregate(signatures.stream().map(BLSSignature::getSignature)));
  }

  /**
   * Verifies an aggregate BLS signature against a list of distinct messages using the list of
   * public keys.
   *
   * <p>https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1.1
   *
   * <p>The standard says to return INVALID, that is, false, if the list of public keys is empty.
   * See also discussion at https://github.com/ethereum/eth2.0-specs/issues/1713
   *
   * <p>We also return false if any of the messages are duplicates.
   *
   * @param publicKeys The list of public keys, not null
   * @param messages The list of messages to verify, all distinct, not null
   * @param signature The aggregate signature, not null
   * @return True if the verification is successful, false otherwise
   */
  public static boolean aggregateVerify(
      List<BLSPublicKey> publicKeys, List<Bytes> messages, BLSSignature signature) {
    checkArgument(
        publicKeys.size() == messages.size(),
        "Number of public keys and number of messages differs.");
    if (publicKeys.isEmpty()) return false;
    // Check that there are no duplicate messages
    if (new HashSet<>(messages).size() != messages.size()) return false;
    List<PublicKey> publicKeyObjects =
        publicKeys.stream().map(BLSPublicKey::getPublicKey).collect(Collectors.toList());
    return BLS12381.coreAggregateVerify(publicKeyObjects, messages, signature.getSignature());
  }

  /**
   * Verifies an aggregate BLS signature against a message using the list of public keys.
   *
   * <p>Implements https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.3.4
   *
   * <p>The standard says to return INVALID, that is, false, if the list of public keys is empty.
   * See also discussion at https://github.com/ethereum/eth2.0-specs/issues/1713
   *
   * @param publicKeys The list of public keys, not null
   * @param message The message data to verify, not null
   * @param signature The aggregate signature, not null
   * @return True if the verification is successful, false otherwise
   */
  public static boolean fastAggregateVerify(
      List<BLSPublicKey> publicKeys, Bytes message, BLSSignature signature) {
    if (publicKeys.isEmpty()) return false;
    List<PublicKey> publicKeyObjects =
        publicKeys.stream().map(BLSPublicKey::getPublicKey).collect(Collectors.toList());
    return BLS12381.fastAggregateVerify(publicKeyObjects, message, signature.getSignature());
  }

  /*
   * The following implement optimised versions of the above. These may or may not follow the standard.
   */

  /**
   * Optimized version for verification of several BLS signatures in a single batch. See
   * https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407 for background
   *
   * <p>Parameters for verification are supplied with 3 lists which should have the same size. Each
   * set consists of a message, signature (aggregate or not), and a list of signers' public keys
   * (several or just a single one). See {@link #fastAggregateVerify(List, Bytes, BLSSignature)} for
   * reference.
   *
   * <p>Calls {@link #fastAggregateVerify(List, Bytes, BLSSignature)} if just a single signature
   * supplied If more than one signature passed then finds optimal parameters and delegates the call
   * to the advanced {@link #batchVerify(List, List, List, boolean, boolean)} method
   *
   * <p>The standard says to return INVALID, that is, false, if the list of public keys is empty.
   *
   * @return True if the verification is successful, false otherwise
   */
  public static boolean batchVerify(
      List<List<BLSPublicKey>> publicKeys, List<Bytes> messages, List<BLSSignature> signatures) {
    Preconditions.checkArgument(
        publicKeys.size() == messages.size() && publicKeys.size() == signatures.size(),
        "Different collection sizes");

    int count = publicKeys.size();
    if (count == 0) {
      return false;
    } else if (count == 1) {
      return fastAggregateVerify(publicKeys.get(0), messages.get(0), signatures.get(0));
    } else {
      // double pairing variant is normally slightly faster, but when the number of
      // signatures is relatively small the parallelization of hashToG2 internally
      // yields more performance gain than double pairing
      boolean doublePairing = count > Runtime.getRuntime().availableProcessors() * 2;
      return batchVerify(publicKeys, messages, signatures, doublePairing, true);
    }
  }

  /**
   * Optimized version for verification of several BLS signatures in a single batch. See
   * https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407 for background
   *
   * <p>Parameters for verification are supplied with 3 lists which should have the same size. Each
   * set consists of a message, signature (aggregate or not), and a list of signers' public keys
   * (several or just a single one). See {@link #fastAggregateVerify(List, Bytes, BLSSignature)} for
   * reference.
   *
   * <p>The standard says to return INVALID, that is, false, if the list of public keys is empty.
   *
   * @param doublePairing if true uses the optimized version of ate pairing (ate2) which processes a
   *     pair of signatures a bit faster than with 2 separate regular ate calls Note that this
   *     option may not be optimal when a number of signatures is relatively small and the
   *     [parallel] option is [true]
   * @param parallel Uses the default {@link java.util.concurrent.ForkJoinPool} to parallelize the
   *     work
   * @return True if the verification is successful, false otherwise
   */
  public static boolean batchVerify(
      List<List<BLSPublicKey>> publicKeys,
      List<Bytes> messages,
      List<BLSSignature> signatures,
      boolean doublePairing,
      boolean parallel) {
    Preconditions.checkArgument(
        publicKeys.size() == messages.size() && publicKeys.size() == signatures.size(),
        "Different collection sizes");
    int count = publicKeys.size();
    if (count == 0) return false;
    if (doublePairing) {
      Stream<List<Integer>> pairsStream =
          Lists.partition(IntStream.range(0, count).boxed().collect(Collectors.toList()), 2)
              .stream();

      if (parallel) {
        pairsStream = pairsStream.parallel();
      }
      return completeBatchVerify(
          pairsStream
              .map(
                  idx ->
                      idx.size() == 1
                          ? prepareBatchVerify(
                              idx.get(0),
                              publicKeys.get(idx.get(0)),
                              messages.get(idx.get(0)),
                              signatures.get(idx.get(0)))
                          : prepareBatchVerify2(
                              idx.get(0),
                              publicKeys.get(idx.get(0)),
                              messages.get(idx.get(0)),
                              signatures.get(idx.get(0)),
                              publicKeys.get(idx.get(1)),
                              messages.get(idx.get(1)),
                              signatures.get(idx.get(1))))
              .collect(Collectors.toList()));
    } else {
      Stream<Integer> indexStream = IntStream.range(0, count).boxed();

      if (parallel) {
        indexStream = indexStream.parallel();
      }
      return completeBatchVerify(
          indexStream
              .map(
                  idx ->
                      prepareBatchVerify(
                          idx, publicKeys.get(idx), messages.get(idx), signatures.get(idx)))
              .collect(Collectors.toList()));
    }
  }

  /**
   * {@link #prepareBatchVerify(int, List, Bytes, BLSSignature)} and {@link
   * #completeBatchVerify(List)} is just a split of the {@link #batchVerify(List, List, List)} onto
   * two separate procedures. {@link #prepareBatchVerify(int, List, Bytes, BLSSignature)} might be
   * e.g. called in background for asynchronous stream of signatures. The results should be
   * collected and then at some point verified with a final {@link #completeBatchVerify(List)} call
   *
   * @param index index of the signature in a batch. Used for minor optimization. -1 may be passed
   *     if no indexes are available
   * @param publicKeys The list of public keys, not null
   * @param message The message data to verify, not null
   * @param signature The aggregate signature, not null
   * @return An opaque instance which should be passed to the final step: {@link
   *     #completeBatchVerify(List)}
   */
  public static BatchSemiAggregate prepareBatchVerify(
      int index, List<BLSPublicKey> publicKeys, Bytes message, BLSSignature signature) {
    return BLS12381.prepareBatchVerify(
        index,
        publicKeys.stream().map(BLSPublicKey::getPublicKey).collect(Collectors.toList()),
        message,
        signature.getSignature());
  }

  /**
   * A slightly optimized variant of x2 {@link #prepareBatchVerify(int, List, Bytes, BLSSignature)}
   * calls when two signatures are available for processing
   *
   * <p>The returned instances can be mixed up with the instances returned by {@link
   * #prepareBatchVerify(int, List, Bytes, BLSSignature)}
   */
  public static BatchSemiAggregate prepareBatchVerify2(
      int index,
      List<BLSPublicKey> publicKeys1,
      Bytes message1,
      BLSSignature signature1,
      List<BLSPublicKey> publicKeys2,
      Bytes message2,
      BLSSignature signature2) {
    return BLS12381.prepareBatchVerify2(
        index,
        publicKeys1.stream().map(BLSPublicKey::getPublicKey).collect(Collectors.toList()),
        message1,
        signature1.getSignature(),
        publicKeys2.stream().map(BLSPublicKey::getPublicKey).collect(Collectors.toList()),
        message2,
        signature2.getSignature());
  }

  /**
   * The final step to verify semi aggregated signatures produced by {@link #prepareBatchVerify(int,
   * List, Bytes, BLSSignature)} or {@link #prepareBatchVerify2(int, List, Bytes, BLSSignature,
   * List, Bytes, BLSSignature)} or a mix of both
   *
   * @return True if the verification is successful, false otherwise
   */
  public static boolean completeBatchVerify(List<BatchSemiAggregate> preparedSignatures) {
    return BLS12381.completeBatchVerify(preparedSignatures);
  }
}
