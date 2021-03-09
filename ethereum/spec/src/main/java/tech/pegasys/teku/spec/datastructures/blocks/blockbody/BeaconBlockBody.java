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

package tech.pegasys.teku.spec.datastructures.blocks.blockbody;

import java.util.function.Function;
import org.apache.tuweni.bytes.Bytes32;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.teku.spec.datastructures.blocks.Eth1Data;
import tech.pegasys.teku.spec.datastructures.operations.Attestation;
import tech.pegasys.teku.spec.datastructures.operations.AttesterSlashing;
import tech.pegasys.teku.spec.datastructures.operations.Deposit;
import tech.pegasys.teku.spec.datastructures.operations.ProposerSlashing;
import tech.pegasys.teku.spec.datastructures.operations.SignedVoluntaryExit;
import tech.pegasys.teku.ssz.SSZTypes.SSZBackingList;
import tech.pegasys.teku.ssz.SSZTypes.SSZList;
import tech.pegasys.teku.ssz.backing.SszList;
import tech.pegasys.teku.ssz.backing.SszVector;
import tech.pegasys.teku.ssz.backing.containers.Container8;
import tech.pegasys.teku.ssz.backing.tree.TreeNode;
import tech.pegasys.teku.ssz.backing.view.SszPrimitives.SszByte;
import tech.pegasys.teku.ssz.backing.view.SszPrimitives.SszBytes32;
import tech.pegasys.teku.ssz.backing.view.SszUtils;
import tech.pegasys.teku.util.config.SpecDependent;

/** A Beacon block body */
public class BeaconBlockBody
    extends Container8<
        BeaconBlockBody,
        SszVector<SszByte>,
        Eth1Data,
        SszBytes32,
        SszList<ProposerSlashing>,
        SszList<AttesterSlashing>,
        SszList<Attestation>,
        SszList<Deposit>,
        SszList<SignedVoluntaryExit>> {

  public static BeaconBlockBodySchema getSszSchema() {
    return SSZ_SCHEMA.get();
  }

  public static final SpecDependent<BeaconBlockBodySchema> SSZ_SCHEMA =
      SpecDependent.of(BeaconBlockBodySchema::create);

  private BLSSignature randaoRevealCache;

  BeaconBlockBody(BeaconBlockBodySchema type, TreeNode backingNode) {
    super(type, backingNode);
  }

  BeaconBlockBody(
      BeaconBlockBodySchema type,
      BLSSignature randao_reveal,
      Eth1Data eth1_data,
      Bytes32 graffiti,
      SSZList<ProposerSlashing> proposer_slashings,
      SSZList<AttesterSlashing> attester_slashings,
      SSZList<Attestation> attestations,
      SSZList<Deposit> deposits,
      SSZList<SignedVoluntaryExit> voluntary_exits) {
    super(
        type,
        SszUtils.toSszByteVector(randao_reveal.toBytesCompressed()),
        eth1_data,
        new SszBytes32(graffiti),
        SszUtils.toSszList(type.getProposerSlashingsSchema(), proposer_slashings),
        SszUtils.toSszList(type.getAttesterSlashingsSchema(), attester_slashings),
        SszUtils.toSszList(type.getAttestationsSchema(), attestations),
        SszUtils.toSszList(type.getDepositsSchema(), deposits),
        SszUtils.toSszList(type.getVoluntaryExitsSchema(), voluntary_exits));
    this.randaoRevealCache = randao_reveal;
  }

  public BeaconBlockBody() {
    super(SSZ_SCHEMA.get());
  }

  public BLSSignature getRandao_reveal() {
    if (randaoRevealCache == null) {
      randaoRevealCache = BLSSignature.fromBytesCompressed(SszUtils.getAllBytes(getField0()));
    }
    return randaoRevealCache;
  }

  public Eth1Data getEth1_data() {
    return getField1();
  }

  public Bytes32 getGraffiti() {
    return getField2().get();
  }

  public SSZList<ProposerSlashing> getProposer_slashings() {
    return new SSZBackingList<>(
        ProposerSlashing.class, getField3(), Function.identity(), Function.identity());
  }

  public SSZList<AttesterSlashing> getAttester_slashings() {
    return new SSZBackingList<>(
        AttesterSlashing.class, getField4(), Function.identity(), Function.identity());
  }

  public SSZList<Attestation> getAttestations() {
    return new SSZBackingList<>(
        Attestation.class, getField5(), Function.identity(), Function.identity());
  }

  public SSZList<Deposit> getDeposits() {
    return new SSZBackingList<>(
        Deposit.class, getField6(), Function.identity(), Function.identity());
  }

  public SSZList<SignedVoluntaryExit> getVoluntary_exits() {
    return new SSZBackingList<>(
        SignedVoluntaryExit.class, getField7(), Function.identity(), Function.identity());
  }
}
