/*
 * Copyright 2022 ConsenSys AG.
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

package tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.bellatrix;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

import java.util.function.Supplier;
import tech.pegasys.teku.infrastructure.async.SafeFuture;
import tech.pegasys.teku.spec.datastructures.blocks.BeaconBlock;
import tech.pegasys.teku.spec.datastructures.blocks.SignedBeaconBlock;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.common.AbstractSignedBeaconBlockUnblinder;
import tech.pegasys.teku.spec.datastructures.execution.ExecutionPayload;
import tech.pegasys.teku.spec.schemas.SchemaDefinitionsBellatrix;

public class SignedBeaconBlockUnblinderBellatrix extends AbstractSignedBeaconBlockUnblinder {
  protected SafeFuture<ExecutionPayload> executionPayloadFuture;

  public SignedBeaconBlockUnblinderBellatrix(
      final SchemaDefinitionsBellatrix schemaDefinitions,
      final SignedBeaconBlock signedBlindedBeaconBlock) {
    super(schemaDefinitions, signedBlindedBeaconBlock);
  }

  @Override
  public void setExecutionPayloadSupplier(
      Supplier<SafeFuture<ExecutionPayload>> executionPayloadSupplier) {
    this.executionPayloadFuture = executionPayloadSupplier.get();
  }

  @Override
  public SafeFuture<SignedBeaconBlock> unblind() {
    BeaconBlock blindedBeaconBlock = signedBlindedBeaconBlock.getMessage();
    if (!blindedBeaconBlock.getBody().isBlinded()) {
      return SafeFuture.completedFuture(signedBlindedBeaconBlock);
    }

    checkNotNull(executionPayloadFuture, "executionPayload must be set");

    return executionPayloadFuture.thenApply(
        executionPayload -> {
          final BlindedBeaconBlockBodyBellatrix blindedBody =
              BlindedBeaconBlockBodyBellatrix.required(blindedBeaconBlock.getBody());

          checkState(
              executionPayload
                  .hashTreeRoot()
                  .equals(blindedBody.getExecutionPayloadHeader().hashTreeRoot()),
              "executionPayloadHeader root in blinded block do not match provided executionPayload root");

          final BeaconBlockBodyBellatrix unblindedBody =
              new BeaconBlockBodyBellatrixImpl(
                  (BeaconBlockBodySchemaBellatrixImpl) schemaDefinitions.getBeaconBlockBodySchema(),
                  blindedBody.getRandaoRevealSsz(),
                  blindedBody.getEth1Data(),
                  blindedBody.getGraffitiSsz(),
                  blindedBody.getProposerSlashings(),
                  blindedBody.getAttesterSlashings(),
                  blindedBody.getAttestations(),
                  blindedBody.getDeposits(),
                  blindedBody.getVoluntaryExits(),
                  blindedBody.getSyncAggregate(),
                  executionPayload);

          final BeaconBlock unblindedBeaconBlock =
              schemaDefinitions
                  .getBeaconBlockSchema()
                  .create(
                      blindedBeaconBlock.getSlot(),
                      blindedBeaconBlock.getProposerIndex(),
                      blindedBeaconBlock.getParentRoot(),
                      blindedBeaconBlock.getStateRoot(),
                      unblindedBody);

          checkState(
              unblindedBeaconBlock.hashTreeRoot().equals(blindedBeaconBlock.hashTreeRoot()),
              "unblinded block root do not match original blinded block root");

          return schemaDefinitions
              .getSignedBeaconBlockSchema()
              .create(unblindedBeaconBlock, signedBlindedBeaconBlock.getSignature());
        });
  }
}
