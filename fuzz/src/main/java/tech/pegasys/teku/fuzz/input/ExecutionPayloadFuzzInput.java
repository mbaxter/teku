/*
 * Copyright ConsenSys Software Inc., 2022
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

package tech.pegasys.teku.fuzz.input;

import tech.pegasys.teku.infrastructure.ssz.containers.Container2;
import tech.pegasys.teku.infrastructure.ssz.containers.ContainerSchema2;
import tech.pegasys.teku.infrastructure.ssz.schema.SszSchema;
import tech.pegasys.teku.infrastructure.ssz.tree.TreeNode;
import tech.pegasys.teku.spec.Spec;
import tech.pegasys.teku.spec.SpecVersion;
import tech.pegasys.teku.spec.datastructures.blocks.blockbody.versions.capella.BeaconBlockBodySchemaCapella;
import tech.pegasys.teku.spec.datastructures.execution.versions.capella.ExecutionPayloadCapellaImpl;
import tech.pegasys.teku.spec.datastructures.execution.versions.capella.ExecutionPayloadSchemaCapella;
import tech.pegasys.teku.spec.datastructures.state.beaconstate.BeaconState;

public class ExecutionPayloadFuzzInput
    extends Container2<ExecutionPayloadFuzzInput, BeaconState, ExecutionPayloadCapellaImpl> {

  public static ContainerSchema2<
          ExecutionPayloadFuzzInput, BeaconState, ExecutionPayloadCapellaImpl>
      createSchema(final SpecVersion spec) {
    BeaconBlockBodySchemaCapella<?> beaconBlockBodySchema =
        spec.getSchemaDefinitions().getBeaconBlockBodySchema().toVersionCapella().orElseThrow();
    return ContainerSchema2.create(
        SszSchema.as(BeaconState.class, spec.getSchemaDefinitions().getBeaconStateSchema()),
        (ExecutionPayloadSchemaCapella) beaconBlockBodySchema.getExecutionPayloadSchema(),
        ExecutionPayloadFuzzInput::new);
  }

  public ExecutionPayloadFuzzInput(
      ContainerSchema2<ExecutionPayloadFuzzInput, BeaconState, ExecutionPayloadCapellaImpl> type,
      TreeNode backingNode) {
    super(type, backingNode);
  }

  public ExecutionPayloadFuzzInput(
      final Spec spec,
      final BeaconState state,
      final ExecutionPayloadCapellaImpl executionPayload) {
    super(createSchema(spec.atSlot(state.getSlot())), state, executionPayload);
  }

  public ExecutionPayloadCapellaImpl getExecutionPayload() {
    return getField1();
  }

  public BeaconState getState() {
    return getField0();
  }
}
