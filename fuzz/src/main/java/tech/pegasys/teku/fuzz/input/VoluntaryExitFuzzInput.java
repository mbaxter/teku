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

package tech.pegasys.teku.fuzz.input;

import java.util.ArrayList;
import java.util.List;
import org.apache.tuweni.bytes.Bytes;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.teku.datastructures.operations.SignedVoluntaryExit;
import tech.pegasys.teku.datastructures.operations.VoluntaryExit;
import tech.pegasys.teku.datastructures.state.BeaconState;
import tech.pegasys.teku.datastructures.state.BeaconStateImpl;
import tech.pegasys.teku.datastructures.util.SimpleOffsetSerializer;
import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.teku.ssz.SSZTypes.SSZContainer;
import tech.pegasys.teku.ssz.sos.SimpleOffsetSerializable;

public class VoluntaryExitFuzzInput implements SimpleOffsetSerializable, SSZContainer {

  // TODO should this be a BeaconState or BeaconStateImpl?
  private BeaconStateImpl state;
  private SignedVoluntaryExit exit;

  public VoluntaryExitFuzzInput(final BeaconStateImpl state, final SignedVoluntaryExit exit) {
    this.state = state;
    this.exit = exit;
  }

  // NOTE: empty constructor is needed for reflection/introspection
  // TODO how is new ReflectionInformation(VoluntaryExit.class) supposed to work when
  // it cals newInstance() with no arguments but VoluntaryExit has no 0 arg constructor?
  public VoluntaryExitFuzzInput() {
    this(
        new BeaconStateImpl(),
        new SignedVoluntaryExit(
            new VoluntaryExit(UInt64.valueOf(0), UInt64.valueOf(0)), BLSSignature.empty()));
  }

  @Override
  public int getSSZFieldCount() {
    return state.getSSZFieldCount() + exit.getSSZFieldCount();
  }

  @Override
  public List<Bytes> get_fixed_parts() {
    List<Bytes> fixedPartsList = new ArrayList<>();
    fixedPartsList.add(Bytes.EMPTY);
    fixedPartsList.add(SimpleOffsetSerializer.serialize(exit));
    return fixedPartsList;
  }

  @Override
  public List<Bytes> get_variable_parts() {
    return List.of(SimpleOffsetSerializer.serialize(state), Bytes.EMPTY);
  }

  /** ******************* * GETTERS & SETTERS * * ******************* */
  public SignedVoluntaryExit getExit() {
    return exit;
  }

  public BeaconState getState() {
    return state;
  }
}
