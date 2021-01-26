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

package tech.pegasys.teku.cli.options;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import tech.pegasys.teku.cli.AbstractBeaconNodeCommandTest;
import tech.pegasys.teku.config.TekuConfiguration;
import tech.pegasys.teku.networking.eth2.P2PConfig;
import tech.pegasys.teku.networking.p2p.network.config.NetworkConfig;

public class P2POptionsTest extends AbstractBeaconNodeCommandTest {

  @Test
  public void shouldReadFromConfigurationFile() {
    final TekuConfiguration tekuConfig = getTekuConfigurationFromFile("P2POptions_config.yaml");

    final P2PConfig p2pConfig = tekuConfig.p2p();
    assertThat(p2pConfig.isP2PEnabled()).isTrue();
    assertThat(p2pConfig.isDiscoveryEnabled()).isTrue();
    assertThat(p2pConfig.getTargetSubnetSubscriberCount()).isEqualTo(5);
    assertThat(p2pConfig.getMinPeers()).isEqualTo(70);
    assertThat(p2pConfig.getMaxPeers()).isEqualTo(85);
    assertThat(p2pConfig.getMinRandomlySelectedPeers()).isEqualTo(1);

    final NetworkConfig networkConfig = tekuConfig.network();
    assertThat(networkConfig.getAdvertisedIp()).isEqualTo("127.200.0.1");
    assertThat(networkConfig.getNetworkInterface()).isEqualTo("127.100.0.1");
    assertThat(networkConfig.getListenPort()).isEqualTo(4321);
    assertThat(networkConfig.getPrivateKeyFile()).contains("/the/file");
    assertThat(networkConfig.getStaticPeers()).isEqualTo(List.of("127.1.0.1", "127.1.1.1"));
  }

  @Test
  public void p2pEnabled_shouldNotRequireAValue() {
    final P2PConfig globalConfiguration = getTekuConfigurationFromArguments("--p2p-enabled").p2p();
    assertThat(globalConfiguration.isP2PEnabled()).isTrue();
  }

  @Test
  public void p2pDiscoveryEnabled_shouldNotRequireAValue() {
    final P2PConfig config =
        getTekuConfigurationFromArguments("--p2p-discovery-enabled").beaconChain().p2pConfig();
    assertThat(config.isP2PEnabled()).isTrue();
  }

  @Test
  public void advertisedIp_shouldDefaultToEmpty() {
    final NetworkConfig config = getTekuConfigurationFromArguments().network();
    assertThat(config.hasUserExplicitlySetAdvertisedIp()).isFalse();
  }

  @Test
  public void advertisedIp_shouldAcceptValue() {
    final String ip = "10.0.1.200";
    assertThat(
            getTekuConfigurationFromArguments("--p2p-advertised-ip", ip)
                .network()
                .getAdvertisedIp())
        .contains(ip);
  }

  @Test
  public void advertisedPort_shouldDefaultToListenPort() {
    assertThat(getTekuConfigurationFromArguments().network().getAdvertisedPort()).isEqualTo(9000);
  }

  @Test
  public void advertisedPort_shouldAcceptValue() {
    assertThat(
            getTekuConfigurationFromArguments("--p2p-advertised-port", "8056")
                .network()
                .getAdvertisedPort())
        .isEqualTo(8056);
  }

  @Test
  public void minimumRandomlySelectedPeerCount_shouldDefaultTo20PercentOfLowerBound() {
    assertThat(
            getTekuConfigurationFromArguments(
                    "--p2p-peer-lower-bound", "100",
                    "--p2p-peer-upper-bound", "110")
                .p2p()
                .getMinRandomlySelectedPeers())
        .isEqualTo(20);
  }

  @Test
  public void privateKeyFile_shouldBeSettable() {
    assertThat(
            getTekuConfigurationFromArguments("--p2p-private-key-file", "/some/file")
                .network()
                .getPrivateKeyFile())
        .contains("/some/file");
  }

  @Test
  public void privateKeyFile_ignoreBlankStrings() {
    assertThat(
            getTekuConfigurationFromArguments("--p2p-private-key-file", "   ")
                .network()
                .getPrivateKeyFile())
        .isEmpty();
  }

  @Test
  public void minimumRandomlySelectedPeerCount_canBeOverriden() {
    assertThat(
            getTekuConfigurationFromArguments(
                    "--p2p-peer-lower-bound", "100",
                    "--p2p-peer-upper-bound", "110",
                    "--Xp2p-minimum-randomly-selected-peer-count", "40")
                .p2p()
                .getMinRandomlySelectedPeers())
        .isEqualTo(40);
  }
}
