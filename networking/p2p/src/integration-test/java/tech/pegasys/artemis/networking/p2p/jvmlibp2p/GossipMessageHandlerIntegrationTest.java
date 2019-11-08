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

package tech.pegasys.artemis.networking.p2p.jvmlibp2p;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import com.google.common.eventbus.EventBus;
import com.google.common.primitives.UnsignedLong;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import tech.pegasys.artemis.datastructures.blocks.BeaconBlock;
import tech.pegasys.artemis.network.p2p.jvmlibp2p.NetworkFactory;
import tech.pegasys.artemis.networking.p2p.JvmLibP2PNetwork;
import tech.pegasys.artemis.statetransition.BeaconChainUtil;
import tech.pegasys.artemis.storage.ChainStorageClient;
import tech.pegasys.artemis.util.Waiter;
import tech.pegasys.artemis.util.bls.BLSKeyGenerator;
import tech.pegasys.artemis.util.bls.BLSKeyPair;

public class GossipMessageHandlerIntegrationTest {

  private final List<BLSKeyPair> validatorKeys = BLSKeyGenerator.generateKeyPairs(12);
  private final EventBus eventBus = new EventBus();
  private final ChainStorageClient storageClient = new ChainStorageClient(eventBus);
  private final BeaconChainUtil chainUtil = BeaconChainUtil.create(validatorKeys, storageClient);

  private final NetworkFactory networkFactory = new NetworkFactory();

  @AfterEach
  public void tearDown() {
    networkFactory.stopAll();
  }

  @Test
  public void shouldGossipBlocksAcrossChainOfPeers_twoNodes() throws Exception {
    testGossipBlocksAcrossChainOfPeers(0);
  }

  @Test
  public void shouldGossipBlocksAcrossChainOfPeers_threeNodes() throws Exception {
    testGossipBlocksAcrossChainOfPeers(1);
  }

  @Test
  public void shouldGossipBlocksAcrossChainOfPeers_manyNodes() throws Exception {
    testGossipBlocksAcrossChainOfPeers(5);
  }

  private void testGossipBlocksAcrossChainOfPeers(final int intermediateNodeCount)
      throws Exception {
    final EventBus firstEventBus = new EventBus();
    final List<EventBus> eventBuses =
        Stream.generate(() -> spy(new EventBus()))
            .limit(intermediateNodeCount + 1)
            .collect(Collectors.toList());

    // Setup network
    final JvmLibP2PNetwork firstNode = createNetwork(firstEventBus);
    final JvmLibP2PNetwork lastNode = createNetwork(eventBuses.get(eventBuses.size() - 1));
    final List<JvmLibP2PNetwork> intermediateNodes =
        IntStream.range(0, intermediateNodeCount)
            .mapToObj(idx -> createNetwork(eventBuses.get(idx)))
            .collect(Collectors.toList());
    // Connect network into a chain
    JvmLibP2PNetwork currentNode = firstNode;
    for (JvmLibP2PNetwork intermediateNode : intermediateNodes) {
      currentNode.connect(intermediateNode.getPeerAddress());
      currentNode = intermediateNode;
    }
    currentNode.connect(lastNode.getPeerAddress());

    // Wait for connections to get set up
    Waiter.waitFor(
        () -> {
          assertThat(firstNode.getPeerManager().getAvailablePeerCount()).isEqualTo(1);
          assertThat(lastNode.getPeerManager().getAvailablePeerCount()).isEqualTo(1);
          for (JvmLibP2PNetwork intermediateNode : intermediateNodes) {
            assertThat(intermediateNode.getPeerManager().getAvailablePeerCount()).isEqualTo(2);
          }
        });
    // TODO: debug this - we shouldn't have to wait here
    Thread.sleep(2000);

    // Propagate block from network 1
    final BeaconBlock newBlock = chainUtil.createBlockAtSlot(UnsignedLong.valueOf(2L));
    firstEventBus.post(newBlock);

    // Listen for new block event to arrive to each node
    final Collection<BeaconBlock> propagatedBlocks = new ConcurrentLinkedQueue<>();
    Waiter.waitFor(
        () -> {
          final ArgumentCaptor<BeaconBlock> blockCaptor =
              ArgumentCaptor.forClass(BeaconBlock.class);
          for (EventBus bus : eventBuses) {
            verify(bus, atLeastOnce()).post(blockCaptor.capture());
          }
          propagatedBlocks.addAll(blockCaptor.getAllValues());
        });

    // Verify the expected block was gossiped across the network
    assertThat(propagatedBlocks.size()).isEqualTo(intermediateNodeCount + 1);
    for (BeaconBlock propagatedBlock : propagatedBlocks) {
      assertThat(propagatedBlock).isEqualTo(newBlock);
    }
  }

  private JvmLibP2PNetwork createNetwork(final EventBus eventBus) {
    final ChainStorageClient storageClient = new ChainStorageClient(eventBus);
    final JvmLibP2PNetwork network;
    try {
      network = networkFactory.startNetwork(eventBus, storageClient);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    BeaconChainUtil.initializeStorage(storageClient, validatorKeys);
    return network;
  }
}
