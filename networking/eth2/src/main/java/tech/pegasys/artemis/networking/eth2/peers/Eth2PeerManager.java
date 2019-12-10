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

package tech.pegasys.artemis.networking.eth2.peers;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.hyperledger.besu.plugin.services.MetricsSystem;
import org.jetbrains.annotations.NotNull;
import tech.pegasys.artemis.networking.eth2.rpc.beaconchain.BeaconChainMethods;
import tech.pegasys.artemis.networking.eth2.rpc.beaconchain.methods.StatusMessageFactory;
import tech.pegasys.artemis.networking.eth2.rpc.core.RpcMethods;
import tech.pegasys.artemis.networking.p2p.network.PeerHandler;
import tech.pegasys.artemis.networking.p2p.peer.NodeId;
import tech.pegasys.artemis.networking.p2p.peer.Peer;
import tech.pegasys.artemis.storage.ChainStorageClient;

public class Eth2PeerManager implements PeerHandler {
  private static final Logger LOG = LogManager.getLogger();
  private final StatusMessageFactory statusMessageFactory;

  private ConcurrentHashMap<NodeId, Eth2Peer> connectedPeerMap = new ConcurrentHashMap<>();

  private final RpcMethods rpcMethods;

  public Eth2PeerManager(
      final ChainStorageClient chainStorageClient, final MetricsSystem metricsSystem) {
    statusMessageFactory = new StatusMessageFactory(chainStorageClient);
    this.rpcMethods =
        BeaconChainMethods.createRpcMethods(
            this, chainStorageClient, metricsSystem, statusMessageFactory);
  }

  @Override
  public void onConnect(@NotNull final Peer peer) {
    Eth2Peer eth2Peer = new Eth2Peer(peer, rpcMethods, statusMessageFactory);
    final boolean wasAdded = connectedPeerMap.putIfAbsent(peer.getId(), eth2Peer) == null;
    if (!wasAdded) {
      LOG.warn("Duplicate peer connection detected. Ignoring peer.");
      return;
    }

    if (peer.connectionInitiatedLocally()) {
      eth2Peer.sendStatus();
    }
  }

  @Override
  public void onDisconnect(@NotNull final Peer peer) {
    connectedPeerMap.compute(
        peer.getId(),
        (id, existingPeer) -> {
          if (peer.idMatches(existingPeer)) {
            return null;
          }
          return existingPeer;
        });
  }

  public RpcMethods getRpcMethods() {
    return rpcMethods;
  }

  /**
   * Look up peer by id, returning peer result regardless of validation status of the peer.
   *
   * @param nodeId The nodeId of the peer to lookup
   * @return the peer corresponding to this node id.
   */
  @Override
  public Eth2Peer getConnectedPeer(NodeId nodeId) {
    return connectedPeerMap.get(nodeId);
  }

  public Optional<Eth2Peer> getPeer(NodeId peerId) {
    return Optional.ofNullable(connectedPeerMap.get(peerId)).filter(this::peerIsReady);
  }

  public Stream<Eth2Peer> streamPeers() {
    return connectedPeerMap.values().stream().filter(this::peerIsReady);
  }

  private boolean peerIsReady(Eth2Peer peer) {
    return peer.hasStatus();
  }
}
