package tech.pegasys.artemis.networking.p2p.network;

import tech.pegasys.artemis.networking.p2p.rpc.RpcMethod;

public interface P2PNetworkBuilder<TNetwork extends P2PNetwork, TBuilder extends P2PNetworkBuilder<TNetwork, TBuilder>> {

  TBuilder registerRpcMethod(RpcMethod rpcMethod);

  TBuilder registerPeerHandler(PeerHandler peerHandler);

  TNetwork build();

}
