package tech.pegasys.artemis.networking.p2p.libp2p;


import tech.pegasys.artemis.networking.p2p.network.P2PNetworkBuilder;
import tech.pegasys.artemis.networking.p2p.network.PeerHandler;
import tech.pegasys.artemis.networking.p2p.rpc.RpcMethod;

public class LibP2PNetworkBuilder implements
  P2PNetworkBuilder<LibP2PNetwork, LibP2PNetworkBuilder> {

  @Override
  public LibP2PNetworkBuilder registerRpcMethod(final RpcMethod rpcMethod) {
    throw new UnsupportedOperationException();
  }

  @Override
  public LibP2PNetworkBuilder registerPeerHandler(final PeerHandler peerHandler) {
    throw new UnsupportedOperationException();
  }

  @Override
  public LibP2PNetwork build() {
    throw new UnsupportedOperationException();
  }
}
