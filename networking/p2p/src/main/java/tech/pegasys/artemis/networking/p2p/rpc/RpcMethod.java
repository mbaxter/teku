package tech.pegasys.artemis.networking.p2p.rpc;

public interface  RpcMethod {

  String getId();

  IncomingRequestHandler createIncomingRequestHandler();

  OutgoingRequestHandler createOutgoingRequestHandler();

}
