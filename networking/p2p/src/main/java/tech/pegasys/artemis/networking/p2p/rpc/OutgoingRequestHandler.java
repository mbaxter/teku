package tech.pegasys.artemis.networking.p2p.rpc;


import org.apache.tuweni.bytes.Bytes;

public interface OutgoingRequestHandler {

  void initiateRequest(Bytes initialPayload, ResponseHandler handler);
}
