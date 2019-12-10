package tech.pegasys.artemis.networking.p2p.rpc;

public interface ResponseListener<O> {
  void onResponse(O response);
}
