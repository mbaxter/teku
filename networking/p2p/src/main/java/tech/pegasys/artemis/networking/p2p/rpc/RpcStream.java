package tech.pegasys.artemis.networking.p2p.rpc;

import org.apache.tuweni.bytes.Bytes;

public interface RpcStream {

  void writeBytes(Bytes bytes) throws StreamClosedException;

  void closeStream() throws StreamClosedException;

  class StreamClosedException extends RuntimeException {

  }
}
