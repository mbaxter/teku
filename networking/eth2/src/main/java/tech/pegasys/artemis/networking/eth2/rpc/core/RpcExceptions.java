package tech.pegasys.artemis.networking.eth2.rpc.core;

import tech.pegasys.artemis.networking.p2p.rpc.RpcException;

public class RpcExceptions {
  private static final byte INVALID_REQUEST_CODE = 1;
  private static final byte SERVER_ERROR_CODE = 2;

  public static final RpcException CHUNK_TOO_LONG_ERROR =
    new RpcException(INVALID_REQUEST_CODE, "Chunk exceeds maximum allowed length");
  public static final RpcException INVALID_STEP =
    new RpcException(INVALID_REQUEST_CODE, "Step must be greater than zero");
  public static final RpcException INCORRECT_LENGTH_ERROR =
    new RpcException(
      INVALID_REQUEST_CODE, "Specified message length did not match actual length");
  public static final RpcException MALFORMED_MESSAGE_LENGTH_ERROR =
    new RpcException(INVALID_REQUEST_CODE, "Message length was invalid");
  public static final RpcException MALFORMED_REQUEST_ERROR =
    new RpcException(INVALID_REQUEST_CODE, "Request was malformed");
  public static final RpcException SERVER_ERROR =
    new RpcException(SERVER_ERROR_CODE, "Unexpected error");
}
