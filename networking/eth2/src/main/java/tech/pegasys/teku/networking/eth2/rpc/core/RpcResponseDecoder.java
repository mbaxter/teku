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

package tech.pegasys.teku.networking.eth2.rpc.core;

import static tech.pegasys.teku.infrastructure.unsigned.ByteUtil.toByteExactUnsigned;
import static tech.pegasys.teku.infrastructure.unsigned.ByteUtil.toUnsignedInt;
import static tech.pegasys.teku.networking.eth2.rpc.core.RpcResponseStatus.SUCCESS_RESPONSE_CODE;

import io.netty.buffer.ByteBuf;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import org.apache.tuweni.bytes.Bytes;
import tech.pegasys.teku.networking.eth2.rpc.core.RpcException.PayloadTruncatedException;
import tech.pegasys.teku.networking.eth2.rpc.core.RpcException.UnrecognizedContextBytesException;
import tech.pegasys.teku.networking.eth2.rpc.core.encodings.ByteBufDecoder;
import tech.pegasys.teku.networking.eth2.rpc.core.encodings.RpcByteBufDecoder;
import tech.pegasys.teku.networking.eth2.rpc.core.encodings.RpcEncoding;
import tech.pegasys.teku.spec.datastructures.networking.libp2p.rpc.RpcErrorMessage;
import tech.pegasys.teku.ssz.SszData;
import tech.pegasys.teku.ssz.schema.SszSchema;

/**
 * Responsible for decoding a stream of responses to a single rpc request
 *
 * @param <T>
 */
public class RpcResponseDecoder<T extends SszData> {
  private final RpcEncoding encoding;
  private final Supplier<RpcResponseContextDecoder> contextDecoderSupplier;
  private final ResponseSchemaSupplier<T> responseSchemaSupplier;

  private Optional<Integer> respCodeMaybe = Optional.empty();
  private Optional<RpcByteBufDecoder<Bytes>> contextDecoder = Optional.empty();
  private Optional<Bytes> contextBytes = Optional.empty();
  private Optional<RpcByteBufDecoder<T>> payloadDecoder = Optional.empty();
  private Optional<RpcByteBufDecoder<RpcErrorMessage>> errorDecoder = Optional.empty();

  private RpcResponseDecoder(
      final RpcEncoding encoding,
      final Supplier<RpcResponseContextDecoder> contextDecoderSupplier,
      final ResponseSchemaSupplier<T> responseSchemaSupplier) {
    this.encoding = encoding;
    this.contextDecoderSupplier = contextDecoderSupplier;
    this.responseSchemaSupplier = responseSchemaSupplier;
  }

  public static <T extends SszData> RpcResponseDecoder<T> createContextFreeDecoder(
      final RpcEncoding encoding, final SszSchema<T> schema) {
    return new RpcResponseDecoder<T>(
        encoding, RpcResponseContextDecoder::noop, __ -> Optional.of(schema));
  }

  public static <T extends SszData> RpcResponseDecoder<T> createContextAwareDecoder(
      final RpcEncoding encoding,
      final Supplier<RpcResponseContextDecoder> contextDecoderSupplier,
      final ResponseSchemaSupplier<T> responseSchemaSupplier) {
    return new RpcResponseDecoder<T>(encoding, contextDecoderSupplier, responseSchemaSupplier);
  }

  public List<T> decodeNextResponses(final ByteBuf data) throws RpcException {
    List<T> ret = new ArrayList<>();
    while (true) {
      Optional<T> responseMaybe = decodeNextResponse(data);
      if (responseMaybe.isPresent()) {
        ret.add(responseMaybe.get());
      } else {
        break;
      }
    }

    return ret;
  }

  private Optional<T> decodeNextResponse(final ByteBuf data) throws RpcException {
    if (!data.isReadable()) {
      return Optional.empty();
    }

    if (respCodeMaybe.isEmpty()) {
      respCodeMaybe = Optional.of(toUnsignedInt(data.readByte()));
    }
    int respCode = respCodeMaybe.get();

    if (respCode == SUCCESS_RESPONSE_CODE) {
      // Process context
      if (contextDecoder.isEmpty()) {
        contextDecoder = Optional.of(contextDecoderSupplier.get());
      }
      if (contextBytes.isEmpty()) {
        contextBytes = contextDecoder.get().decodeOneMessage(data);
        if (contextBytes.isEmpty()) {
          // Wait for more context data
          return Optional.empty();
        }
      }

      // Process payload
      if (payloadDecoder.isEmpty()) {
        final SszSchema<T> schema =
            responseSchemaSupplier
                .getSchema(contextBytes.get())
                .orElseThrow(() -> new UnrecognizedContextBytesException(contextBytes.get()));
        payloadDecoder = Optional.of(encoding.createDecoder(schema));
      }
      Optional<T> ret = payloadDecoder.get().decodeOneMessage(data);
      if (ret.isPresent()) {
        respCodeMaybe = Optional.empty();
        contextDecoder = Optional.empty();
        contextBytes = Optional.empty();
        payloadDecoder = Optional.empty();
      }
      return ret;
    } else {
      if (errorDecoder.isEmpty()) {
        errorDecoder = Optional.of(encoding.createDecoder(RpcErrorMessage.SSZ_SCHEMA));
      }
      Optional<RpcException> rpcException =
          errorDecoder
              .get()
              .decodeOneMessage(data)
              .map(errorMessage -> new RpcException(toByteExactUnsigned(respCode), errorMessage));
      if (rpcException.isPresent()) {
        respCodeMaybe = Optional.empty();
        errorDecoder = Optional.empty();
        throw rpcException.get();
      } else {
        return Optional.empty();
      }
    }
  }

  public void close() {
    payloadDecoder.ifPresent(ByteBufDecoder::close);
    contextDecoder.ifPresent(ByteBufDecoder::close);
    errorDecoder.ifPresent(ByteBufDecoder::close);
  }

  public void complete() throws RpcException {
    final List<RpcException> exceptions = new ArrayList<>();
    completeDecoder(payloadDecoder).ifPresent(exceptions::add);
    payloadDecoder = Optional.empty();
    completeDecoder(contextDecoder).ifPresent(exceptions::add);
    contextDecoder = Optional.empty();
    completeDecoder(errorDecoder).ifPresent(exceptions::add);
    errorDecoder = Optional.empty();

    if (exceptions.size() > 0) {
      throw exceptions.get(0);
    }
    if (respCodeMaybe.isPresent()) {
      throw new PayloadTruncatedException();
    }
  }

  private <T> Optional<RpcException> completeDecoder(Optional<RpcByteBufDecoder<T>> decoder) {
    try {
      if (decoder.isPresent()) {
        decoder.get().complete();
      }
    } catch (RpcException e) {
      return Optional.of(e);
    }
    return Optional.empty();
  }

  @FunctionalInterface
  public interface ResponseSchemaSupplier<T extends SszData> {
    Optional<SszSchema<T>> getSchema(final Bytes contextBytes);
  }
}
