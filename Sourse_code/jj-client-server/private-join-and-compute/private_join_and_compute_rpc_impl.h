
#ifndef OPEN_SOURCE_PRIVATE_JOIN_AND_COMPUTE_RPC_IMPL_H_
#define OPEN_SOURCE_PRIVATE_JOIN_AND_COMPUTE_RPC_IMPL_H_

#include "glog/logging.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/server_context.h"
#include "include/grpcpp/support/status.h"
#include "private_join_and_compute.grpc.pb.h"
#include "private_join_and_compute.pb.h"
#include "protocol_server.h"

namespace private_join_and_compute {

// Implements the PrivateJoin and Compute RPC-handling Server.
class PrivateJoinAndComputeRpcImpl : public PrivateJoinAndComputeRpc::Service {
 public:
  // Takes as a parameter an implementation of the server actually implementing
  // the steps of the protocol.
  //
  // Important note: This class will internally create a server message sink
  // that accepts a SINGLE message in response to a Handle request, and fails
  // with INVALID_ARGUMENT if more than one message is supplied. All supplied
  // protocol_server_impls' Handle methods should therefore Send at most one
  // message to the server_message_sink.
  explicit PrivateJoinAndComputeRpcImpl(
      std::unique_ptr<ProtocolServer> protocol_server_impl)
      : protocol_server_impl_(std::move(protocol_server_impl)) {}

  // Executes a round of the protocol.
  ::grpc::Status Handle(::grpc::ServerContext* context,
                        const ClientMessage* request,
                        ServerMessage* response) override;

  bool protocol_finished() {
    return protocol_server_impl_->protocol_finished();
  }

 private:
  std::unique_ptr<ProtocolServer> protocol_server_impl_;
};

}  // namespace private_join_and_compute

#endif  // OPEN_SOURCE_PRIVATE_JOIN_AND_COMPUTE_RPC_IMPL_H_
