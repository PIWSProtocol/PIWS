
#ifndef OPEN_SOURCE_PROTOCOL_SERVER_H_
#define OPEN_SOURCE_PROTOCOL_SERVER_H_

#include "message_sink.h"
#include "private_join_and_compute.pb.h"
#include "util/status.inc"

namespace private_join_and_compute {

// Abstract class representing a server for a cryptographic protocol.
//
// In all subclasses, the server should expect the first protocol message to be
// sent by the client. (If the protocol requires the server to send the first
// meaningful message, the first client message can be a dummy.)
class ProtocolServer {
 public:
  virtual ~ProtocolServer() = default;

  // All subclasses should check that the client_message is the right type, and,
  // if so, execute the next round of the server, which may involve sending one
  // or more messages to the server message sink.
  virtual Status Handle(const ClientMessage& client_message,
                        MessageSink<ServerMessage>* server_message_sink) = 0;

  // All subclasses should return true if the protocol is complete, and false
  // otherwise.
  virtual bool protocol_finished() = 0;

 protected:
  ProtocolServer() = default;
};

}  // namespace private_join_and_compute

#endif  // OPEN_SOURCE_PROTOCOL_SERVER_H_
