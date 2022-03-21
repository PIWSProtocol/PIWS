
#ifndef OPEN_SOURCE_MESSAGE_SINK_H_
#define OPEN_SOURCE_MESSAGE_SINK_H_

#include "private_join_and_compute.pb.h"
#include "util/status.inc"
#include "absl/memory/memory.h"

namespace private_join_and_compute {

// An interface for message sinks.
template <typename T>
class MessageSink {
 public:
  virtual ~MessageSink() = default;

  // Subclasses should accept a message and process it appropriately.
  virtual Status Send(const T& message) = 0;

 protected:
  MessageSink() = default;
};

// A dummy message sink, that simply stores the last message received, and
// allows retrieval. Intended for testing.
template <typename T>
class DummyMessageSink : public MessageSink<T> {
 public:
  ~DummyMessageSink() override = default;

  // Simply copies the message.
  Status Send(const T& message) override {
    last_message_ = absl::make_unique<T>(message);
    return OkStatus();
  }

  // Will fail if no message was received.
  const T& last_message() { return *last_message_; }

 private:
  std::unique_ptr<T> last_message_;
};

}  // namespace private_join_and_compute

#endif  // OPEN_SOURCE_MESSAGE_SINK_H_
