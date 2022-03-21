
#include "client_impl.h"

#include <algorithm>
#include <iterator>
#include <ctime>
#include<sys/timeb.h>
#include "absl/memory/memory.h"

namespace private_join_and_compute {

std::time_t start1;
long long systemtime()
{
    timeb t;
    ftime(&t);
    return t.time*1000+t.millitm;
}

PrivateIntersectionSumProtocolClientImpl::
    PrivateIntersectionSumProtocolClientImpl(
        Context* ctx, const std::vector<std::string>& elements,
        const std::vector<std::string>& values, int32_t modulus_size)
    : ctx_(ctx),
      elements_(elements),
      values_(values),

      intersection_sum_(ctx->Zero()),
      ec_cipher_(std::move(
          ECCommutativeCipher::CreateWithNewKey(
              NID_X9_62_prime256v1, ECCommutativeCipher::HashType::SHA256)
              .value())) {}

StatusOr<PrivateIntersectionSumClientMessage::ClientRoundOne>
PrivateIntersectionSumProtocolClientImpl::ReEncryptSet(
    const PrivateIntersectionSumServerMessage::ServerRoundOne& message) {

  PrivateIntersectionSumClientMessage::ClientRoundOne result;
  for (size_t i = 0; i < elements_.size(); i++) {
    EncryptedElement* element = result.mutable_encrypted_set()->add_elements();
    StatusOr<std::string> encrypted = ec_cipher_->Encrypt(elements_[i]);
    if (!encrypted.ok()) {
      return encrypted.status();
    }
    *element->mutable_element() = encrypted.value();

    *element->mutable_associated_data() = values_[i];
  }

  std::vector<EncryptedElement> reencrypted_set;
  for (const EncryptedElement& element : message.encrypted_set().elements()) {
    EncryptedElement reencrypted;
    StatusOr<std::string> reenc = ec_cipher_->ReEncrypt(element.element());
    if (!reenc.ok()) {
      return reenc.status();
    }
    *reencrypted.mutable_element() = reenc.value();
    reencrypted_set.push_back(reencrypted);
  }

  for (const EncryptedElement& element : reencrypted_set) {
    *result.mutable_reencrypted_set()->add_elements() = element;
  }

  return result;
}

StatusOr<std::pair<int64_t, BigNum>>
PrivateIntersectionSumProtocolClientImpl::DecryptSum(
    const PrivateIntersectionSumServerMessage::ServerRoundTwo& server_message) {
  return std::make_pair(server_message.intersection_size(), ctx_->CreateBigNum(0));
}

Status PrivateIntersectionSumProtocolClientImpl::StartProtocol(
    MessageSink<ClientMessage>* client_message_sink) {
  ClientMessage client_message;
  *(client_message.mutable_private_intersection_sum_client_message()
        ->mutable_start_protocol_request()) =
      PrivateIntersectionSumClientMessage::StartProtocolRequest();
  // std::time(&start1);
  std::cout<<"client_message send time:"<<systemtime()<<std::endl;
  return client_message_sink->Send(client_message);
}

Status PrivateIntersectionSumProtocolClientImpl::Handle(
    const ServerMessage& server_message,
    MessageSink<ClientMessage>* client_message_sink) {
  if (protocol_finished()) {
    return InvalidArgumentError(
        "PrivateIntersectionSumProtocolClientImpl: Protocol is already "
        "complete.");
  }

  // Check that the message is a PrivateIntersectionSum protocol message.
  if (!server_message.has_private_intersection_sum_server_message()) {
    return InvalidArgumentError(
        "PrivateIntersectionSumProtocolClientImpl: Received a message for the "
        "wrong protocol type");
  }
  
  if (server_message.private_intersection_sum_server_message()
          .has_server_round_one()) {
    std::cout<<"recieve time:"<<systemtime()<<std::endl;
    // Handle the server round one message.
    ClientMessage client_message;

    auto maybe_client_round_one =
        ReEncryptSet(server_message.private_intersection_sum_server_message()
                         .server_round_one());
    if (!maybe_client_round_one.ok()) {
      return maybe_client_round_one.status();
    }
    *(client_message.mutable_private_intersection_sum_client_message()
          ->mutable_client_round_one()) =
        std::move(maybe_client_round_one.value());
    std::cout<<"send erlun + yici time:"<<systemtime()<<std::endl;
    return client_message_sink->Send(client_message);
  } else if (server_message.private_intersection_sum_server_message()
                 .has_server_round_two()) {
    std::cout<<"recieve time:"<<systemtime()<<std::endl;
    // Handle the server round two message.
    auto maybe_result =
        DecryptSum(server_message.private_intersection_sum_server_message()
                       .server_round_two());
    if (!maybe_result.ok()) {
      return maybe_result.status();
    }
    std::tie(intersection_size_, intersection_sum_) =
        std::move(maybe_result.value());
    // Mark the protocol as finished here.
    protocol_finished_ = true;
    std::cout<<"client end:"<<systemtime()<<std::endl;
    return OkStatus();
  }
  // If none of the previous cases matched, we received the wrong kind of
  // message.
  return InvalidArgumentError(
      "PrivateIntersectionSumProtocolClientImpl: Received a server message "
      "of an unknown type.");
}

Status PrivateIntersectionSumProtocolClientImpl::PrintOutput() {
  if (!protocol_finished()) {
    return InvalidArgumentError(
        "PrivateIntersectionSumProtocolClientImpl: Not ready to print the "
        "output yet.");
  }

  std::cout << "Client: The intersection size is " << intersection_size_
            << " and the intersection-sum is "
            << "0" << std::endl;
  return OkStatus();
}

}  // namespace private_join_and_compute
