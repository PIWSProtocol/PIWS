/*
 * Copyright 2019 Google Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "server_impl.h"

#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <random>

#include "crypto/paillier.h"
#include "util/status.inc"
#include "crypto/ec_commutative_cipher.h"
#include "absl/memory/memory.h"

using namespace std;

using ::private_join_and_compute::BigNum;
using ::private_join_and_compute::ECCommutativeCipher;
using ::private_join_and_compute::PublicPaillier;

char* strndup_with_new(const char* the_string, size_t max_length) {
  if (the_string == nullptr) return nullptr;

  char* result = new char[max_length + 1];
  result[max_length] = '\0';  // terminate the string because strncpy might not
  return strncpy(result, the_string, max_length);
}

void SplitCSVLineWithDelimiter(char* line, char delimiter,
                               vector<char*>* cols) {
  char* end_of_line = line + strlen(line);
  char* end;
  char* start;

  for (; line < end_of_line; line++) {
    // Skip leading whitespace, unless said whitespace is the delimiter.
    while (isspace(*line) && *line != delimiter) ++line;

    if (*line == '"' && delimiter == ',') {  // Quoted value...
      start = ++line;
      end = start;
      for (; *line; line++) {
        if (*line == '"') {
          line++;
          if (*line != '"')  // [""] is an escaped ["]
            break;           // but just ["] is end of value
        }
        *end++ = *line;
      }
      // All characters after the closing quote and before the comma
      // are ignored.
      line = strchr(line, delimiter);
      if (!line) line = end_of_line;
    } else {
      start = line;
      line = strchr(line, delimiter);
      if (!line) line = end_of_line;
      // Skip all trailing whitespace, unless said whitespace is the delimiter.
      for (end = line; end > start; --end) {
        if (!isspace(end[-1]) || end[-1] == delimiter) break;
      }
    }
    const bool need_another_column =
        (*line == delimiter) && (line == end_of_line - 1);
    *end = '\0';
    cols->push_back(start);
    // If line was something like [paul,] (comma is the last character
    // and is not proceeded by whitespace or quote) then we are about
    // to eliminate the last column (which is empty). This would be
    // incorrect.
    if (need_another_column) cols->push_back(end);

    assert(*line == '\0' || *line == delimiter);
  }
}

void SplitCSVLineWithDelimiterForStrings(const string& line,
                                         char delimiter,
                                         vector<string>* cols) {
  // Unfortunately, the interface requires char* instead of const char*
  // which requires copying the string.
  char* cline = strndup_with_new(line.c_str(), line.size());
  vector<char*> v;
  SplitCSVLineWithDelimiter(cline, delimiter, &v);
  for (char* str : v) {
    cols->push_back(str);
  }
  delete[] cline;
}

vector<string> SplitCsvLine(const string& line) {
  vector<string> cols;
  SplitCSVLineWithDelimiterForStrings(line, ',', &cols);
  return cols;
}

namespace uuid {
  static std::random_device              rd;
  static std::mt19937                    gen(rd());
  static std::uniform_int_distribution<> dis(0, 15);
  static std::uniform_int_distribution<> dis2(8, 11);

  std::string generate_uuid_v4() {
    std::stringstream ss;
    int i;
    ss << std::hex;
    for (i = 0; i < 8; i++) {
        ss << dis(gen);
    }
    // ss << "-";
    for (i = 0; i < 4; i++) {
        ss << dis(gen);
    }
    // ss << "-4";
    for (i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    // ss << "-";
    ss << dis2(gen);
    for (i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    // ss << "-";
    for (i = 0; i < 12; i++) {
        ss << dis(gen);
    };
    return ss.str();
  }
}

namespace private_join_and_compute {

class CException
{
  public:
    std::string msg;
    CException(std::string s) : msg(s) {}
};

StatusOr<PrivateIntersectionSumServerMessage::ServerRoundOne>
PrivateIntersectionSumProtocolServerImpl::EncryptSet() {
  if (ec_cipher_ != nullptr) {
    return InvalidArgumentError("Attempted to call EncryptSet twice.");
  }
  StatusOr<std::unique_ptr<ECCommutativeCipher>> ec_cipher =
      ECCommutativeCipher::CreateWithNewKey(
          NID_X9_62_prime256v1, ECCommutativeCipher::HashType::SHA256);
  if (!ec_cipher.ok()) {
    return ec_cipher.status();
  }
  ec_cipher_ = std::move(ec_cipher.value());

  PrivateIntersectionSumServerMessage::ServerRoundOne result;
  for (const std::string& input : inputs_) {
    EncryptedElement* encrypted =
        result.mutable_encrypted_set()->add_elements();
    StatusOr<std::string> encrypted_element = ec_cipher_->Encrypt(input);
    if (!encrypted_element.ok()) {
      return encrypted_element.status();
    }
    *encrypted->mutable_element() = encrypted_element.value();
  }

  return result;
}

StatusOr<PrivateIntersectionSumServerMessage::ServerRoundTwo>
PrivateIntersectionSumProtocolServerImpl::ComputeIntersection(
    const PrivateIntersectionSumClientMessage::ClientRoundOne& client_message) {
  try{
    if (ec_cipher_ == nullptr) {
      return InvalidArgumentError(
          "Called ComputeIntersection before EncryptSet.");
    }
    PrivateIntersectionSumServerMessage::ServerRoundTwo result;
    // BigNum N = ctx_->CreateBigNum(client_message.public_key());
    // PublicPaillier public_paillier(ctx_, N, 2);

    std::vector<EncryptedElement> server_set, client_set, intersection;

    // First, we re-encrypt the client party's set, so that we can compare with
    // the re-encrypted set received from the client.
    for (const EncryptedElement& element :
        client_message.encrypted_set().elements()) {
      EncryptedElement reencrypted;
      *reencrypted.mutable_associated_data() = element.associated_data();
      StatusOr<std::string> reenc = ec_cipher_->ReEncrypt(element.element());
      if (!reenc.ok()) {
        return reenc.status();
      }
      *reencrypted.mutable_element() = reenc.value();
      client_set.push_back(reencrypted);
    }
    std::vector<std::string> weightfiles;
    std::map<std::string, std::string> element_weight;
    std::stringstream ss;

    ifstream data_file;
    string line;
    data_file.open(private_join_and_compute::server_file_name);
    while (getline(data_file, line)) {
      vector<string> columns = SplitCsvLine(line);
      weightfiles.push_back(columns[1]);
    }

    data_file.close();

    int weightnumber = 0;
    for (const EncryptedElement& element :
        client_message.reencrypted_set().elements()) {
      server_set.push_back(element);
      element_weight[element.element()] = weightfiles[weightnumber];
      weightnumber++;
    }

    // std::set_intersection requires sorted inputs.
    std::sort(client_set.begin(), client_set.end(),
              [](const EncryptedElement& a, const EncryptedElement& b) {
                return a.element() < b.element();
              });
    std::sort(server_set.begin(), server_set.end(),
              [](const EncryptedElement& a, const EncryptedElement& b) {
                return a.element() < b.element();
              });
    std::set_intersection(
        client_set.begin(), client_set.end(), server_set.begin(),
        server_set.end(), std::back_inserter(intersection),
        [](const EncryptedElement& a, const EncryptedElement& b) {
          return a.element() < b.element();
        });

    // From the intersection we compute the sum of the associated values, which is
    // the result we return to the client.
    // StatusOr<BigNum> encrypted_zero =
    //     public_paillier.Encrypt(ctx_->CreateBigNum(0));
    // if (!encrypted_zero.ok()) {
    //   return encrypted_zero.status();
    // }
    // BigNum sum = encrypted_zero.value();
    
    // std::cout<<std::system("ls ./")<<std::endl;

    data_file.open("./config.txt");
    
    std::string configs[17];
    int location = 0;
    while (getline(data_file, line)) {
      configs[location] = line.substr(line.find("=")+1);
      location++;
    }
    data_file.close();

    std::string sealServerIngsPath = configs[11];

    std::string addedvotelist = uuid::generate_uuid_v4();

    std::ofstream outputcsv;
    outputcsv.open(sealServerIngsPath + "native/server-add/input/"+ addedvotelist +".csv",std::ios::out|std::ios::trunc);

    for (const EncryptedElement& element : intersection) {
      outputcsv<<element.associated_data()<<","<<element_weight[element.element()]<<std::endl;
    }
    outputcsv.close();

    system((sealServerIngsPath + "native/server-add/build/bin/serveradd " + addedvotelist + ".csv").c_str());

    *result.mutable_encrypted_sum() = "0";
    result.set_intersection_size(intersection.size());
    return result;
  }
  catch (CException e) {
    std::cout<<"jj-client-server/private-join-and-compute/server_impl.cc"<<std::endl;
    std::cout<<"Exception happened, the detailed information as follows:"<<std::endl;
    std::cout<<e.msg<<std::endl;
    exit(1);
  }
  catch (...) {
    std::cout<<"Exception happened!File:jj-client-server/private-join-and-compute/server_impl.cc!"<<std::endl;
    exit(1);
  }
}

Status PrivateIntersectionSumProtocolServerImpl::Handle(
    const ClientMessage& request,
    MessageSink<ServerMessage>* server_message_sink) {
  if (protocol_finished()) {
    return InvalidArgumentError(
        "PrivateIntersectionSumProtocolServerImpl: Protocol is already "
        "complete.");
  }

  // Check that the message is a PrivateIntersectionSum protocol message.
  if (!request.has_private_intersection_sum_client_message()) {
    return InvalidArgumentError(
        "PrivateIntersectionSumProtocolServerImpl: Received a message for the "
        "wrong protocol type");
  }
  const PrivateIntersectionSumClientMessage& client_message =
      request.private_intersection_sum_client_message();

  ServerMessage server_message;

  if (client_message.has_start_protocol_request()) {
    // Handle a protocol start message.
    auto maybe_server_round_one = EncryptSet();
    if (!maybe_server_round_one.ok()) {
      return maybe_server_round_one.status();
    }
    *(server_message.mutable_private_intersection_sum_server_message()
          ->mutable_server_round_one()) =
        std::move(maybe_server_round_one.value());
  } else if (client_message.has_client_round_one()) {
    // Handle the client round 1 message.
    auto maybe_server_round_two =
        ComputeIntersection(client_message.client_round_one());
    if (!maybe_server_round_two.ok()) {
      return maybe_server_round_two.status();
    }
    *(server_message.mutable_private_intersection_sum_server_message()
          ->mutable_server_round_two()) =
        std::move(maybe_server_round_two.value());
    // Mark the protocol as finished here.
    protocol_finished_ = true;
  } else {
    return InvalidArgumentError(
        "PrivateIntersectionSumProtocolServerImpl: Received a client message "
        "of an unknown type.");
  }

  return server_message_sink->Send(server_message);
}

}  // namespace private_join_and_compute
