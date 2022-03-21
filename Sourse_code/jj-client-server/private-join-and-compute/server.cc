
#include <iostream>
#include <memory>
#include <string>
#include <thread>  // NOLINT

#include "gflags/gflags.h"

#include "include/grpc/grpc_security_constants.h"
#include "include/grpcpp/grpcpp.h"
#include "include/grpcpp/security/server_credentials.h"
#include "include/grpcpp/server_builder.h"
#include "include/grpcpp/server_context.h"
#include "include/grpcpp/support/status.h"
#include "data_util.h"
#include <fstream>
#include "server_impl.h"
#include "private_join_and_compute.grpc.pb.h"
#include "private_join_and_compute_rpc_impl.h"
#include "protocol_server.h"
#include "absl/memory/memory.h"
#include <sstream>

DEFINE_string(port, "0.0.0.0:10501", "Port on which to listen");
DEFINE_string(server_data_file, "",
              "The file from which to read the server database.");

std::string private_join_and_compute::server_file_name;

using namespace std;
using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

static std::string get_file_contents(const char *fpath)
{
  std::ifstream finstream(fpath);
  std::string contents;
  contents.assign((std::istreambuf_iterator<char>(finstream)),
                       std::istreambuf_iterator<char>());
  finstream.close();
  return contents;
}

int RunServer() {
  std::cout << "Server: loading data... " << std::endl;
  auto maybe_server_identifiers =
      ::private_join_and_compute::ReadServerDatasetFromFile(FLAGS_server_data_file);
  private_join_and_compute::server_file_name = FLAGS_server_data_file;
  if (!maybe_server_identifiers.ok()) {
    std::cerr << "RunServer: failed " << maybe_server_identifiers.status()
              << std::endl;
    return 1;
  }

  ::private_join_and_compute::Context context;
  std::unique_ptr<::private_join_and_compute::ProtocolServer> server =
      absl::make_unique<::private_join_and_compute::PrivateIntersectionSumProtocolServerImpl>(
          &context, std::move(maybe_server_identifiers.value()));
  ::private_join_and_compute::PrivateJoinAndComputeRpcImpl service(std::move(server));

  ::grpc::ServerBuilder builder;
  // Consider grpc::SslServerCredentials if not running locally.

  std::ifstream data_file;
  
  data_file.open("./config.txt");

  std::string configs[17];
  std::string line;
  int location = 0;
  while (getline(data_file, line)) {
    configs[location] = line.substr(line.find("=")+1);
    location++;
  }
  data_file.close();

  std::string priAndjoinServerIngsPath = configs[12];

  string clientcert_path_string = priAndjoinServerIngsPath + "private-join-and-compute/key/client_self_signed_crt.pem";
  string servercert_path_string = priAndjoinServerIngsPath + "private-join-and-compute/key/server_self_signed_crt.pem";
  string serverkey_path_string = priAndjoinServerIngsPath + "private-join-and-compute/key/server_privatekey.pem";

  char clientcert_path[120],servercert_path[120],serverkey_path[120];

  strcpy(clientcert_path,clientcert_path_string.c_str());
  strcpy(servercert_path,servercert_path_string.c_str());
  strcpy(serverkey_path,serverkey_path_string.c_str());

  auto clientcert = get_file_contents(clientcert_path); // for verifying clients
  auto servercert = get_file_contents(servercert_path);
  auto serverkey  = get_file_contents(serverkey_path);

  grpc::SslServerCredentialsOptions::PemKeyCertPair pkcp = {
    serverkey.c_str(), servercert.c_str()
  };

  grpc::SslServerCredentialsOptions ssl_opts(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
  ssl_opts.pem_root_certs = clientcert;
  ssl_opts.pem_key_cert_pairs.push_back(pkcp);

  std::shared_ptr<grpc::ServerCredentials> creds;
  creds = grpc::SslServerCredentials(ssl_opts);

  builder.AddListeningPort(FLAGS_port,creds);

  // builder.AddListeningPort(FLAGS_port,
  //                          ::grpc::InsecureServerCredentials());
  builder.RegisterService(&service);
  std::unique_ptr<::grpc::Server> grpc_server(builder.BuildAndStart());

  // Run the server on a background thread.
  std::thread grpc_server_thread(
      [](::grpc::Server* grpc_server_ptr) {
        std::cout << "Server: listening on " << FLAGS_port << std::endl;
        grpc_server_ptr->Wait();
      },
      grpc_server.get());

  while (!service.protocol_finished()) {
    // Wait for the server to be done, and then shut the server down.
  }

  // Shut down server.
  grpc_server->Shutdown();
  grpc_server_thread.join();
  // std::cout << "Server completed protocol and shut down." << std::endl;

  return 0;
}

int main(int argc, char** argv) {
  google::InitGoogleLogging(argv[0]);
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  return RunServer();
}
