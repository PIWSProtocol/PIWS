// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include <assert.h>
#include "sm3.h"
#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <ctime>
#include <algorithm>
#include "com_weblinkon_jni_Homomorphism.h"

using namespace std;
using namespace seal;

namespace uuid {
  static std::random_device              rd;
  static std::mt19937                    gen(rd());
  static std::uniform_int_distribution<> dis(0, 15);
  static std::uniform_int_distribution<> dis2(8, 11);

  std::string generate_uuid_v4() {
    std::stringstream ss;
    int i;
    ss << std::hex;
    for (i = 0; i < 15; i++) {
        ss << dis(gen);
    }
    ss << dis2(gen);
    for (i = 0; i < 15; i++) {
        ss << dis(gen);
    }
    return ss.str();
  }
}

void save_Ciphertext_into_file(string filename, Ciphertext const& ciphertext){
  ofstream ct;
  ct.open(filename, ios::binary);
  ciphertext.save(ct);
  ct.close();
}

void save_PublicKey_into_file(string filename, PublicKey const& publicKey){
  ofstream ct;
  ct.open(filename, ios::binary);
  publicKey.save(ct);
  ct.close();
}

void save_SecretKey_into_file(string filename, SecretKey const& secretKey){
  ofstream ct;
  ct.open(filename, ios::binary);
  secretKey.save(ct);
  ct.close();
}

void save_RelinKeys_into_file(string filename, RelinKeys const& relinKeys){
  ofstream ct;
  ct.open(filename, ios::binary);
  relinKeys.save(ct);
  ct.close();
}

Ciphertext load_Ciphertext_from_file(string filename, SEALContext context){
  ifstream ct;
  ct.open(filename, ios::binary);
  Ciphertext result;
  result.load(context, ct);
  ct.close();
  return result;
}

PublicKey load_PublicKey_from_file(string filename, SEALContext context){
  ifstream ct;
  ct.open(filename, ios::binary);
  PublicKey result;
  result.load(context, ct);
  ct.close();
  return result;
}

SecretKey load_SecretKey_from_file(string filename, SEALContext context){
  ifstream ct;
  ct.open(filename, ios::binary);
  SecretKey result;
  result.load(context, ct);
  ct.close();
  return result;
}

RelinKeys load_RelinKeys_from_file(string filename, SEALContext context){
  ifstream ct;
  ct.open(filename, ios::binary);
  RelinKeys result;
  result.load(context, ct);
  ct.close();
  return result;
}

char* strndup_with_new(const char* the_string, size_t max_length) {
  if (the_string == nullptr) return nullptr;

  char* result = new char[max_length + 1];
  result[max_length] = '\0';  
  return strncpy(result, the_string, max_length);
}

void SplitCSVLineWithDelimiter(char* line, char delimiter,
                               vector<char*>* cols) {
  char* end_of_line = line + strlen(line);
  char* end;
  char* start;

  for (; line < end_of_line; line++) {
    while (isspace(*line) && *line != delimiter) ++line;

    if (*line == '"' && delimiter == ',') { 
      start = ++line;
      end = start;
      for (; *line; line++) {
        if (*line == '"') {
          line++;
          if (*line != '"') 
            break;          
        }
        *end++ = *line;
      }
      line = strchr(line, delimiter);
      if (!line) line = end_of_line;
    } else {
      start = line;
      line = strchr(line, delimiter);
      if (!line) line = end_of_line;
      for (end = line; end > start; --end) {
        if (!isspace(end[-1]) || end[-1] == delimiter) break;
      }
    }
    const bool need_another_column =
        (*line == delimiter) && (line == end_of_line - 1);
    *end = '\0';
    cols->push_back(start);
    if (need_another_column) cols->push_back(end);

    assert(*line == '\0' || *line == delimiter);
  }
}

void SplitCSVLineWithDelimiterForStrings(const string& line,
                                         char delimiter,
                                         vector<string>* cols) {
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

class CException
{
  public:
    string msg;
    CException(string s) : msg(s) {}
};

void genkeytofiles(string secret_key_path, string public_key_path, string relin_key_path)
{
  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
  double scale = pow(2.0, 40);

  SEALContext context(parms);

  KeyGenerator keygen(context);
  auto secret_key = keygen.secret_key();

  PublicKey public_key;
  keygen.create_public_key(public_key);

  RelinKeys relin_keys;
  keygen.create_relin_keys(relin_keys);

  save_SecretKey_into_file(secret_key_path,secret_key);

  save_PublicKey_into_file(public_key_path,public_key);

  save_RelinKeys_into_file(relin_key_path,relin_keys);
}

void genkey(SecretKey *secret_key, PublicKey *public_key, RelinKeys *relin_keys)
{
  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
  double scale = pow(2.0, 40);

  SEALContext context(parms);

  KeyGenerator keygen(context);
  *secret_key = keygen.secret_key();

  keygen.create_public_key(*public_key);
  
  keygen.create_relin_keys(*relin_keys);
}

void encryptweightfiles(string public_key_path, string weightfile_path, string num_candidate, string fileout_path, string fileindexout_path)
{
  string serverfilename = weightfile_path;
  string numlength_str = num_candidate;
  stringstream ss;

  int numlength;

  ss.clear();
  ss << numlength_str;
  ss >> numlength;

  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
  double scale = pow(2.0, 40);

  SEALContext context(parms);

  PublicKey public_key = load_PublicKey_from_file(public_key_path, context);
  Encryptor encryptor(context, public_key);
  CKKSEncoder encoder(context);

  ifstream data_file;
  data_file.open(serverfilename);
  
  ofstream outputcsv;
  outputcsv.open(fileindexout_path,ios::out|ios::trunc);

  string line;
  int ilen;
  string identifier,filename;

  int i;
  while (getline(data_file, line)) {
    vector<string> columns = SplitCsvLine(line);

    unsigned char *input = (unsigned char*)columns[0].c_str();
    ilen = columns[0].size();
    unsigned char output[32];
    
    sm3_context ctx;
    sm3(input, ilen, output);

    identifier = "";
    char st1[3] = {0};

    for (i = 0; i < 32; i++){
      sprintf(st1, "%02x", output[i]);
      string charstr = st1;
      identifier.append(charstr);
    }

    double v_val;
    ss.clear();
    ss << columns[1];
    ss >> v_val;
    vector<double> v(numlength,v_val);

    Plaintext plain_input;
    encoder.encode(v, scale, plain_input);
    Ciphertext input_encrypted;
    encryptor.encrypt(plain_input, input_encrypted);

    string stru0 = uuid::generate_uuid_v4();

    filename = fileout_path + stru0;
    save_Ciphertext_into_file(filename, input_encrypted);       
    outputcsv<<columns[0]<<","<<identifier<<","<<stru0<<endl;
  }
  
  data_file.close();
  outputcsv.close();
}

void encryptweightfile(string public_key_path, string name, string weight, string num_candidate, string fileout_path, string& identifier, string& weightname)
{
  string numlength_str = num_candidate;
  stringstream ss;

  int numlength;

  ss.clear();
  ss << numlength_str;
  ss >> numlength;

  weightname = uuid::generate_uuid_v4();

  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
  double scale = pow(2.0, 40);

  SEALContext context(parms);

  PublicKey public_key = load_PublicKey_from_file(public_key_path, context);
  Encryptor encryptor(context, public_key);
  CKKSEncoder encoder(context);

  int ilen,i;
  string filename;

  unsigned char *input = (unsigned char*)name.c_str();
  ilen = name.size();
  unsigned char output[32];
  
  sm3_context ctx;
  sm3(input, ilen, output);

  identifier = "";
  char st1[3] = {0};

  for (i = 0; i < 32; i++){
    sprintf(st1, "%02x", output[i]);
    string charstr = st1;
    identifier = identifier + charstr;
  }

  double v_val;
  ss.clear();
  ss << weight;
  ss >> v_val;
  vector<double> v(numlength,v_val);
  
  Plaintext plain_input;
  encoder.encode(v, scale, plain_input);
  Ciphertext input_encrypted;
  encryptor.encrypt(plain_input, input_encrypted);

  filename = fileout_path + weightname;
  save_Ciphertext_into_file(filename, input_encrypted);
}

void encryptvotefiles(string public_key_path, string votefile_path, string fileout_path, string fileindexout_path)
{
  string clientfilename = votefile_path;
  stringstream ss;
  
  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
  double scale = pow(2.0, 40);

  SEALContext context(parms);

  PublicKey public_key = load_PublicKey_from_file(public_key_path, context);
  Encryptor encryptor(context, public_key);
  CKKSEncoder encoder(context);

  ifstream data_file;
  data_file.open(clientfilename);

  ofstream outputcsv;
  outputcsv.open(fileindexout_path,ios::out|ios::trunc);

  string line;
  int ilen,i;
  string identifier,filename;

  while (getline(data_file, line)) {
    vector<string> columns = SplitCsvLine(line);

    unsigned char *input = (unsigned char*)columns[0].c_str();
    ilen = columns[0].size();
    unsigned char output[32];
    
    sm3_context ctx;
    sm3(input, ilen, output);

    identifier = "";
    char st1[3] = {0};

    for (i = 0; i < 32; i++){
      sprintf(st1, "%02x", output[i]);
      string charstr = st1;
      identifier.append(charstr);
    }

    vector<double> v;

    for (int kk = 0; kk < columns[1].size(); kk++){
        double dd;
        ss.clear();
        ss << columns[1][kk];
        ss >> dd;
        v.push_back(dd);
    }
    Plaintext plain_input;
    encoder.encode(v, scale, plain_input);
    Ciphertext input_encrypted;
    encryptor.encrypt(plain_input, input_encrypted);

    string stru0 = uuid::generate_uuid_v4();

    filename = fileout_path + stru0;
    save_Ciphertext_into_file(filename, input_encrypted);
    outputcsv<<columns[0]<<","<<identifier<<","<<stru0<<endl;
  }

  data_file.close();
  outputcsv.close();
}

void encryptfiles(string public_key_path, string votefile_path, string fileout_path, string fileindexout_path)
{
  string clientfilename = votefile_path;
  stringstream ss;
  
  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
  double scale = pow(2.0, 40);

  SEALContext context(parms);

  // cout<<"456"<<endl;
  PublicKey public_key = load_PublicKey_from_file(public_key_path, context);
  Encryptor encryptor(context, public_key);
  CKKSEncoder encoder(context);
  // cout<<"123"<<endl;

  ifstream data_file;
  data_file.open(clientfilename);

  ofstream outputcsv;
  outputcsv.open(fileindexout_path,ios::out|ios::trunc);

  string line;
  int ilen,i;
  string identifier,filename;

  while (getline(data_file, line)) {
    vector<string> columns = SplitCsvLine(line);
    cout<<columns[0]<<"--"<<columns[1]<<endl;

    unsigned char *input = (unsigned char*)columns[0].c_str();
    ilen = columns[0].size();
    unsigned char output[32];
    
    sm3_context ctx;
    sm3(input, ilen, output);

    identifier = "";
    char st1[3] = {0};

    for (i = 0; i < 32; i++){
      sprintf(st1, "%02x", output[i]);
      string charstr = st1;
      identifier.append(charstr);
    }

    vector<double> v;

    v.clear();
    size_t lastPos = columns[1].find_first_not_of(' ', 0);
    size_t pos = columns[1].find(' ', lastPos);
    double num;
    while (lastPos != string::npos) {
    	ss.clear();
    	ss << columns[1].substr(lastPos, pos - lastPos);
    	ss >> num;
      v.push_back(num);
      lastPos = columns[1].find_first_not_of(' ', pos);
      pos = columns[1].find(' ', lastPos);
    }

    Plaintext plain_input;
    encoder.encode(v, scale, plain_input);
    Ciphertext input_encrypted;
    encryptor.encrypt(plain_input, input_encrypted);

    string stru0 = uuid::generate_uuid_v4();

    filename = fileout_path + stru0;
    save_Ciphertext_into_file(filename, input_encrypted);
    outputcsv<<columns[0]<<","<<identifier<<","<<stru0<<endl;
  }

  data_file.close();
  outputcsv.close();
}

void encryptvotefile(string public_key_path, string name, string vote, string fileout_path, string& identifier, string& votename)
{
  stringstream ss;

  votename = uuid::generate_uuid_v4();

  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
  double scale = pow(2.0, 40);

  SEALContext context(parms);

  PublicKey public_key = load_PublicKey_from_file(public_key_path, context);
  Encryptor encryptor(context, public_key);
  CKKSEncoder encoder(context);

  int ilen,i;
  string filename;

  unsigned char *input = (unsigned char*)name.c_str();
  ilen = name.size();
  unsigned char output[32];
  
  sm3_context ctx;
  sm3(input, ilen, output);

  identifier = "";
  char st1[3] = {0};

  for (i = 0; i < 32; i++){
    sprintf(st1, "%02x", output[i]);
    string charstr = st1;
    identifier = identifier + charstr;
  }

  vector<double> v;

  for (int kk = 0; kk < vote.size(); kk++){
      double dd;
      ss.clear();
      ss << vote[kk];
      ss >> dd;
      v.push_back(dd);
  }
  Plaintext plain_input;
  encoder.encode(v, scale, plain_input);
  Ciphertext input_encrypted;
  encryptor.encrypt(plain_input, input_encrypted);

  filename = fileout_path + votename;
  save_Ciphertext_into_file(filename, input_encrypted);
}

void encrypttofile(string public_key_path, string name, string value, string fileout_path, string& identifier, string& filename)
{
  stringstream ss;

  filename = uuid::generate_uuid_v4();

  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
  double scale = pow(2.0, 40);

  SEALContext context(parms);

  PublicKey public_key = load_PublicKey_from_file(public_key_path, context);
  Encryptor encryptor(context, public_key);
  CKKSEncoder encoder(context);

  int ilen,i;

  unsigned char *input = (unsigned char*)name.c_str();
  ilen = name.size();
  unsigned char output[32];
  
  sm3_context ctx;
  sm3(input, ilen, output);

  identifier = "";
  char st1[3] = {0};

  for (i = 0; i < 32; i++){
    sprintf(st1, "%02x", output[i]);
    string charstr = st1;
    identifier = identifier + charstr;
  }

  vector<double> v;

  v.clear();
  size_t lastPos = value.find_first_not_of(' ', 0);
  size_t pos = value.find(' ', lastPos);
  double num;
  while (lastPos != string::npos) {
    ss.clear();
    ss << value.substr(lastPos, pos - lastPos);
    ss >> num;
    v.push_back(num);
    lastPos = value.find_first_not_of(' ', pos);
    pos = value.find(' ', lastPos);
  }

  Plaintext plain_input;
  encoder.encode(v, scale, plain_input);
  Ciphertext input_encrypted;
  encryptor.encrypt(plain_input, input_encrypted);

  string savefilename = fileout_path + filename;
  save_Ciphertext_into_file(savefilename, input_encrypted);
}

void decrypt_file(string secret_key_path, string encrypt_file_path, string result_path, string num_candidate)
{
  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
  double scale = pow(2.0, 40);

  SEALContext context(parms);
  SecretKey secret_key = load_SecretKey_from_file(secret_key_path, context);

  CKKSEncoder encoder(context);
  Decryptor decryptor(context, secret_key);
  // cout<< "cipher_str: "<<cipher_str <<endl;
  Ciphertext result_cipher = load_Ciphertext_from_file(encrypt_file_path, context);

  Plaintext plain_result;
  decryptor.decrypt(result_cipher, plain_result);
  vector<double> result;
  encoder.decode(plain_result, result);

  stringstream ss;
  int numlength;
  ss << num_candidate;
  ss >> numlength;

  ofstream outputcsv;
  outputcsv.open(result_path,ios::out|ios::trunc);

  int num_val = 0;
  for(vector<double>::iterator it = result.begin() ;it!=result.end();it++){
    outputcsv<<setiosflags(ios::fixed)<<setprecision(3)<<*it<<endl;
    num_val++;
    if(num_val >= numlength){
      break;
    }
  }
  outputcsv.close();
  // cout<<sealMainInQueryPath +"native/webserver-encrypt/outputresultcsv/"+ cipher_str<<endl;
}

void decrypt_file_JNI(string secret_key_path, string encrypt_file_path, string result_path, int num_candidate)
{
  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
  double scale = pow(2.0, 40);

  SEALContext context(parms);
  SecretKey secret_key = load_SecretKey_from_file(secret_key_path, context);

  CKKSEncoder encoder(context);
  Decryptor decryptor(context, secret_key);
  // cout<< "cipher_str: "<<cipher_str <<endl;
  Ciphertext result_cipher = load_Ciphertext_from_file(encrypt_file_path, context);

  Plaintext plain_result;
  decryptor.decrypt(result_cipher, plain_result);
  vector<double> result;
  encoder.decode(plain_result, result);

  ofstream outputcsv;
  outputcsv.open(result_path,ios::out|ios::trunc);

  int num_val = 0;
  for(vector<double>::iterator it = result.begin() ;it!=result.end();it++){
    outputcsv<<setiosflags(ios::fixed)<<setprecision(3)<<*it<<endl;
    num_val++;
    if(num_val >= num_candidate){
      break;
    }
  }
  outputcsv.close();
  // cout<<sealMainInQueryPath +"native/webserver-encrypt/outputresultcsv/"+ cipher_str<<endl;
}

void insert_to_FHE_operation(string relinkey_path, string insertfile_path, string weight_path, string vote_path, string fileout_path)
{
  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
  double scale = pow(2.0, 40);

  SEALContext context(parms);

  RelinKeys relin_keys = load_RelinKeys_from_file(relinkey_path, context);

  Evaluator evaluator(context);
  
  string addedfilelist_path = insertfile_path;

  ifstream data_file;
  data_file.open(addedfilelist_path);
//   std::cout<<"opensuccess!:"<<addedfilelist_path<<std::endl;
  int line_number = 0;
  // string votefiledir;
  Ciphertext result;
  string line;

  while (getline(data_file, line)) {
    vector<string> columns = SplitCsvLine(line);
    string vote_path_new = vote_path + "/" + columns[0];
    string weight_path_new = weight_path + "/" + columns[1];
  //   std::cout<<"vote weight ok!"<<std::endl;
//std::cout<<"votepath="<<vote_path<<std::endl;
//std::cout<<"weightpath"<<weight_path<<std::endl;
    // cout<<vote_path_new<<endl;
    Ciphertext votecipher = load_Ciphertext_from_file(vote_path_new,context);
    // std::cout<<"vote vote read ok!"<<std::endl;
    // cout<<weight_path_new<<endl;
    Ciphertext weightcipher = load_Ciphertext_from_file(weight_path_new,context);
    //  std::cout<<"vote weight read ok!"<<std::endl;
    Ciphertext temp;
    evaluator.multiply(votecipher,weightcipher,temp);
    evaluator.relinearize_inplace(temp, relin_keys);
    evaluator.rescale_to_next_inplace(temp);
    if(line_number == 0){
      result = temp;
    }
    else{
      Ciphertext result_c;
      evaluator.add(result, temp, result_c);
      result = result_c;
    }
    line_number++;
  }
  // std::cout<<"vote weight ok!"<<std::endl;
  data_file.close();
  save_Ciphertext_into_file(fileout_path,result);
}

// void All_FHE_operation_result(string relinkey_path, string weight_path, string vote_path, string encryptfile1_path, string encryptfile2_path)
void All_FHE_operation_result(string relinkey_path, string weight_path, string vote_path)
{
  //native/webserver-encrypt/inputcipher/serverclient-uuid.csv,密文结果在serverclient-uuid 这个会自动调用descrypt，忽略就好
  string voteServerIp;
  string voteServerUser;
  string voteServerPw;
  string sealMainInVotePath;
  string queryServerIp;
  string queryServerUser;
  string queryServerPw;
  string sealMainInQueryPath;

  string gsIp;
  string gsUser;
  string gsPw;
  string sealServerIngsPath;
  string priAndjoinServerIngsPath;

  string gcIp;
  string gcUser;
  string gcPw;
  string priAndjoinClientIngcPath;

  ifstream configure_file;
  configure_file.open("./config.txt");
  string configs[17];
  string config_line;
  int location = 0;
  while (getline(configure_file, config_line)) {
    configs[location] = config_line.substr(config_line.find("=")+1);
    location++;
  }
  configure_file.close();
  
  voteServerIp = configs[0];
  voteServerUser = configs[1];
  voteServerPw = configs[2];
  sealMainInVotePath = configs[3];

  queryServerIp = configs[4];
  queryServerUser = configs[5];
  queryServerPw = configs[6];
  sealMainInQueryPath = configs[7];

  gsIp = configs[8];
  gsUser = configs[9];
  gsPw = configs[10];
  sealServerIngsPath = configs[11];
  priAndjoinServerIngsPath = configs[12];

  gcIp = configs[13];
  gcUser = configs[14];
  gcPw = configs[15];
  priAndjoinClientIngcPath = configs[16];

  string file1csvname = weight_path.substr(weight_path.find_last_of('-')+1);
  string uuidname = file1csvname.substr(0, file1csvname.find("."));
  string relienkeyname = "relienkey-" + uuidname;

  system(("sshpass -p "+gsPw+" scp "+ relinkey_path + " "+gsUser+"@"+gsIp+":"+sealServerIngsPath+"native/server-add/input/outputserver/"+relienkeyname).c_str());

  system(("sshpass -p "+ gsPw +" scp "+ weight_path +" "+gsUser+"@"+gsIp+":"+sealServerIngsPath+"native/server-add/input/outputserver").c_str());
  system(("sshpass -p "+ voteServerPw +" scp "+ vote_path +" "+ gcUser +"@"+ gcIp +":"+ priAndjoinClientIngcPath +"clientinput").c_str());
  system(("sshpass -p "+ gcPw +" ssh "+ gcUser +"@"+ gcIp +" "+ priAndjoinClientIngcPath +"private-join-and-compute/bazel-bin/client --client_data_file="+ priAndjoinClientIngcPath +"clientinput/"+ vote_path.substr(vote_path.find_last_of('/')+1) +" > log.txt").c_str());
  // cout<<vote_path.substr(vote_path.find_last_of('/')+1)<<endl;
}

void All_FHE_operation(string vote_path)
{
  //native/webserver-encrypt/inputcipher/serverclient-uuid.csv,密文结果在serverclient-uuid 这个会自动调用descrypt，忽略就好
  string voteServerIp;
  string voteServerUser;
  string voteServerPw;
  string sealMainInVotePath;
  string queryServerIp;
  string queryServerUser;
  string queryServerPw;
  string sealMainInQueryPath;

  string gsIp;
  string gsUser;
  string gsPw;
  string sealServerIngsPath;
  string priAndjoinServerIngsPath;

  string gcIp;
  string gcUser;
  string gcPw;
  string priAndjoinClientIngcPath;

  ifstream configure_file;
  configure_file.open("/root/config.txt");
  string configs[17];
  string config_line;
  int location = 0;
  while (getline(configure_file, config_line)) {
    configs[location] = config_line.substr(config_line.find("=")+1);
    location++;
  }
  configure_file.close();
  
  voteServerIp = configs[0];
  voteServerUser = configs[1];
  voteServerPw = configs[2];
  sealMainInVotePath = configs[3];

  queryServerIp = configs[4];
  queryServerUser = configs[5];
  queryServerPw = configs[6];
  sealMainInQueryPath = configs[7];

  gsIp = configs[8];
  gsUser = configs[9];
  gsPw = configs[10];
  sealServerIngsPath = configs[11];
  priAndjoinServerIngsPath = configs[12];

  gcIp = configs[13];
  gcUser = configs[14];
  gcPw = configs[15];
  priAndjoinClientIngcPath = configs[16];

  // string file1csvname = weight_path.substr(weight_path.find_last_of('-')+1);
  // string uuidname = file1csvname.substr(0, file1csvname.find("."));
  // string relienkeyname = "relienkey-" + uuidname;

  // system(("sshpass -p "+gsPw+" scp "+ relinkey_path + " "+gsUser+"@"+gsIp+":"+sealServerIngsPath+"native/server-add/input/outputserver/"+relienkeyname).c_str());

  // system(("sshpass -p "+ gsPw +" scp "+ weight_path +" "+gsUser+"@"+gsIp+":"+sealServerIngsPath+"native/server-add/input/outputserver").c_str());
  // system(("sshpass -p "+ voteServerPw +" scp "+ vote_path +" "+ gcUser +"@"+ gcIp +":"+ priAndjoinClientIngcPath +"clientinput").c_str());
  system(("sshpass -p "+ gcPw +" ssh "+ gcUser +"@"+ gcIp +" "+ priAndjoinClientIngcPath +"private-join-and-compute/bazel-bin/client --client_data_file="+ vote_path).c_str());
  // cout<<vote_path.substr(vote_path.find_last_of('/')+1)<<endl;
  // pull result files from gsserver
  string addedvotelist_csv = "serverclient-" + vote_path.substr(vote_path.find_last_of('-')+1);
  string resultname = addedvotelist_csv.substr(0, addedvotelist_csv.find("."));
  system(("sshpass -p "+ gsPw +" scp "+ gsUser +"@"+ gsIp +":"+ sealServerIngsPath +"native/server-add/input/"+ addedvotelist_csv + " " + sealMainInQueryPath + "native/webserver-encrypt/inputcipher").c_str());
  system(("sshpass -p "+ gsPw +" scp "+ gsUser +"@"+ gsIp +":"+ sealServerIngsPath +"native/server-add/output/"+ resultname + " " + sealMainInQueryPath + "native/webserver-encrypt/inputcipher").c_str());
}

void multiplyoradd(string relinkey_path, string func, string filein_path, string filecipher_path, string fileout_path)
{
  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
  double scale = pow(2.0, 40);

  SEALContext context(parms);

  RelinKeys relin_keys = load_RelinKeys_from_file(relinkey_path, context);

  Evaluator evaluator(context);

  CKKSEncoder encoder(context);

  ifstream data_file;
  data_file.open(filein_path);

  int line_number = 0;
  // string votefiledir;
  Ciphertext result;

  string line, file_path;

  if(func=="add"){
    while (getline(data_file, line)) {
      file_path = filecipher_path + "/" + line;
      Ciphertext cipher = load_Ciphertext_from_file(file_path,context);

      if(line_number == 0){
        result = cipher;
      }
      else{
        Ciphertext result_c;
        evaluator.add(result, cipher, result_c);
        result = result_c;
      }
      line_number++;
    }
  }
  else if(func=="multiply"){
    while (getline(data_file, line)) {
      file_path = filecipher_path + "/" + line;
      // cout<<file_path<<endl;
      Ciphertext cipher = load_Ciphertext_from_file(file_path,context);

      if(line_number == 0){
        result = cipher;
        
      }
      else if(line_number == 2){
        Plaintext wt;
        encoder.encode(1.0, scale, wt);
        evaluator.multiply_plain_inplace(cipher, wt);
        evaluator.rescale_to_next_inplace(cipher);

        
        Ciphertext result_c;
        evaluator.multiply(result,cipher,result_c);
        evaluator.relinearize_inplace(result_c, relin_keys);
        evaluator.rescale_to_next_inplace(result_c);
        result = result_c;
      }
      else if(line_number == 1){
        Ciphertext result_c;
        
        evaluator.multiply(result,cipher,result_c);
        evaluator.relinearize_inplace(result_c, relin_keys);
        evaluator.rescale_to_next_inplace(result_c);
        result = result_c;
      }
      else{
        if(line_number>=3){
          cout<<"Homomorphic multiplication of floating-point numbers only supports three-level operations!"<<endl;
          break;
        }
        Plaintext wt;
        encoder.encode(1.0, scale, wt);
        evaluator.multiply_plain_inplace(cipher, wt);
        evaluator.rescale_to_next_inplace(cipher);

        evaluator.rescale_to_next_inplace(cipher);

        
        Ciphertext result_c;
        evaluator.multiply(result,cipher,result_c);
        evaluator.relinearize_inplace(result_c, relin_keys);
        evaluator.rescale_to_next_inplace(result_c);
        result = result_c;
      }
      line_number++;
    }
  }

//std::cout<<"vote weight ok!"<<std::endl;
  data_file.close();
  save_Ciphertext_into_file(fileout_path,result);
}

void homomorfic_multiply(string relinkey_path, string filein_path, string filecipher_path, string fileout_path)
{
  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
  double scale = pow(2.0, 40);

  SEALContext context(parms);

  RelinKeys relin_keys = load_RelinKeys_from_file(relinkey_path, context);

  Evaluator evaluator(context);

  CKKSEncoder encoder(context);

  ifstream data_file;
  data_file.open(filein_path);

  int line_number = 0;
  // string votefiledir;
  Ciphertext result;

  string line, file_path;

  while (getline(data_file, line)) {
    file_path = filecipher_path + "/" + line;
    // cout<<file_path<<endl;
    Ciphertext cipher = load_Ciphertext_from_file(file_path,context);

    if(line_number == 0){
      result = cipher;
      
    }
    else if(line_number == 2){
      Plaintext wt;
      encoder.encode(1.0, scale, wt);
      evaluator.multiply_plain_inplace(cipher, wt);
      evaluator.rescale_to_next_inplace(cipher);

      
      Ciphertext result_c;
      evaluator.multiply(result,cipher,result_c);
      evaluator.relinearize_inplace(result_c, relin_keys);
      evaluator.rescale_to_next_inplace(result_c);
      result = result_c;
    }
    else if(line_number == 1){
      Ciphertext result_c;
      
      evaluator.multiply(result,cipher,result_c);
      evaluator.relinearize_inplace(result_c, relin_keys);
      evaluator.rescale_to_next_inplace(result_c);
      result = result_c;
    }
    else{
      if(line_number>=3){
        cout<<"Homomorphic multiplication of floating-point numbers only supports three-level operations!"<<endl;
        break;
      }
      Plaintext wt;
      encoder.encode(1.0, scale, wt);
      evaluator.multiply_plain_inplace(cipher, wt);
      evaluator.rescale_to_next_inplace(cipher);

      evaluator.rescale_to_next_inplace(cipher);

      
      Ciphertext result_c;
      evaluator.multiply(result,cipher,result_c);
      evaluator.relinearize_inplace(result_c, relin_keys);
      evaluator.rescale_to_next_inplace(result_c);
      result = result_c;
    }
    line_number++;
  }

//std::cout<<"vote weight ok!"<<std::endl;
  data_file.close();
  save_Ciphertext_into_file(fileout_path,result);
}

void homomorfic_add(string relinkey_path, string filein_path, string filecipher_path, string fileout_path)
{
  EncryptionParameters parms(scheme_type::ckks);
  size_t poly_modulus_degree = 8192;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
  double scale = pow(2.0, 40);

  SEALContext context(parms);

  RelinKeys relin_keys = load_RelinKeys_from_file(relinkey_path, context);

  Evaluator evaluator(context);

  CKKSEncoder encoder(context);

  ifstream data_file;
  data_file.open(filein_path);

  int line_number = 0;
  // string votefiledir;
  Ciphertext result;

  string line, file_path;

  while (getline(data_file, line)) {
    file_path = filecipher_path + "/" + line;
    Ciphertext cipher = load_Ciphertext_from_file(file_path,context);

    if(line_number == 0){
      result = cipher;
    }
    else{
      Ciphertext result_c;
      evaluator.add(result, cipher, result_c);
      result = result_c;
    }
    line_number++;
  }

//std::cout<<"vote weight ok!"<<std::endl;
  data_file.close();
  save_Ciphertext_into_file(fileout_path,result);
}

JNIEXPORT void JNICALL Java_com_weblinkon_jni_Homomorphism_genkey
  (JNIEnv *env, jobject obejct, jstring secretkeypath_jstring, jstring publickeypath_jstring, jstring relinkeypath_jstring)
{
  string secretkeypath = env->GetStringUTFChars(secretkeypath_jstring, 0);
  string publickeypath = env->GetStringUTFChars(publickeypath_jstring, 0);
  string relinkeypath = env->GetStringUTFChars(relinkeypath_jstring, 0);

  // config file read start
  string config_file_path = "/root/config.txt";

  string voteServerIp;
  string voteServerUser;
  string voteServerPw;
  string sealMainInVotePath;

  string queryServerIp;
  string queryServerUser;
  string queryServerPw;
  string sealMainInQueryPath;

  //Private join configuration
  string gsIp;
  string gsUser;
  string gsPw;
  string sealServerIngsPath;
  string priAndjoinServerIngsPath;

  string gcIp;
  string gcUser;
  string gcPw;
  string priAndjoinClientIngcPath;
  ifstream configure_file;
  configure_file.open(config_file_path);
  string configs[17];
  string config_line;
  int location = 0;
  while (getline(configure_file, config_line)) {
    configs[location] = config_line.substr(config_line.find("=")+1);
    location++;
  }
  configure_file.close();
  
  voteServerIp = configs[0];
  voteServerUser = configs[1];
  voteServerPw = configs[2];
  sealMainInVotePath = configs[3];

  queryServerIp = configs[4];
  queryServerUser = configs[5];
  queryServerPw = configs[6];
  sealMainInQueryPath = configs[7];

  //Private join configuration
  gsIp = configs[8];
  gsUser = configs[9];
  gsPw = configs[10];
  sealServerIngsPath = configs[11];
  priAndjoinServerIngsPath = configs[12];

  gcIp = configs[13];
  gcUser = configs[14];
  gcPw = configs[15];
  priAndjoinClientIngcPath = configs[16];
  // config file read end

  SecretKey secret_key;
  PublicKey public_key;
  RelinKeys relin_keys;

  genkey(&secret_key, &public_key, &relin_keys);
  save_SecretKey_into_file(secretkeypath,secret_key);

  save_PublicKey_into_file(publickeypath,public_key);

  save_RelinKeys_into_file(relinkeypath,relin_keys);
}

// void weblink_genkey(string secretkeypath, string publickeypath, string relinkeypath)
// {
  
// }

JNIEXPORT void JNICALL Java_com_weblinkon_jni_Homomorphism_encryptCSV
  (JNIEnv *env, jobject obejct, jstring pubkeypath_jstring, jstring serverfilename_jstring, jstring fileout_jstring, jstring pathout_jstring)
{
  string pubkeypath = env->GetStringUTFChars(pubkeypath_jstring, 0);
  string serverfilename = env->GetStringUTFChars(serverfilename_jstring, 0);
  string fileout = env->GetStringUTFChars(fileout_jstring, 0);
  string pathout = env->GetStringUTFChars(pathout_jstring, 0);

  // config file read start
  string config_file_path = "/root/config.txt";

  string voteServerIp;
  string voteServerUser;
  string voteServerPw;
  string sealMainInVotePath;

  string queryServerIp;
  string queryServerUser;
  string queryServerPw;
  string sealMainInQueryPath;

  //Private join configuration
  string gsIp;
  string gsUser;
  string gsPw;
  string sealServerIngsPath;
  string priAndjoinServerIngsPath;

  string gcIp;
  string gcUser;
  string gcPw;
  string priAndjoinClientIngcPath;
  ifstream configure_file;
  configure_file.open(config_file_path);
  string configs[17];
  string config_line;
  int location = 0;
  while (getline(configure_file, config_line)) {
    configs[location] = config_line.substr(config_line.find("=")+1);
    location++;
  }
  configure_file.close();
  
  voteServerIp = configs[0];
  voteServerUser = configs[1];
  voteServerPw = configs[2];
  sealMainInVotePath = configs[3];

  queryServerIp = configs[4];
  queryServerUser = configs[5];
  queryServerPw = configs[6];
  sealMainInQueryPath = configs[7];

  //Private join configuration
  gsIp = configs[8];
  gsUser = configs[9];
  gsPw = configs[10];
  sealServerIngsPath = configs[11];
  priAndjoinServerIngsPath = configs[12];

  gcIp = configs[13];
  gcUser = configs[14];
  gcPw = configs[15];
  priAndjoinClientIngcPath = configs[16];
  // config file read end

  system(("rm -rf "+ pathout + "/*").c_str());

  encryptfiles(pubkeypath, serverfilename, fileout + "/", pathout);
}

// void weblink_encrypt(string pubkeypath, string serverfilename, string fileout, string pathout)
// {
  
// }

void weblink_encryptweightcsv(string pubkeypath, string serverfilename, string numlength_str, string fileout, string pathout)
{
  // config file read start
  string config_file_path = "/root/config.txt";

  string voteServerIp;
  string voteServerUser;
  string voteServerPw;
  string sealMainInVotePath;

  string queryServerIp;
  string queryServerUser;
  string queryServerPw;
  string sealMainInQueryPath;

  //Private join configuration
  string gsIp;
  string gsUser;
  string gsPw;
  string sealServerIngsPath;
  string priAndjoinServerIngsPath;

  string gcIp;
  string gcUser;
  string gcPw;
  string priAndjoinClientIngcPath;
  ifstream configure_file;
  configure_file.open(config_file_path);
  string configs[17];
  string config_line;
  int location = 0;
  while (getline(configure_file, config_line)) {
    configs[location] = config_line.substr(config_line.find("=")+1);
    location++;
  }
  configure_file.close();
  
  voteServerIp = configs[0];
  voteServerUser = configs[1];
  voteServerPw = configs[2];
  sealMainInVotePath = configs[3];

  queryServerIp = configs[4];
  queryServerUser = configs[5];
  queryServerPw = configs[6];
  sealMainInQueryPath = configs[7];

  //Private join configuration
  gsIp = configs[8];
  gsUser = configs[9];
  gsPw = configs[10];
  sealServerIngsPath = configs[11];
  priAndjoinServerIngsPath = configs[12];

  gcIp = configs[13];
  gcUser = configs[14];
  gcPw = configs[15];
  priAndjoinClientIngcPath = configs[16];
  // config file read end

  system(("rm -rf "+ pathout + "/*").c_str());

  encryptweightfiles(pubkeypath, serverfilename, numlength_str, fileout + "/", pathout);
}

void weblink_encryptvotecsv(string pubkeypath, string clientfilename, string fileout, string pathout)
{
  // config file read start
  string config_file_path = "/root/config.txt";

  string voteServerIp;
  string voteServerUser;
  string voteServerPw;
  string sealMainInVotePath;

  string queryServerIp;
  string queryServerUser;
  string queryServerPw;
  string sealMainInQueryPath;

  //Private join configuration
  string gsIp;
  string gsUser;
  string gsPw;
  string sealServerIngsPath;
  string priAndjoinServerIngsPath;

  string gcIp;
  string gcUser;
  string gcPw;
  string priAndjoinClientIngcPath;
  ifstream configure_file;
  configure_file.open(config_file_path);
  string configs[17];
  string config_line;
  int location = 0;
  while (getline(configure_file, config_line)) {
    configs[location] = config_line.substr(config_line.find("=")+1);
    location++;
  }
  configure_file.close();
  
  voteServerIp = configs[0];
  voteServerUser = configs[1];
  voteServerPw = configs[2];
  sealMainInVotePath = configs[3];

  queryServerIp = configs[4];
  queryServerUser = configs[5];
  queryServerPw = configs[6];
  sealMainInQueryPath = configs[7];

  //Private join configuration
  gsIp = configs[8];
  gsUser = configs[9];
  gsPw = configs[10];
  sealServerIngsPath = configs[11];
  priAndjoinServerIngsPath = configs[12];

  gcIp = configs[13];
  gcUser = configs[14];
  gcPw = configs[15];
  priAndjoinClientIngcPath = configs[16];
  // config file read end

  system(("rm -rf "+ fileout + "/*").c_str());

  encryptvotefiles(pubkeypath, clientfilename, fileout + "/", pathout);
}

JNIEXPORT jstring JNICALL Java_com_weblinkon_jni_Homomorphism_encrypt
  (JNIEnv *env, jobject obejct, jstring pubkeypath_jstring, jstring name_jstring, jstring value_jstring, jstring fileout_string)
{
  string pubkeypath = env->GetStringUTFChars(pubkeypath_jstring, 0);
  string name = env->GetStringUTFChars(name_jstring, 0);
  string value = env->GetStringUTFChars(value_jstring, 0);
  string fileout = env->GetStringUTFChars(fileout_string, 0);

  // config file read start
  string config_file_path = "/root/config.txt";

  string voteServerIp;
  string voteServerUser;
  string voteServerPw;
  string sealMainInVotePath;

  string queryServerIp;
  string queryServerUser;
  string queryServerPw;
  string sealMainInQueryPath;

  //Private join configuration
  string gsIp;
  string gsUser;
  string gsPw;
  string sealServerIngsPath;
  string priAndjoinServerIngsPath;

  string gcIp;
  string gcUser;
  string gcPw;
  string priAndjoinClientIngcPath;
  ifstream configure_file;
  configure_file.open(config_file_path);
  string configs[17];
  string config_line;
  int location = 0;
  while (getline(configure_file, config_line)) {
    configs[location] = config_line.substr(config_line.find("=")+1);
    location++;
  }
  configure_file.close();
  
  voteServerIp = configs[0];
  voteServerUser = configs[1];
  voteServerPw = configs[2];
  sealMainInVotePath = configs[3];

  queryServerIp = configs[4];
  queryServerUser = configs[5];
  queryServerPw = configs[6];
  sealMainInQueryPath = configs[7];

  //Private join configuration
  gsIp = configs[8];
  gsUser = configs[9];
  gsPw = configs[10];
  sealServerIngsPath = configs[11];
  priAndjoinServerIngsPath = configs[12];

  gcIp = configs[13];
  gcUser = configs[14];
  gcPw = configs[15];
  priAndjoinClientIngcPath = configs[16];
  // config file read end

  string fileout_path = fileout + "/";
  string identifier,filename;
  encrypttofile(pubkeypath, name, value, fileout_path, identifier, filename);

  string returnvalue = name+","+identifier+","+filename;

  char* c = nullptr;
  const char* constc = nullptr;
  constc = returnvalue.c_str();
  c = const_cast<char*>(constc);

  jstring out= env->NewStringUTF(c);

  return out;
}

// string weblink_encryptvote(string pubkeypath, string name, string vote, string fileout)
// {
  
// }

string weblink_encryptweight(string pubkeypath, string numlength_str, string name, string weight, string fileout)
{
  // config file read start
  string config_file_path = "/root/config.txt";

  string voteServerIp;
  string voteServerUser;
  string voteServerPw;
  string sealMainInVotePath;

  string queryServerIp;
  string queryServerUser;
  string queryServerPw;
  string sealMainInQueryPath;

  //Private join configuration
  string gsIp;
  string gsUser;
  string gsPw;
  string sealServerIngsPath;
  string priAndjoinServerIngsPath;

  string gcIp;
  string gcUser;
  string gcPw;
  string priAndjoinClientIngcPath;
  ifstream configure_file;
  configure_file.open(config_file_path);
  string configs[17];
  string config_line;
  int location = 0;
  while (getline(configure_file, config_line)) {
    configs[location] = config_line.substr(config_line.find("=")+1);
    location++;
  }
  configure_file.close();
  
  voteServerIp = configs[0];
  voteServerUser = configs[1];
  voteServerPw = configs[2];
  sealMainInVotePath = configs[3];

  queryServerIp = configs[4];
  queryServerUser = configs[5];
  queryServerPw = configs[6];
  sealMainInQueryPath = configs[7];

  //Private join configuration
  gsIp = configs[8];
  gsUser = configs[9];
  gsPw = configs[10];
  sealServerIngsPath = configs[11];
  priAndjoinServerIngsPath = configs[12];

  gcIp = configs[13];
  gcUser = configs[14];
  gcPw = configs[15];
  priAndjoinClientIngcPath = configs[16];
  // config file read end

  string identifier, weightname;
  string fileout_path = fileout + "/";
  encryptweightfile(pubkeypath, name, weight, numlength_str, fileout_path, identifier, weightname);
  
  return name+","+identifier+","+weightname;
}

void weblink_FHE_operation_result(string relinkey_path, string server_str, string client_str, string numlength_str)
{
  // config file read start
  string config_file_path = "/root/config.txt";

  string voteServerIp;
  string voteServerUser;
  string voteServerPw;
  string sealMainInVotePath;

  string queryServerIp;
  string queryServerUser;
  string queryServerPw;
  string sealMainInQueryPath;

  //Private join configuration
  string gsIp;
  string gsUser;
  string gsPw;
  string sealServerIngsPath;
  string priAndjoinServerIngsPath;

  string gcIp;
  string gcUser;
  string gcPw;
  string priAndjoinClientIngcPath;
  ifstream configure_file;
  configure_file.open(config_file_path);
  string configs[17];
  string config_line;
  int location = 0;
  while (getline(configure_file, config_line)) {
    configs[location] = config_line.substr(config_line.find("=")+1);
    location++;
  }
  configure_file.close();
  
  voteServerIp = configs[0];
  voteServerUser = configs[1];
  voteServerPw = configs[2];
  sealMainInVotePath = configs[3];

  queryServerIp = configs[4];
  queryServerUser = configs[5];
  queryServerPw = configs[6];
  sealMainInQueryPath = configs[7];

  //Private join configuration
  gsIp = configs[8];
  gsUser = configs[9];
  gsPw = configs[10];
  sealServerIngsPath = configs[11];
  priAndjoinServerIngsPath = configs[12];

  gcIp = configs[13];
  gcUser = configs[14];
  gcPw = configs[15];
  priAndjoinClientIngcPath = configs[16];
  // config file read end

  All_FHE_operation_result(relinkey_path, server_str, client_str);
  ofstream writetxt;
  writetxt.open(sealMainInQueryPath + "native/webserver-encrypt/keys/numlength.txt",ios::out|ios::trunc);
  writetxt << numlength_str;
  writetxt.close();
}

JNIEXPORT void JNICALL Java_com_weblinkon_jni_Homomorphism_FHEOperationResult
  (JNIEnv *env, jobject obejct, jstring relinkey_path_jstring, jstring server_str_jstring, jstring client_str_jstring)
{
  // string relinkey_path = env->GetStringUTFChars(relinkey_path_jstring, 0);
  // string server_str = env->GetStringUTFChars(server_str_jstring, 0);
  string client_str = env->GetStringUTFChars(client_str_jstring, 0);

  All_FHE_operation(client_str);
}

void weblink_insert_to_FHE_operation(string relinkey_path, string insertfile_path, string weight_path, string vote_path, string result_path)
{
  // config file read start
  string config_file_path = "/root/config.txt";

  string voteServerIp;
  string voteServerUser;
  string voteServerPw;
  string sealMainInVotePath;

  string queryServerIp;
  string queryServerUser;
  string queryServerPw;
  string sealMainInQueryPath;

  //Private join configuration
  string gsIp;
  string gsUser;
  string gsPw;
  string sealServerIngsPath;
  string priAndjoinServerIngsPath;

  string gcIp;
  string gcUser;
  string gcPw;
  string priAndjoinClientIngcPath;
  ifstream configure_file;
  configure_file.open(config_file_path);
  string configs[17];
  string config_line;
  int location = 0;
  while (getline(configure_file, config_line)) {
    configs[location] = config_line.substr(config_line.find("=")+1);
    location++;
  }
  configure_file.close();
  
  voteServerIp = configs[0];
  voteServerUser = configs[1];
  voteServerPw = configs[2];
  sealMainInVotePath = configs[3];

  queryServerIp = configs[4];
  queryServerUser = configs[5];
  queryServerPw = configs[6];
  sealMainInQueryPath = configs[7];

  //Private join configuration
  gsIp = configs[8];
  gsUser = configs[9];
  gsPw = configs[10];
  sealServerIngsPath = configs[11];
  priAndjoinServerIngsPath = configs[12];

  gcIp = configs[13];
  gcUser = configs[14];
  gcPw = configs[15];
  priAndjoinClientIngcPath = configs[16];
  // config file read end

  insert_to_FHE_operation(relinkey_path, insertfile_path, weight_path, vote_path, result_path);
}

void weblink_eval(string relinkey_path, string func, string filein_path, string filecipher_path, string result_path)
{
  // config file read start
  string config_file_path = "/root/config.txt";

  string voteServerIp;
  string voteServerUser;
  string voteServerPw;
  string sealMainInVotePath;

  string queryServerIp;
  string queryServerUser;
  string queryServerPw;
  string sealMainInQueryPath;

  //Private join configuration
  string gsIp;
  string gsUser;
  string gsPw;
  string sealServerIngsPath;
  string priAndjoinServerIngsPath;

  string gcIp;
  string gcUser;
  string gcPw;
  string priAndjoinClientIngcPath;
  ifstream configure_file;
  configure_file.open(config_file_path);
  string configs[17];
  string config_line;
  int location = 0;
  while (getline(configure_file, config_line)) {
    configs[location] = config_line.substr(config_line.find("=")+1);
    location++;
  }
  configure_file.close();
  
  voteServerIp = configs[0];
  voteServerUser = configs[1];
  voteServerPw = configs[2];
  sealMainInVotePath = configs[3];

  queryServerIp = configs[4];
  queryServerUser = configs[5];
  queryServerPw = configs[6];
  sealMainInQueryPath = configs[7];

  //Private join configuration
  gsIp = configs[8];
  gsUser = configs[9];
  gsPw = configs[10];
  sealServerIngsPath = configs[11];
  priAndjoinServerIngsPath = configs[12];

  gcIp = configs[13];
  gcUser = configs[14];
  gcPw = configs[15];
  priAndjoinClientIngcPath = configs[16];
  // config file read end

  multiplyoradd(relinkey_path, func, filein_path, filecipher_path, result_path);
}

JNIEXPORT void JNICALL Java_com_weblinkon_jni_Homomorphism_multiply
  (JNIEnv *env, jobject obejct, jstring relinkey_path_jstring, jstring filein_path_jstring, jstring filecipher_path_jstring, jstring result_path_jstring)
{
  string relinkey_path = env->GetStringUTFChars(relinkey_path_jstring, 0);
  string filein_path = env->GetStringUTFChars(filein_path_jstring, 0);
  string filecipher_path = env->GetStringUTFChars(filecipher_path_jstring, 0);
  string result_path = env->GetStringUTFChars(result_path_jstring, 0);

  // config file read start
  string config_file_path = "/root/config.txt";

  string voteServerIp;
  string voteServerUser;
  string voteServerPw;
  string sealMainInVotePath;

  string queryServerIp;
  string queryServerUser;
  string queryServerPw;
  string sealMainInQueryPath;

  //Private join configuration
  string gsIp;
  string gsUser;
  string gsPw;
  string sealServerIngsPath;
  string priAndjoinServerIngsPath;

  string gcIp;
  string gcUser;
  string gcPw;
  string priAndjoinClientIngcPath;
  ifstream configure_file;
  configure_file.open(config_file_path);
  string configs[17];
  string config_line;
  int location = 0;
  while (getline(configure_file, config_line)) {
    configs[location] = config_line.substr(config_line.find("=")+1);
    location++;
  }
  configure_file.close();
  
  voteServerIp = configs[0];
  voteServerUser = configs[1];
  voteServerPw = configs[2];
  sealMainInVotePath = configs[3];

  queryServerIp = configs[4];
  queryServerUser = configs[5];
  queryServerPw = configs[6];
  sealMainInQueryPath = configs[7];

  //Private join configuration
  gsIp = configs[8];
  gsUser = configs[9];
  gsPw = configs[10];
  sealServerIngsPath = configs[11];
  priAndjoinServerIngsPath = configs[12];

  gcIp = configs[13];
  gcUser = configs[14];
  gcPw = configs[15];
  priAndjoinClientIngcPath = configs[16];
  // config file read end

  homomorfic_multiply(relinkey_path, filein_path, filecipher_path, result_path);
}

JNIEXPORT void JNICALL Java_com_weblinkon_jni_Homomorphism_add
  (JNIEnv *env, jobject obejct, jstring relinkey_path_jstring, jstring filein_path_jstring, jstring filecipher_path_jstring, jstring result_path_jstring)
{
  string relinkey_path = env->GetStringUTFChars(relinkey_path_jstring, 0);
  string filein_path = env->GetStringUTFChars(filein_path_jstring, 0);
  string filecipher_path = env->GetStringUTFChars(filecipher_path_jstring, 0);
  string result_path = env->GetStringUTFChars(result_path_jstring, 0);

  // config file read start
  string config_file_path = "/root/config.txt";

  string voteServerIp;
  string voteServerUser;
  string voteServerPw;
  string sealMainInVotePath;

  string queryServerIp;
  string queryServerUser;
  string queryServerPw;
  string sealMainInQueryPath;

  //Private join configuration
  string gsIp;
  string gsUser;
  string gsPw;
  string sealServerIngsPath;
  string priAndjoinServerIngsPath;

  string gcIp;
  string gcUser;
  string gcPw;
  string priAndjoinClientIngcPath;
  ifstream configure_file;
  configure_file.open(config_file_path);
  string configs[17];
  string config_line;
  int location = 0;
  while (getline(configure_file, config_line)) {
    configs[location] = config_line.substr(config_line.find("=")+1);
    location++;
  }
  configure_file.close();
  
  voteServerIp = configs[0];
  voteServerUser = configs[1];
  voteServerPw = configs[2];
  sealMainInVotePath = configs[3];

  queryServerIp = configs[4];
  queryServerUser = configs[5];
  queryServerPw = configs[6];
  sealMainInQueryPath = configs[7];

  //Private join configuration
  gsIp = configs[8];
  gsUser = configs[9];
  gsPw = configs[10];
  sealServerIngsPath = configs[11];
  priAndjoinServerIngsPath = configs[12];

  gcIp = configs[13];
  gcUser = configs[14];
  gcPw = configs[15];
  priAndjoinClientIngcPath = configs[16];
  // config file read end

  homomorfic_add(relinkey_path, filein_path, filecipher_path, result_path);
}

void decrypt(string cipher_str)
{
  // config file read start
  string config_file_path = "/root/config.txt";

  string voteServerIp;
  string voteServerUser;
  string voteServerPw;
  string sealMainInVotePath;

  string queryServerIp;
  string queryServerUser;
  string queryServerPw;
  string sealMainInQueryPath;

  //Private join configuration
  string gsIp;
  string gsUser;
  string gsPw;
  string sealServerIngsPath;
  string priAndjoinServerIngsPath;

  string gcIp;
  string gcUser;
  string gcPw;
  string priAndjoinClientIngcPath;
  ifstream configure_file;
  configure_file.open(config_file_path);
  string configs[17];
  string config_line;
  int location = 0;
  while (getline(configure_file, config_line)) {
    configs[location] = config_line.substr(config_line.find("=")+1);
    location++;
  }
  configure_file.close();
  
  voteServerIp = configs[0];
  voteServerUser = configs[1];
  voteServerPw = configs[2];
  sealMainInVotePath = configs[3];

  queryServerIp = configs[4];
  queryServerUser = configs[5];
  queryServerPw = configs[6];
  sealMainInQueryPath = configs[7];

  //Private join configuration
  gsIp = configs[8];
  gsUser = configs[9];
  gsPw = configs[10];
  sealServerIngsPath = configs[11];
  priAndjoinServerIngsPath = configs[12];

  gcIp = configs[13];
  gcUser = configs[14];
  gcPw = configs[15];
  priAndjoinClientIngcPath = configs[16];
  // config file read end

  ifstream readtxt;
  readtxt.open(sealMainInQueryPath + "native/webserver-encrypt/keys/numlength.txt");
  string str_read;
  getline(readtxt, str_read);
  readtxt.close();

  decrypt_file(sealMainInQueryPath + "native/webserver-encrypt/keys/secretkey", sealMainInQueryPath + "native/webserver-encrypt/inputcipher/"+cipher_str, sealMainInQueryPath + "native/webserver-encrypt/outputresultcsv/"+ cipher_str, str_read);
}

void weblink_decrypt(string secretkey_path, string cipher_path, string result_path, string candidate)
{
  // config file read start
  string config_file_path = "/root/config.txt";

  string voteServerIp;
  string voteServerUser;
  string voteServerPw;
  string sealMainInVotePath;

  string queryServerIp;
  string queryServerUser;
  string queryServerPw;
  string sealMainInQueryPath;

  //Private join configuration
  string gsIp;
  string gsUser;
  string gsPw;
  string sealServerIngsPath;
  string priAndjoinServerIngsPath;

  string gcIp;
  string gcUser;
  string gcPw;
  string priAndjoinClientIngcPath;
  ifstream configure_file;
  configure_file.open(config_file_path);
  string configs[17];
  string config_line;
  int location = 0;
  while (getline(configure_file, config_line)) {
    configs[location] = config_line.substr(config_line.find("=")+1);
    location++;
  }
  configure_file.close();
  
  voteServerIp = configs[0];
  voteServerUser = configs[1];
  voteServerPw = configs[2];
  sealMainInVotePath = configs[3];

  queryServerIp = configs[4];
  queryServerUser = configs[5];
  queryServerPw = configs[6];
  sealMainInQueryPath = configs[7];

  //Private join configuration
  gsIp = configs[8];
  gsUser = configs[9];
  gsPw = configs[10];
  sealServerIngsPath = configs[11];
  priAndjoinServerIngsPath = configs[12];

  gcIp = configs[13];
  gcUser = configs[14];
  gcPw = configs[15];
  priAndjoinClientIngcPath = configs[16];
  // config file read end

  decrypt_file(secretkey_path, cipher_path, result_path, candidate);
}

JNIEXPORT void JNICALL Java_com_weblinkon_jni_Homomorphism_decrypt
  (JNIEnv *env, jobject obejct, jstring secretkey_path_jstring, jstring cipher_path_jstring, jstring result_path_jstring, jint candidate_jint)
{
  try{
    string secretkey_path = env->GetStringUTFChars(secretkey_path_jstring, 0);
    string cipher_path = env->GetStringUTFChars(cipher_path_jstring, 0);
    string result_path = env->GetStringUTFChars(result_path_jstring, 0);
    int candidate = (int)candidate_jint;

    // config file read start
    string config_file_path = "/root/config.txt";

    string voteServerIp;
    string voteServerUser;
    string voteServerPw;
    string sealMainInVotePath;

    string queryServerIp;
    string queryServerUser;
    string queryServerPw;
    string sealMainInQueryPath;

    //Private join configuration
    string gsIp;
    string gsUser;
    string gsPw;
    string sealServerIngsPath;
    string priAndjoinServerIngsPath;

    string gcIp;
    string gcUser;
    string gcPw;
    string priAndjoinClientIngcPath;
    ifstream configure_file;
    configure_file.open(config_file_path);
    string configs[17];
    string config_line;
    int location = 0;
    while (getline(configure_file, config_line)) {
      configs[location] = config_line.substr(config_line.find("=")+1);
      location++;
    }
    configure_file.close();
    
    voteServerIp = configs[0];
    voteServerUser = configs[1];
    voteServerPw = configs[2];
    sealMainInVotePath = configs[3];

    queryServerIp = configs[4];
    queryServerUser = configs[5];
    queryServerPw = configs[6];
    sealMainInQueryPath = configs[7];

    //Private join configuration
    gsIp = configs[8];
    gsUser = configs[9];
    gsPw = configs[10];
    sealServerIngsPath = configs[11];
    priAndjoinServerIngsPath = configs[12];

    gcIp = configs[13];
    gcUser = configs[14];
    gcPw = configs[15];
    priAndjoinClientIngcPath = configs[16];
    // config file read end

    decrypt_file_JNI(secretkey_path, cipher_path, result_path, candidate);
  }
  catch (CException e) {
    cout<< "Exception happened!" << endl;
  }
  catch (...) {
    cout<< "Exception happened!" << endl;
  }
}