// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include <assert.h>

#include <stdio.h>
#include <stdlib.h>

using namespace std;
using namespace seal;

//Web server configuration

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

//   auto context = SEALContext::Create(parms);

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

int main(int count, char* input_parameters[])
{
    string addedvotelist_csv = input_parameters[1];
    ifstream data_file;
    data_file.open("./config.txt");
    
    string configs[17];
    string line;
    int location = 0;
    while (getline(data_file, line)) {
      configs[location] = line.substr(line.find("=")+1);
      location++;
    }
    data_file.close();

    string voteServerIp = configs[0];
    string voteServerUser = configs[1];
    string voteServerPw = configs[2];
    string sealMainInVotePath = configs[3];

    string queryServerIp = configs[4];
    string queryServerUser = configs[5];
    string queryServerPw = configs[6];
    string sealMainInQueryPath = configs[7];

    //Private join configuration
    string gsIp = configs[8];
    string gsUser = configs[9];
    string gsPw = configs[10];
    string sealServerIngsPath = configs[11];
    string priAndjoinServerIngsPath = configs[12];

    string gcIp = configs[13];
    string gcUser = configs[14];
    string gcPw = configs[15];
    string priAndjoinClientIngcPath = configs[16];

    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    double scale = pow(2.0, 40);

    SEALContext context(parms);
    
    string addedvotelistcsvname = addedvotelist_csv.substr(addedvotelist_csv.find_last_of('-')+1);
    string uuidname = addedvotelistcsvname.substr(0, addedvotelistcsvname.find("."));
    string relienkeyname = "relienkey-" + uuidname;

    // KeyGenerator keygen(context);
    RelinKeys relin_keys = load_RelinKeys_from_file(sealServerIngsPath + "native/server-add/input/outputserver/" + relienkeyname, context);
  
    Evaluator evaluator(context);
    string addedfilelist_path = sealServerIngsPath + "native/server-add/input/" + addedvotelist_csv;

    data_file.open(addedfilelist_path);
    int line_number = 0;
    // string votefiledir;
    Ciphertext result;

    while (getline(data_file, line)) {
      string vote_path = sealServerIngsPath + "native/server-add/input/outputserver/ciphers/vote/";
      string weight_path = sealServerIngsPath + "native/server-add/input/outputserver/ciphers/weight/";
      
      vector<string> columns = SplitCsvLine(line);

      vote_path.append(columns[0]);
      weight_path.append(columns[1]);

      Ciphertext votecipher = load_Ciphertext_from_file(vote_path,context);
  	std::cout<<"vote ok!"<<std::endl;
      Ciphertext weightcipher = load_Ciphertext_from_file(weight_path,context);
      std::cout<<" weight ok!"<<std::endl;
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
    data_file.close();
	  string resultname = addedvotelist_csv.substr(0, addedvotelist_csv.find("."));
    save_Ciphertext_into_file(sealServerIngsPath + "native/server-add/output/" + resultname,result);

    system(("sshpass -p "+ queryServerPw +" scp "+ sealServerIngsPath +"native/server-add/input/"+ addedvotelist_csv + " " + queryServerUser +"@"+ queryServerIp +":"+ sealMainInQueryPath +"native/webserver-encrypt/inputcipher").c_str());
    system(("sshpass -p "+ queryServerPw +" scp "+ sealServerIngsPath +"native/server-add/output/"+ resultname + " " + queryServerUser +"@"+ queryServerIp +":"+ sealMainInQueryPath +"native/webserver-encrypt/inputcipher").c_str());
    
    system(("sshpass -p "+ queryServerPw +" ssh -o StrictHostKeyChecking=no "+ queryServerUser +"@"+ queryServerIp +" "+ sealMainInQueryPath +"native/webserver-encrypt/build/bin/webserverencrypt weblink_decrypt "+resultname).c_str());

    return 0;
}
