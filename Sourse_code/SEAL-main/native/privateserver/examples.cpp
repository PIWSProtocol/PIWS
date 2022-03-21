// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

#include <stdlib.h>

using namespace std;
using namespace seal;

void save_Ciphertext_into_file(string filename, Ciphertext const& ciphertext){
  ofstream ct;
  ct.open(filename, ios::binary);
  ciphertext.save(ct);
}

void save_PublicKey_into_file(string filename, PublicKey const& publicKey){
  ofstream ct;
  ct.open(filename, ios::binary);
  publicKey.save(ct);
}

void save_SecretKey_into_file(string filename, SecretKey const& secretKey){
  ofstream ct;
  ct.open(filename, ios::binary);
  secretKey.save(ct);
}

Ciphertext load_Ciphertext_from_file(string filename, SEALContext context){

  ifstream ct;
  ct.open(filename, ios::binary);
  Ciphertext result;
  result.load(context, ct);

  return result;
}

PublicKey load_PublicKey_from_file(string filename, SEALContext context){
  ifstream ct;
  ct.open(filename, ios::binary);
  PublicKey result;
  result.load(context, ct);
  return result;
}

SecretKey load_SecretKey_from_file(string filename, SEALContext context){
  ifstream ct;
  ct.open(filename, ios::binary);
  SecretKey result;
  result.load(context, ct);
  return result;
}

int main()
{
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    double scale = pow(2.0, 40);

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    save_SecretKey_into_file("secretkey",secret_key);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    save_PublicKey_into_file("pubkey",public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);   
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    SecretKey secret_key_ro = load_SecretKey_from_file("secretkey",context);
    
    Decryptor decryptor(context, secret_key_ro);

    PublicKey public_key_ro = load_PublicKey_from_file("pubkey",context);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input1,input2,input3,input4;

    input1 = { 0, 1, 0};
    input2 = { 2, 2, 2 };
    input3 = { 1, 0, 0 };
    input4 = { 3, 3, 3 };
    
    int numlength = sizeof(input1) / sizeof(input1[0]);
    cout<<numlength<<endl;

    /*
    We create plaintexts for PI, 0.4, and 1 using an overload of CKKSEncoder::encode
    that encodes the given floating-point value to every slot in the vector.
    */
    Plaintext plain_input1, plain_input2, plain_input3, plain_input4;
    cout << "Encode input vectors." << endl;
    encoder.encode(input1, scale, plain_input1);
    encoder.encode(input2, scale, plain_input2);
    encoder.encode(input3, scale, plain_input3);
    encoder.encode(input4, scale, plain_input4);

    print_line(__LINE__);
    cout << "Encrypt input vectors." << endl;
    Ciphertext input1_encrypted, input2_encrypted, input3_encrypted, input4_encrypted;

    encryptor.encrypt(plain_input1, input1_encrypted);
    encryptor.encrypt(plain_input2, input2_encrypted);
    encryptor.encrypt(plain_input3, input3_encrypted);
    encryptor.encrypt(plain_input4, input4_encrypted);

    string filename = "cipher1";
    save_Ciphertext_into_file(filename, input1_encrypted);
    cout<<input1_encrypted.parms_id()<<endl;

    Ciphertext dd = load_Ciphertext_from_file(filename, context);
    cout<<dd.parms_id()<<endl;

    Ciphertext temp;
	  Ciphertext result_c;

    evaluator.multiply(input1_encrypted,input2_encrypted,temp);
	  evaluator.relinearize_inplace(temp, relin_keys);
    cout << " input1 * input2 before rescale: " << log2(temp.scale()) << " bits" << endl;
	  evaluator.rescale_to_next_inplace(temp);
    cout << " input1 * input2 after rescale: " << log2(temp.scale()) << " bits" << endl;

    cout << "    + Modulus chain index for input3_encrypted: "
    << context.get_context_data(input3_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for temp(input1_encrypted*input2_encrypted): "
    << context.get_context_data(temp.parms_id())->chain_index() << endl;

    Ciphertext temp1;
    evaluator.multiply(input3_encrypted,input4_encrypted,temp1);
    evaluator.relinearize_inplace(temp1, relin_keys);
    evaluator.rescale_to_next_inplace(temp1);

    cout << "    + Modulus chain index for input3_encrypted: "
    << context.get_context_data(temp1.parms_id())->chain_index() << endl;
    
    evaluator.add(temp, temp1, result_c);
    
    Plaintext result_p;
	  decryptor.decrypt(result_c, result_p);
    //注意要解码到一个向量上
    vector<double> result;
    encoder.decode(result_p, result);
    //得到结果 
    //正确的话将输出：{6.000，24.000，60.000，...，0.000，0.000，0.000}
    cout << "结果是：" << endl;
    print_vector(result,3,3);

    vector<double> copy(result.begin(), result.begin() + numlength);
    print_vector(copy);
    /*
    While we did not show any computations on complex numbers in these examples,
    the CKKSEncoder would allow us to have done that just as easily. Additions
    and multiplications of complex numbers behave just as one would expect.
    */
    return 0;
}