#pragma once
#include "../set_1/set_1.hpp" // reuse utilities from previous sets
#include <algorithm>
#include <random>

// TASK 9 #######################################################################

std::vector<std::byte> pad_message(
    std::vector<std::byte> in,
    size_t block_size,
    std::byte pad_byte = (std::byte)'\x04'
)
{
    size_t const pad_elems = (block_size - in.size() % block_size) % block_size;
    if (pad_elems > 0) in.resize(in.size() + pad_elems, pad_byte);
    return in;
}

// TASK 10 #######################################################################

template<bool decipher = false>
std::vector<std::byte> aes_ecb(
    std::vector<std::byte> const& cipher_str,
    std::vector<std::byte> const& key_bytes)
{

    auto cipher_str_padded = decipher ? cipher_str : pad_message(cipher_str, AES_BLOCK_SIZE); // padding only needed for encryption

    // prepare key
    AES_KEY key;
    if constexpr (decipher)
        AES_set_decrypt_key((unsigned char const*)key_bytes.data(), 128, &key);
    else
        AES_set_encrypt_key((unsigned char const*)key_bytes.data(), 128, &key);

    // prepare data and output container
    auto const msg = reinterpret_cast<unsigned char const*>(cipher_str_padded.data());
    std::unique_ptr<unsigned char[]> result(new unsigned char[cipher_str_padded.size()]);
    // process block by block
    for (int i = 0; i < cipher_str_padded.size(); i += AES_BLOCK_SIZE) // AES always has block size of 128-bit i.e. 16 bytes
        AES_ecb_encrypt(msg + i, result.get() + i, &key, decipher ? AES_DECRYPT : AES_ENCRYPT);

    // collect result, ignore padding
    std::vector<std::byte> output;
    output.reserve(cipher_str_padded.size());


    for (int i = 0; i < cipher_str_padded.size(); ++i) {
        if constexpr (decipher) if (result[i] == '\x04') break; // End-Of-Transmission received
        output.push_back(static_cast<std::byte>(result[i]));
    }
    return output;
}

template<bool decipher = false>
std::vector<std::byte> aes_cbc(
    std::vector<std::byte> const& cipher_str,
    std::vector<std::byte> const& key,
    std::byte iv_default_fill = (std::byte)'\x00',
    std::vector<std::byte> iv = {})
{
    if (iv.size() == 0) iv.resize(AES_BLOCK_SIZE, iv_default_fill); // initialize init vector
    assert(iv.size() == AES_BLOCK_SIZE); // iv size must match block size, which is 128-bit (16 byte) for AES

    auto cipher_str_padded = decipher?cipher_str:pad_message(cipher_str, AES_BLOCK_SIZE); // padding only needed for encryption

    // prepare key
    AES_KEY aes_key;
    if constexpr (decipher) AES_set_decrypt_key(reinterpret_cast<unsigned char const*>(key.data()), 128, &aes_key);
    else AES_set_encrypt_key(reinterpret_cast<unsigned char const*>(key.data()), 128, &aes_key);

    // prepare data and output container
    auto const msg = reinterpret_cast<unsigned char const*>(cipher_str_padded.data());
    std::unique_ptr<unsigned char[]> result(new unsigned char[cipher_str_padded.size()]);

    // process block by block
    for (int i = 0; i < cipher_str_padded.size(); i += AES_BLOCK_SIZE) {
        if constexpr (decipher) {
            AES_ecb_encrypt(msg + i, result.get() + i, &aes_key, AES_DECRYPT);
            std::transform(iv.begin(), iv.end(), result.get() + i, result.get() + i, [](auto a, auto b) { return (unsigned char)(a ^ (std::byte)b); });
            iv = std::vector<std::byte>((std::byte*)msg + i, (std::byte*)msg + i + AES_BLOCK_SIZE);
        }
        else {
            unsigned char temp[AES_BLOCK_SIZE];
            std::transform(iv.begin(), iv.end(), msg + i, temp, [](auto a, auto b) { return (unsigned char)(a ^ (std::byte)b); });
            AES_ecb_encrypt(temp, result.get() + i, &aes_key, AES_ENCRYPT);
            iv = std::vector<std::byte>((std::byte*)result.get() + i, (std::byte*)result.get() + i + AES_BLOCK_SIZE);
        }
    }

    // collect result, ignore padding
    std::vector<std::byte> output;
    output.reserve(cipher_str_padded.size());
    for (int i = 0; i < cipher_str_padded.size(); ++i) {
        if constexpr (decipher) if (result[i] == '\x04') break; // End-Of-Transmission received
        output.push_back(static_cast<std::byte>(result[i]));
    }
    return output;
}

// TASK 11 #######################################################################

std::vector<std::byte> generate_random_key(size_t length = AES_BLOCK_SIZE)
{
    std::random_device generator;
    std::uniform_int_distribution<unsigned short> distribution;
    std::vector<std::byte> result(length);
    std::for_each(result.begin(), result.end(), [&](auto& val) { val = (std::byte)distribution(generator); });
    return result;
}

std::vector<std::byte> encryption_oracle(std::vector<std::byte> const& cipher_str, std::vector<std::byte> const& = {})
{
    std::random_device generator;
    std::uniform_int_distribution<int> range_distr(5, 10);
    std::uniform_int_distribution<int> value_distr(0, 255);
    auto const pre_append_bytes = range_distr(generator), post_append_bytes = range_distr(generator);

    std::vector<std::byte> formatted;
    formatted.reserve(pre_append_bytes + cipher_str.size() + post_append_bytes);

    for (int i = 0; i < pre_append_bytes; ++i) formatted.push_back((std::byte)value_distr(generator));
    std::for_each(cipher_str.begin(), cipher_str.end(), [&](auto const& val) { formatted.push_back(val); });
    for (int i = 0; i < post_append_bytes; ++i) formatted.push_back((std::byte)value_distr(generator));

    std::uniform_int_distribution decision_distr(0, 1);
    std::vector<std::byte> result;

    if (decision_distr(generator))
    {
        std::cout << "This is ECB" << std::endl;
        result = aes_ecb<false>(cipher_str, generate_random_key()); // ecb
    } // with probability of 1/2 select cbc or ecb
    else
    {
        std::cout << "This is CBC" << std::endl;
        result = aes_cbc<false>(cipher_str, generate_random_key(), {}, generate_random_key()); // cbc
    }
    
    return result;
}

enum class AES_BLOCK_MODE {
    ECB, CBC
};

AES_BLOCK_MODE aes_mode_detect(std::function<std::vector<std::byte>(std::vector<std::byte> const&, std::vector<std::byte> const&)> func)
{
    std::vector<std::byte> cleartext(4 * AES_BLOCK_SIZE, (std::byte)'a'); // with size of 4 blocks, two adjacent blocks will always
                                                                          // be filled with value of 'a' byte
    auto cipher = encryption_oracle(cleartext);

    for (int i = AES_BLOCK_SIZE; i < cipher.size() - AES_BLOCK_SIZE; i += AES_BLOCK_SIZE) {
        if (std::equal(cipher.data() - AES_BLOCK_SIZE + i, cipher.data() + i, cipher.data() + i))
            return AES_BLOCK_MODE::ECB; // if single repeat is found, there is no overlapping between adjacent blocks which happens with cbc
    }

    return AES_BLOCK_MODE::CBC;
}

// RUNNERS #######################################################################

void task_9()
{
    assert(as_str(pad_message(as_bytes("YELLOW SUBMARINE"), 20)) == "YELLOW SUBMARINE\x04\x04\x04\x04");
    assert(as_str(pad_message(as_bytes("12345"), 3)) == "12345\x04");
    assert(as_str(pad_message(as_bytes("12"), 2)) == "12");
    assert(as_str(pad_message(as_bytes("12345678"), 2)) == "12345678");
    assert(as_str(pad_message(as_bytes("1234567"), 5)) == "1234567\x04\x04\x04");

    std::cout << "Task 9 passed" << std::endl;
}

void task_10()
{
    const std::string key = "YELLOW SUBMARINE";
    std::fstream infile("set_2/task10.txt", std::ios::in);
    if (!infile) throw std::runtime_error("opening file failed");

    // read base64-encoded cipher from file
    std::string encoded, fragment;
    while (getline(infile, fragment)) encoded += fragment;

    // decode input
    auto cipher = base64_decode(encoded);
    auto output = aes_cbc<true>(cipher, as_bytes(key));

    assert(as_str(aes_cbc<true>(aes_cbc<false>(output, as_bytes(key)), as_bytes(key))) == as_str(output));
    assert(as_str(aes_ecb<true>(aes_ecb<false>(output, as_bytes(key)), as_bytes(key))) == as_str(output));

    std::cout << "Task 10 (decrypted):\n" << as_str(output).substr(0, 100) << "..." << std::endl;
}

void task_11()
{
    // test if random ciphertext is produced
    std::string input = "One is the loneliest number that you'll ever do\nTwo can be as bad as one\nIt's the loneliest number since the number one";
    auto result = encryption_oracle(as_bytes(input));
    std::for_each(result.begin(), result.end(), [](auto const& val) {std::cout << std::hex << (int)val; });
    std::cout << std::endl;

    // test prediction function
    for (int i = 0; i < 10; ++i){
        auto res = aes_mode_detect(encryption_oracle);
        std::cout << "Predicted: " << ((res == AES_BLOCK_MODE::ECB) ? "ECB" : "CBC") << '\n' << std::endl;
    }

    std::cout << "Task 11 passed" << std::endl;
}