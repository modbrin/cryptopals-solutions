#pragma once
#include "../set_1/set_1.hpp" // reuse utilities from previous sets
#include <algorithm>

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
std::vector<std::byte> aes_cbc(
	std::vector<std::byte> const& cipher_str,
	std::vector<std::byte> const& key,
	std::byte iv_default_fill = (std::byte)'\x00',
	std::vector<std::byte> iv = {})
{
	if (iv.size() == 0) iv.resize(AES_BLOCK_SIZE, iv_default_fill); // initialize init vector
	assert(iv.size() == AES_BLOCK_SIZE); // iv size must match block size, which is 128-bit (16 byte) for AES
	
	auto cipher_str_padded = pad_message(cipher_str, AES_BLOCK_SIZE);

	// prepare key
	AES_KEY aes_key;
	if constexpr(decipher) AES_set_decrypt_key(reinterpret_cast<unsigned char const*>(key.data()), 128, &aes_key);
	else AES_set_encrypt_key(reinterpret_cast<unsigned char const*>(key.data()), 128, &aes_key);
	
	// prepare data and output container
	auto const msg = reinterpret_cast<unsigned char const*>(cipher_str_padded.data());
	std::unique_ptr<unsigned char[]> result(new unsigned char[cipher_str_padded.size()]);
	
	// process block by block
	for (int i = 0; i < cipher_str_padded.size(); i += AES_BLOCK_SIZE)
	{
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
		if constexpr(decipher) if (result[i] == '\x04') break; // End-Of-Transmission received
		output.push_back(static_cast<std::byte>(result[i]));
	}
	return output;
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

	std::cout << "Task 10 (decrypted):\n" << as_str(output).substr(0, 100) << "..." << std::endl;
}