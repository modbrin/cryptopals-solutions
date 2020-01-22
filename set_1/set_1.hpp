#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <bitset>
#include <cassert>
#include <unordered_map>
#include <fstream>
#include <iomanip>
#include <array>
#include <functional>
#include <cstddef>
#include <unordered_set>
#include <sstream>
#include <openssl/aes.h>

// UTILS #######################################################################

// transform string with printed hex numbers into bytes
std::vector<std::byte> hex_str_to_bytes(std::string const& hex) {
	std::vector<std::byte> bytes;
	for (size_t i = 0; i < hex.size(); i += 2) {
		std::istringstream iss(hex.substr(i, 2));
		unsigned long b;
		iss >> std::hex >> b;
		bytes.push_back((std::byte) b);
	}
	return bytes;
}

// transform bytes into string with printed hex numbers
std::string bytes_to_hex_str(std::vector<std::byte> const& in) {
	std::stringstream result;
	for (auto const& elem : in)
		result << std::hex << std::setfill('0') << std::setw(2) << (int)elem;
	return result.str();
}

std::vector<std::byte> as_bytes(std::string const& in) {
	std::vector<std::byte> result;
	result.reserve(in.size());
	for (auto const& elem : in)
		result.push_back((std::byte) elem);
	return result;
}

std::string as_str(std::vector<std::byte> const& in) {
	std::string result;
	result.reserve(in.size());
	for (auto const& byte : in)
		result += (char)byte;
	return result;
}

// TASK 1 #######################################################################

const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

// parser-like approach to base64 encoding
std::string base64_encode(std::vector<std::byte> bytes) {
	std::stringstream buffer;
	int hexCounter = 0, octCounter = 0;
	size_t iter = 0;
	std::string hexBuffer;
	hexBuffer.resize(6);
	std::string result;

	while (true) {
		if (hexCounter == 0 && iter >= bytes.size()) {
			while (octCounter % 8 != 0) {
				octCounter += 6;
				result += '=';
			}
			break;
		}
		if (hexCounter < 6) {
			if (iter >= bytes.size()) { // last real char
				if (hexCounter != 0) {  // some data, pad with zeros
					int fpad = 6 - hexCounter;
					for (int i = 0; i < fpad; ++i) buffer << '0';
					hexCounter += fpad;
					octCounter += fpad;
				}
			}
			else {
				buffer << std::bitset<8>((unsigned char)bytes[iter]).to_string();
				hexCounter += 8;
				octCounter += 8;
				++iter;
			}
		}
		buffer.read(&hexBuffer[0], 6);
		result += base64_chars[std::stoi(hexBuffer, nullptr, 2)];
		hexCounter -= 6;
	}
	return result;
}

char base64_to_index(char in) {
	// TODO resolve integral promotions warnings
	if (in >= 65 && in <= 90)       // from A to Z
		return in - 65;             // map to 0-25
	else if (in >= 97 && in <= 122) // from a to z
		return in - 97 + 26;        // map to 26-51
	else if (in >= 48 && in <= 57)  // from 0 to 9
		return in - 48 + 52;        // map to 52-61
	else if (in == 43)                    // for +
		return 62;
	else if (in == 47)                    // for /
		return 63;
	else throw std::runtime_error("unexpected base64 character");
}

std::vector<std::byte> base64_decode(std::string in) {
	std::stringstream buffer;
	int octCounter = 0;
	std::string octBuffer;
	octBuffer.resize(8);
	std::vector<std::byte> result;
	int iter = 0;
	bool must_end = false;

	while (true) {
		if (iter >= in.size() || in.at(iter) == '=') {
			break;
		}
		while (octCounter < 8) {
			if (iter >= in.size() || in.at(iter) == '=') {
				must_end = true;
			}
			buffer << std::bitset<6>((unsigned char)base64_to_index(in.at(iter)));
			++iter;
			octCounter += 6;
		}
		if (must_end) break;
		buffer.read(&octBuffer[0], 8);
		result.push_back(static_cast<std::byte>(std::stoi(octBuffer, nullptr, 2)));
		octCounter -= 8;
	}
	return result;
}

std::string hex_str_to_base64(std::string const& in) {
	return base64_encode(hex_str_to_bytes(in));
}

std::string base64_to_hex_str(std::string const& in) {
	return bytes_to_hex_str(base64_decode(in));
}

// TASK 2 #######################################################################

std::string fixed_length_xor(std::string const& hexA, std::string const& hexB) {
	std::stringstream result;
	std::vector<std::byte> a = hex_str_to_bytes(hexA), b = hex_str_to_bytes(hexB);
	for (int i = 0; i < a.size(); ++i) {
		result << std::hex << static_cast<int>(a[i] ^ b[i]);
	}
	return result.str();
}

// TASK 3 #######################################################################

std::vector<std::byte> single_byte_xor_decode(std::vector<std::byte> const& bytes, std::byte const key) {
	std::vector<std::byte> result;
	result.reserve(bytes.size());
	for (auto const& elem : bytes) result.push_back(elem ^ key);
	return result;
}

std::vector<std::byte> single_byte_xor_decode_hex(std::vector<std::byte> const& hex, std::byte const key) {
	return single_byte_xor_decode(hex_str_to_bytes(as_str(hex)), key);
}


// TASK 4 #######################################################################

// data is taken from http://www.data-compression.com/english.html
const std::unordered_map<char, double> english_letter_frequencies{
		{'a', 0.0651738},
		{'b', 0.0124248},
		{'c', 0.0217339},
		{'d', 0.0349835},
		{'e', 0.1041442},
		{'f', 0.0197881},
		{'g', 0.0158610},
		{'h', 0.0492888},
		{'i', 0.0558094},
		{'j', 0.0009033},
		{'k', 0.0050529},
		{'l', 0.0331490},
		{'m', 0.0202124},
		{'n', 0.0564513},
		{'o', 0.0596302},
		{'p', 0.0596302},
		{'q', 0.0008606},
		{'r', 0.0497563},
		{'s', 0.0515760},
		{'t', 0.0729357},
		{'u', 0.0225134},
		{'v', 0.0082903},
		{'w', 0.0171272},
		{'x', 0.0013692},
		{'y', 0.0145984},
		{'z', 0.0007836},
		{' ', 0.1918182}
};

// rate string based on english letter frequencies, better rating is greater
double rate_english_frequency(std::string const& in) {
	double result = 0;
	for (auto const& elem : in)
		if (english_letter_frequencies.find(std::tolower(elem)) != english_letter_frequencies.end())
			result += english_letter_frequencies.at(std::tolower(elem));
	return result;
}

std::byte brute_single_byte_xor(std::vector<std::byte> const& in,
	std::function<std::vector<std::byte>(std::vector<std::byte>,
		std::byte)> const& decode = single_byte_xor_decode) {
	std::string curr_guess;
	double max_rating = 0, curr_rating;
	unsigned char best_key = 0;
	for (unsigned k = 0; k <= 255; k += 1) {
		curr_guess = as_str(decode(in, (std::byte) k));
		curr_rating = rate_english_frequency(curr_guess);
		if (curr_rating > max_rating) {
			max_rating = curr_rating;
			best_key = k;
		}
	}
	return (std::byte) best_key;
}

std::byte brute_single_byte_xor_hex(std::vector<std::byte> const& in) {
	return brute_single_byte_xor(in, single_byte_xor_decode_hex);
}

// TASK 5 #######################################################################

std::vector<std::byte> repeating_key_xor(std::vector<std::byte> const& in, std::vector<std::byte> const& key) {
	std::vector<std::byte> result(in.size());
	for (int i = 0; i < in.size(); ++i)
		result[i] = in[i] ^ key[i % key.size()];
	return result;
}

std::string repeating_key_xor_string_hex(std::string const& in, std::string const& key) {
	std::stringstream result;
	for (auto const& elem : repeating_key_xor(as_bytes(in), as_bytes(key))) {
		result << std::hex << std::setfill('0') << std::setw(2) << (int)elem;
	}
	return result.str();
}

std::string repeating_key_xor_string(std::string const& in, std::string const& key) {
	std::stringstream result;
	for (auto const& elem : repeating_key_xor(as_bytes(in), as_bytes(key))) {
		result << (char)elem;
	}
	return result.str();
}

// TASK 6 #######################################################################

std::vector<std::byte> str_to_bytes(std::string const& in) {
	std::vector<std::byte> result;
	for (auto const& elem : in) result.push_back((std::byte) elem);
	return result;
}


int hamming_distance(std::vector<std::byte> const& a, std::vector<std::byte> const& b) {
	assert(a.size() == b.size());
	int counter = 0;
	for (int i = 0; i < a.size(); ++i) {
		auto bs = std::bitset<8>((unsigned char)(a[i] ^ b[i]));
		for (int j = 0; j < bs.size(); ++j)
			if (bs[j]) ++counter;
	}
	return counter;
}

int string_distance(std::string const& a, std::string const& b) {
	return hamming_distance(str_to_bytes(a), str_to_bytes(b));
}

double normalized_edit_distance(std::vector<std::byte> const& a, std::vector<std::byte> const& b) {
	return hamming_distance(a, b) / (double)a.size();
}

double normalized_string_edit_distance(std::string const& a, std::string const& b) {
	return normalized_edit_distance(str_to_bytes(a), str_to_bytes(b));
}

bool sort_by_second_ascend(const std::tuple<int, double>& a,
	const std::tuple<int, double>& b) {
	return (std::get<1>(a) < std::get<1>(b));
}

template<typename Ty>
std::vector<Ty> subvector(std::vector<Ty> in, size_t from, size_t count) {
	return std::vector<Ty>(in.begin() + from, in.begin() + from + count);
}

std::vector<int>
find_keysizes(std::vector<std::byte> const& cipher, const int chunks_num = 2, const int best_count = 3) {
	size_t const keymin = 2, keymax = 40;
	assert(best_count < keymax - keymin + 1);

	std::vector<std::pair<int, double>> distances;

	for (size_t i = keymin; i <= keymax; ++i) {
		std::vector<std::vector<std::byte>> chunks;
		for (size_t j = 0; j * i + i - 1 < cipher.size(); ++j)
			chunks.push_back(subvector(cipher, j * i, i));
		double avgdist = 0.;
		for (int j = 0; j < chunks.size() - 1; ++j)
			avgdist += normalized_edit_distance(chunks[j], chunks[j + 1]);
		avgdist /= (double)chunks.size() - 1;
		distances.emplace_back(i, avgdist); // save keysize=avgdist pair
	}
	std::sort(distances.begin(), distances.end(), sort_by_second_ascend);
	std::vector<int> result(best_count);
	for (int i = 0; i < best_count; ++i)
		result[i] = std::get<0>(distances[i]);

	return result;
}

std::vector<std::vector<std::byte>> split_into_chunks(std::vector<std::byte> const& in, const int chunk_size) {
	std::vector<std::vector<std::byte>> result;
	for (int i = 0; i < chunk_size; ++i) {
		std::vector<std::byte> current;
		int j = i;
		while (j < in.size()) {
			current.push_back(in[j]);
			j += chunk_size;
		}
		if (current.empty()) break;
		result.push_back(current);
	}
	return result;
}

std::vector<std::byte> brute_repeating_key_xor(std::vector<std::byte> const& cipher) {
	auto keysizes = find_keysizes(cipher);

	std::vector<std::byte> best_key;
	double max_rate = 0;

	for (auto const& ks : keysizes) {
		auto chunks = split_into_chunks(cipher, ks);
		std::vector<std::byte> guess_key;
		for (auto const& chunk : chunks) // each chunk is encrypted with single cipherkey byte
		{
			guess_key.push_back(brute_single_byte_xor(chunk));
		}
		auto guess = repeating_key_xor(cipher, guess_key);
		auto rate = rate_english_frequency(as_str(guess));
		if (rate > max_rate) {
			max_rate = rate;
			best_key = guess_key;
		}
	}
	return best_key;
}

// TASK 7 #######################################################################

std::string decipher_aes_ecb(std::string cipher_str, std::string key) {
	// prepare key
	AES_KEY dec_key;
	AES_set_decrypt_key((unsigned char*)key.c_str(), 128, &dec_key);

	// prepare data and output container
	const char* msg = cipher_str.c_str();
	char* result = new char[cipher_str.size()];
	// process block by block
	for (int i = 0; i < cipher_str.size(); i += AES_BLOCK_SIZE) // AES always has block size of 128-bit i.e. 16 bytes
		AES_ecb_encrypt((unsigned char*)msg + i, (unsigned char*)result + i, &dec_key, AES_DECRYPT);
	// collect result, ignore padding
	std::string output;
	for (int i = 0; i < cipher_str.size(); ++i) {
		if (result[i] == '\x04') break; // End-Of-Transmission received
		output += result[i];
	}
	return output;
}

// TASK 8 #######################################################################

int find_aes_ecb_repeats(std::string const& cipher) {
	std::unordered_set<std::string> block_occurances;
	int repeats = 0;
	for (int i = 0; i < cipher.size(); i += AES_BLOCK_SIZE) {
		std::string block = cipher.substr(i, AES_BLOCK_SIZE);
		if (block_occurances.find(block) != block_occurances.end())
			++repeats;
		else
			block_occurances.insert(block);
	}
	return repeats;
}

// RUNNERS #######################################################################

// Implement base64 encoding/decoding
void task_1() {
	assert(hex_str_to_base64("") == "");
	assert(hex_str_to_base64("66") == "Zg==");
	assert(hex_str_to_base64("666f") == "Zm8=");
	assert(hex_str_to_base64("666f6f") == "Zm9v");
	assert(hex_str_to_base64("666f6f62") == "Zm9vYg==");
	assert(hex_str_to_base64("666f6f6261") == "Zm9vYmE=");
	assert(hex_str_to_base64("666f6f626172") == "Zm9vYmFy");
	assert(hex_str_to_base64(
		"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") ==
		"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

	assert(base64_to_hex_str("") == "");
	assert(base64_to_hex_str("Zg==") == "66");
	assert(base64_to_hex_str("Zm8=") == "666f");
	assert(base64_to_hex_str("Zm9v") == "666f6f");
	assert(base64_to_hex_str("Zm9vYg==") == "666f6f62");
	assert(base64_to_hex_str("Zm9vYmE=") == "666f6f6261");
	assert(base64_to_hex_str("Zm9vYmFy") == "666f6f626172");
	assert(base64_to_hex_str("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t") ==
		"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");

	std::cout << "Task 1 passed" << std::endl;
}

// Implement fixed length xor function
void task_2() {
	assert(fixed_length_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") ==
		"746865206b696420646f6e277420706c6179");
	std::cout << "Task 2 passed" << std::endl;
}

// Break single-byte-xor cipher
void task_3() {
	auto cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
	auto key = brute_single_byte_xor_hex(as_bytes(cipher));
	std::cout << "Task 3 (best guess): " << as_str(single_byte_xor_decode_hex(as_bytes(cipher), key)) << std::endl;
}

// Find and break single-byte-xor cipher from bunch of samples
void task_4() {
	std::string line;
	std::fstream infile("set_1/task4.txt", std::ios::in);

	std::string best_guess, curr_guess;
	double max_rating = 0, curr_rating;

	while (getline(infile, line)) {
		std::byte key = brute_single_byte_xor_hex(as_bytes(line));
		curr_guess = as_str(single_byte_xor_decode_hex(as_bytes(line), key));
		curr_rating = rate_english_frequency(curr_guess);
		if (curr_rating > max_rating) {
			max_rating = curr_rating;
			best_guess = curr_guess;
		}
	}
	std::cout << "Task 4 (best guess): " << best_guess << std::endl;
}

// Implement repeating-key-xor encryption/decryption
void task_5() {
	auto r1 = repeating_key_xor_string_hex(
		"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE");
	assert(r1 == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
		"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
	std::cout << "Task 5 passed" << std::endl;
}

// Break base64-encoded ciphertext as repeating-key-xor
void task_6() {
	assert(string_distance("this is a test", "wokka wokka!!!") == 37);

	std::fstream infile("set_1/task6.txt", std::ios::in);
	if (!infile) throw std::runtime_error("opening file failed");

	// read base64-encoded cipher from file
	std::string encoded{}, fragment{};
	while (getline(infile, fragment)) encoded += fragment;

	// decode input
	auto cipher = base64_decode(encoded);

	// get best key
	auto best_key = brute_repeating_key_xor(cipher);

	std::cout << "Task 6 (best key: " << as_str(best_key) << ")" << std::endl;
	std::cout << "Best guess: " << as_str(repeating_key_xor(cipher, best_key)).substr(0, 100) << "..." << std::endl;
}

void task_7() {
	const std::string key = "YELLOW SUBMARINE";
	std::fstream infile("set_1/task7.txt", std::ios::in);
	if (!infile) throw std::runtime_error("opening file failed");

	// read base64-encoded cipher from file
	std::string encoded, fragment;
	while (getline(infile, fragment)) encoded += fragment;

	// decode input
	auto cipher = base64_decode(encoded);

	auto output = decipher_aes_ecb(as_str(cipher), key);
	std::cout << "Task 7 (decrypted):\n" << output.substr(0, 100) << "..." << std::endl;
}

// Detect AES in ECB mode from bunch of hex-encoded ciphertexts
void task_8() {
	std::fstream infile("set_1/task8.txt", std::ios::in);
	if (!infile) throw std::runtime_error("opening file failed");

	std::string likely_ecb_cipher;
	int max_repeats = -1;

	std::string line;
	while (getline(infile, line)) {
		int repeats = find_aes_ecb_repeats(as_str(hex_str_to_bytes(line)));
		if (repeats > max_repeats) {
			max_repeats = repeats;
			likely_ecb_cipher = line;
		}
	}
	std::cout << "Task 8: " << "(" << max_repeats << " repeats) "
		<< likely_ecb_cipher.substr(0, 30)
		<< "..."
		<< std::endl;
}