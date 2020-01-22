#pragma once
#include "../set_1/set_1.hpp" // reuse utilities from previous sets

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
	std::cout << "Task 10 passed" << std::endl;
}