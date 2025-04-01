#include <memory>
#include <cstring>
#include "driver.h"
#include <bitcoinfuzz/basemodule.h>

#ifdef BITCOIN_CORE
#include <modules/bitcoin/module.h>
#endif

#ifdef RUST_BITCOIN
#include <modules/rustbitcoin/module.h>
#endif

#ifdef MAKO
#include <modules/mako/module.h>
#endif

#ifdef RUST_MINISCRIPT
#include <modules/rustminiscript/module.h>
#endif

#ifdef BTCD
#include <modules/btcd/module.h>
#endif

#ifdef LND
#include <modules/lnd/module.h>
#endif

#ifdef LDK
#include <modules/ldk/module.h>
#endif

#ifdef NLIGHTNING
#include <modules/nlightning/module.h>
#endif

#ifdef EMBIT
#include <modules/embit/module.h>
#endif

#ifdef CUSTOM_MUTATOR_BOLT11
#include "modules/bitcoin/bech32.h"
#endif

std::shared_ptr<bitcoinfuzz::Driver> driver = nullptr;

#ifdef CUSTOM_MUTATOR_BOLT11
extern "C" size_t LLVMFuzzerMutate(uint8_t *data, size_t size, size_t max_size);
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *fuzz_data, size_t size, size_t max_size,
			       unsigned int seed);
extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t *in1, size_t in1_size, const uint8_t *in2,
				 size_t in2_size, uint8_t *out, size_t max_out_size,
				 unsigned seed);

// Encodes a dummy bolt11 invoice into `fuzz_data` and returns the size of the
// encoded string.
static size_t initial_input(uint8_t *fuzz_data, size_t size, size_t max_size)
{
    const std::string dummy =
        "lnbc16lta047pp5h6lta047h6lta047h6lta047h6lta047h6lta047h6lta047"
	    "h6lqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
	    "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqxnht6w";

    size_t output_size = std::min(max_size, dummy.size());
    std::memcpy(fuzz_data, dummy.data(), output_size);
    return output_size;
}

// We use a custom mutator to produce an input corpus that consists entirely of
// correctly encoded bech32 strings. This enables us to efficiently fuzz the
// bolt11 decoding logic without the fuzzer getting stuck on fuzzing the bech32
// decoding/encoding logic.
//
// This custom mutator does the following things:
//   1. Attempt to bech32 decode the given input (returns the encoded dummy
//      invoice on failure).
//   2. Mutate either the human readable or data part of the invoice using
//      libFuzzer's default mutator `LLVMFuzzerMutate`.
//   3. Attempt to bech32 encode the mutated hrp and data (returns the endcoded
//      dummy on failure).
//   4. Write the encoded result to `fuzz_data` if its size does not exceed
//      `max_size`, otherwise return the encoded dummy invoice.
extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

size_t LLVMFuzzerCustomMutator(uint8_t *fuzz_data, size_t size, size_t max_size,
                               unsigned int seed)
{
    // A minimum size of 9 prevents hrp_maxlen <= 0 and data_maxlen <= 0.
    if (size < 9)
        return initial_input(fuzz_data, size, max_size);

    // Interpret fuzz input as string
    std::string input(reinterpret_cast<char*>(fuzz_data), size);

    // Attempt to bech32 decode the input
    bech32::DecodeResult decoded = bech32::Decode(input, bech32::CharLimit::CUSTOM_MUTATOR);
    if (decoded.encoding != bech32::Encoding::BECH32) {
        // Decoding failed, this should only happen when starting from
        // an empty corpus.
        return initial_input(fuzz_data, size, max_size);
    }

    auto data = decoded.data;
    auto hrp = decoded.hrp;

    size_t data_maxlen = input.size() > 8 ? std::min(input.size() - 8, static_cast<size_t>(65)) : 0;
    size_t hrp_maxlen = input.size() > 6 ? std::min(input.size() - 6, static_cast<size_t>(83)) : 0;

    // Mutate either the hrp or data
    std::srand(seed);
    switch (std::rand() % 2) {
        case 0: { // Mutate hrp
            if (hrp_maxlen > 0) {
                // Make sure we have a buffer that's large enough for mutation
                std::vector<uint8_t> hrp_buffer(hrp.begin(), hrp.end());
                // Reserve enough space for the maximum mutation size
                hrp_buffer.resize(hrp_maxlen);

                // Mutate the buffer
                size_t new_len = LLVMFuzzerMutate(hrp_buffer.data(),
                                                 hrp.size(),
                                                 hrp_maxlen - 1);

                // Ensure minimum length and validate - at least 1 character
                new_len = std::max(new_len, static_cast<size_t>(1));

                // Convert back to string with the new length
                hrp = std::string(reinterpret_cast<char*>(hrp_buffer.data()), new_len);

                // Sanitize hrp - ensure only valid ASCII characters (33-126) and not uppercase
                for (char& c : hrp) {
                    if (c < 33 || c > 126) {
                        c = 'a' + (c % 26); // Replace with a valid lowercase letter
                    } else if (c >= 'A' && c <= 'Z') {
                        c = c - 'A' + 'a'; // Convert uppercase to lowercase
                    }
                }
            }
            break;
        }
        case 1: { // Mutate data
            if (data_maxlen > 0) {
                // Make sure we have a buffer that's large enough for mutation
                data.resize(std::max(data.size(), data_maxlen));

                size_t datalen = data.size();
                size_t new_len = LLVMFuzzerMutate(data.data(),
                                                 std::min(datalen, data_maxlen),
                                                 data_maxlen);

                new_len = std::max(new_len, static_cast<size_t>(1));
                data.resize(new_len);

                for (auto& val : data) {
                    val &= 0x1F;
                }
            }
            break;
        }
    }

    if (hrp.empty() || hrp.size() > 83) {
        return initial_input(fuzz_data, size, max_size);
    } else if (!hrp.empty()) {
        for (const char& c : hrp) {
            if (c >= 'A' && c <= 'Z') {
                return initial_input(fuzz_data, size, max_size);
            }
        }
    }

    if (data.empty() || data.size() > 65) {
        return initial_input(fuzz_data, size, max_size);
    }

    std::string output = bech32::Encode(bech32::Encoding::BECH32, hrp, data);

    if (output.empty() || output.length() > max_size) {
        return initial_input(fuzz_data, size, max_size);
    }

    std::memcpy(fuzz_data, output.data(), output.length());
    return output.length();
}

static size_t insert_part(const uint8_t *in1, size_t in1_size, const uint8_t *in2,
                        size_t in2_size, uint8_t *out, size_t max_out_size)
{
    if (in1_size >= max_out_size || in1_size == 0 || in2_size == 0)
        return 0;

    size_t max_insert_size = std::min(max_out_size - in1_size, in2_size);
    size_t insert_begin = std::rand() % in1_size;
    size_t insert_size = (std::rand() % max_insert_size) + 1;
    size_t in2_begin = std::rand() % (in2_size - insert_size + 1);

    std::memcpy(out, in1, insert_begin);
    std::memcpy(out + insert_begin, in2 + in2_begin, insert_size);
    std::memcpy(out + insert_begin + insert_size, in1 + insert_begin,
               in1_size - insert_begin);

    return in1_size + insert_size;
}

static size_t overwrite_part(const uint8_t *in1, size_t in1_size, const uint8_t *in2,
                           size_t in2_size, uint8_t *out, size_t max_out_size)
{
    if (in1_size > max_out_size || in1_size == 0)
        return 0;

    size_t overwrite_begin = std::rand() % in1_size;
    size_t overwrite_size = (std::rand() % (in1_size - overwrite_begin)) + 1;
    overwrite_size = std::min(overwrite_size, in2_size);
    size_t in2_begin = std::rand() % (in2_size - overwrite_size + 1);

    std::memcpy(out, in1, in1_size);
    std::memcpy(out + overwrite_begin, in2 + in2_begin, overwrite_size);

    return in1_size;
}

size_t cross_over(const uint8_t *in1, size_t in1_size, const uint8_t *in2,
                size_t in2_size, uint8_t *out, size_t max_out_size, unsigned seed)
{
    std::srand(seed);
    if (std::rand() % 2)
        return insert_part(in1, in1_size, in2, in2_size, out, max_out_size);
    return overwrite_part(in1, in1_size, in2, in2_size, out, max_out_size);
}

size_t LLVMFuzzerCustomCrossOver(const uint8_t *in1, size_t in1_size, const uint8_t *in2,
                               size_t in2_size, uint8_t *out, size_t max_out_size,
                               unsigned seed)
{
    if (in1_size < 9 || in2_size < 9)
        return 0;

    // Interpret fuzz inputs as strings
    std::string input1(reinterpret_cast<const char*>(in1), in1_size);
    std::string input2(reinterpret_cast<const char*>(in2), in2_size);

    // Attempt to bech32 decode the inputs
    bech32::DecodeResult result1 = bech32::Decode(input1, bech32::CharLimit::CUSTOM_MUTATOR);
    if (result1.encoding != bech32::Encoding::BECH32) {
        // Decoding failed
        return 0;
    }

    bech32::DecodeResult result2 = bech32::Decode(input2, bech32::CharLimit::CUSTOM_MUTATOR);
    if (result2.encoding != bech32::Encoding::BECH32) {
        // Decoding failed
        return 0;
    }

    std::string hrp1 = result1.hrp;
    std::string hrp2 = result2.hrp;
    std::vector<uint8_t> data1 = result1.data;
    std::vector<uint8_t> data2 = result2.data;

    std::srand(seed);
    std::string out_hrp;
    std::vector<uint8_t> out_data;

    if (std::rand() % 2) {
        // Cross-over the HRP
        out_data = data1;

        // Convert strings to vectors for cross_over function
        std::vector<uint8_t> hrp1_vec(hrp1.begin(), hrp1.end());
        std::vector<uint8_t> hrp2_vec(hrp2.begin(), hrp2.end());
        std::vector<uint8_t> out_hrp_vec(max_out_size - data1.size() - 8);

        size_t out_hrp_size = cross_over(
            hrp1_vec.data(), hrp1_vec.size(),
            hrp2_vec.data(), hrp2_vec.size(),
            out_hrp_vec.data(), out_hrp_vec.size(),
            (unsigned)std::rand());

        // Convert back to string and ensure null termination
        out_hrp = std::string(out_hrp_vec.begin(), out_hrp_vec.begin() + out_hrp_size);
    } else {
        // Cross-over the data part
        out_hrp = hrp1;

        size_t max_out_data_size = max_out_size - hrp1.size() - 8;
        std::vector<uint8_t> out_data_vec(max_out_data_size);

        size_t out_data_size = cross_over(
            data1.data(), data1.size(),
            data2.data(), data2.size(),
            out_data_vec.data(), max_out_data_size,
            (unsigned)std::rand());

        out_data.assign(out_data_vec.begin(), out_data_vec.begin() + out_data_size);
    }

    // Encode the output
    std::string encoded = bech32::Encode(bech32::Encoding::BECH32, out_hrp, out_data);

    if (encoded.empty() || encoded.size() > max_out_size) {
        return 0;
    }

    // Copy the result to out buffer
    std::memcpy(out, encoded.data(), encoded.size());
    return encoded.size();
}
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
  const char* target = std::getenv("FUZZ");
  driver = std::make_shared<bitcoinfuzz::Driver>();
#ifdef BITCOIN_CORE
  driver->LoadModule(std::make_shared<bitcoinfuzz::module::Bitcoin>());
#endif
#ifdef RUST_BITCOIN
  driver->LoadModule(std::make_shared<bitcoinfuzz::module::Rustbitcoin>());
#endif
#ifdef MAKO
  driver->LoadModule(std::make_shared<bitcoinfuzz::module::Mako>());
#endif
#ifdef RUST_MINISCRIPT
  driver->LoadModule(std::make_shared<bitcoinfuzz::module::Rustminiscript>());
#endif
#ifdef BTCD
  driver->LoadModule(std::make_shared<bitcoinfuzz::module::Btcd>());
#endif
#ifdef LND
  driver->LoadModule(std::make_shared<bitcoinfuzz::module::Lnd>());
#endif
#ifdef LDK
  driver->LoadModule(std::make_shared<bitcoinfuzz::module::Ldk>());
#endif
#ifdef NLIGHTNING
  driver->LoadModule(std::make_shared<bitcoinfuzz::module::NLightning>());
#endif
#ifdef EMBIT
  driver->LoadModule(std::make_shared<bitcoinfuzz::module::Embit>());
#endif

  driver->Run(Data, Size, target);
  return 0;
}
