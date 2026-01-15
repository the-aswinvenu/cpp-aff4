/*
 * Quick test for AFF4 hash functionality.
 * Build: g++ -std=c++17 -I.. -I../build test_hash.cc -L../build -laff4 -lssl -lcrypto -lraptor2 -lz -lsnappy -llz4 -o test_hash
 */

#include "aff4/aff4_hash.h"
#include "aff4/data_store.h"
#include "aff4/lexicon.h"
#include <iostream>
#include <cassert>
#include <cstring>

using namespace aff4;

void test_hash_types() {
    std::cout << "Testing hash type utilities... ";
    
    assert(HashTypeToString(HashType::HASH_MD5) == "md5");
    assert(HashTypeToString(HashType::HASH_SHA1) == "sha1");
    assert(HashTypeToString(HashType::HASH_SHA256) == "sha256");
    assert(HashTypeToString(HashType::HASH_SHA512) == "sha512");
    
    assert(HashTypeFromString("md5") == HashType::HASH_MD5);
    assert(HashTypeFromString("SHA256") == HashType::HASH_SHA256);
    assert(HashTypeFromString("BLAKE2B") == HashType::HASH_BLAKE2B);
    
    assert(HashDigestLength(HashType::HASH_MD5) == 16);
    assert(HashDigestLength(HashType::HASH_SHA1) == 20);
    assert(HashDigestLength(HashType::HASH_SHA256) == 32);
    assert(HashDigestLength(HashType::HASH_SHA512) == 64);
    
    std::cout << "PASS" << std::endl;
}

void test_single_hash() {
    std::cout << "Testing single hash computation... ";
    
    // Test vectors from various sources
    const char* test_data = "hello world";
    
    // MD5
    auto md5_hasher = HasherFactory::Create(HashType::HASH_MD5);
    assert(md5_hasher != nullptr);
    
    AFF4Hash md5_hash;
    AFF4Status status = md5_hasher->HashString(test_data, md5_hash);
    assert(status == STATUS_OK);
    assert(md5_hash.type == HashType::HASH_MD5);
    // MD5("hello world") = 5eb63bbbe01eeed093cb22bb8f5acdc3
    assert(md5_hash.HexDigest() == "5eb63bbbe01eeed093cb22bb8f5acdc3");
    
    // SHA1
    auto sha1_hasher = HasherFactory::Create(HashType::HASH_SHA1);
    AFF4Hash sha1_hash;
    status = sha1_hasher->HashString(test_data, sha1_hash);
    assert(status == STATUS_OK);
    // SHA1("hello world") = 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed
    assert(sha1_hash.HexDigest() == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
    
    // SHA256
    auto sha256_hasher = HasherFactory::Create(HashType::HASH_SHA256);
    AFF4Hash sha256_hash;
    status = sha256_hasher->HashString(test_data, sha256_hash);
    assert(status == STATUS_OK);
    // SHA256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    assert(sha256_hash.HexDigest() == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    
    std::cout << "PASS" << std::endl;
}

void test_streaming_hash() {
    std::cout << "Testing streaming hash computation... ";
    
    auto hasher = HasherFactory::Create(HashType::HASH_SHA256);
    assert(hasher != nullptr);
    
    AFF4Status status = hasher->Init();
    assert(status == STATUS_OK);
    
    // Feed data in chunks
    status = hasher->Update("hello", 5);
    assert(status == STATUS_OK);
    
    status = hasher->Update(" ", 1);
    assert(status == STATUS_OK);
    
    status = hasher->Update("world", 5);
    assert(status == STATUS_OK);
    
    AFF4Hash hash;
    status = hasher->Finalize(hash);
    assert(status == STATUS_OK);
    
    // Should be same as hashing "hello world" at once
    assert(hash.HexDigest() == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    
    std::cout << "PASS" << std::endl;
}

void test_multi_hasher() {
    std::cout << "Testing multi-hash computation... ";
    
    MultiHasher multi;
    
    AFF4Status status = multi.AddHashType(HashType::HASH_MD5);
    assert(status == STATUS_OK);
    
    status = multi.AddHashType(HashType::HASH_SHA1);
    assert(status == STATUS_OK);
    
    status = multi.AddHashType(HashType::HASH_SHA256);
    assert(status == STATUS_OK);
    
    assert(multi.Count() == 3);
    
    const char* test_data = "hello world";
    std::vector<AFF4Hash> results;
    
    status = multi.HashBuffer(test_data, strlen(test_data), results);
    assert(status == STATUS_OK);
    assert(results.size() == 3);
    
    // Check each result
    bool found_md5 = false, found_sha1 = false, found_sha256 = false;
    for (const auto& h : results) {
        if (h.type == HashType::HASH_MD5) {
            assert(h.HexDigest() == "5eb63bbbe01eeed093cb22bb8f5acdc3");
            found_md5 = true;
        } else if (h.type == HashType::HASH_SHA1) {
            assert(h.HexDigest() == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
            found_sha1 = true;
        } else if (h.type == HashType::HASH_SHA256) {
            assert(h.HexDigest() == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
            found_sha256 = true;
        }
    }
    assert(found_md5 && found_sha1 && found_sha256);
    
    std::cout << "PASS" << std::endl;
}

void test_hex_conversion() {
    std::cout << "Testing hex digest conversion... ";
    
    AFF4Hash hash;
    AFF4Status status = AFF4Hash::FromHexDigest(
        HashType::HASH_MD5,
        "5eb63bbbe01eeed093cb22bb8f5acdc3",
        hash);
    
    assert(status == STATUS_OK);
    assert(hash.type == HashType::HASH_MD5);
    assert(hash.HexDigest() == "5eb63bbbe01eeed093cb22bb8f5acdc3");
    
    // Test invalid hex
    status = AFF4Hash::FromHexDigest(HashType::HASH_MD5, "invalid", hash);
    assert(status == INVALID_INPUT);
    
    std::cout << "PASS" << std::endl;
}

void test_hash_verification() {
    std::cout << "Testing hash verification... ";
    
    auto hasher = HasherFactory::Create(HashType::HASH_SHA256);
    AFF4Hash computed;
    hasher->HashString("hello world", computed);
    
    AFF4Hash expected;
    AFF4Hash::FromHexDigest(
        HashType::HASH_SHA256,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        expected);
    
    assert(VerifyHash(expected, computed) == true);
    
    // Test with wrong hash
    AFF4Hash wrong;
    AFF4Hash::FromHexDigest(
        HashType::HASH_SHA256,
        "0000000000000000000000000000000000000000000000000000000000000000",
        wrong);
    
    assert(VerifyHash(wrong, computed) == false);
    
    std::cout << "PASS" << std::endl;
}

void test_supported_types() {
    std::cout << "Testing supported types... ";
    
    auto types = HasherFactory::SupportedTypes();
    assert(!types.empty());
    
    for (HashType t : types) {
        assert(HasherFactory::IsSupported(t));
        auto hasher = HasherFactory::Create(t);
        assert(hasher != nullptr);
        
        AFF4Hash hash;
        AFF4Status status = hasher->HashString("test", hash);
        assert(status == STATUS_OK);
        assert(hash.IsValid());
        
        std::cout << HashTypeToString(t) << " ";
    }
    
    std::cout << "PASS" << std::endl;
}

void test_datastore_integration() {
    std::cout << "Testing DataStore integration... ";
    
    // Create an in-memory data store
    MemoryDataStore resolver;
    
    // Create a test URN
    URN subject("aff4://test-image");
    
    // Compute a hash
    auto hasher = HasherFactory::Create(HashType::HASH_SHA256);
    AFF4Hash hash;
    hasher->HashString("test data", hash);
    
    // Store the hash
    AFF4Status status = StoreHash(&resolver, subject, hash);
    assert(status == STATUS_OK);
    
    // Retrieve the hash
    AFF4Hash retrieved;
    status = GetHash(&resolver, subject, HashType::HASH_SHA256, retrieved);
    assert(status == STATUS_OK);
    assert(retrieved.type == HashType::HASH_SHA256);
    assert(retrieved.HexDigest() == hash.HexDigest());
    
    // Test getting a non-existent hash type
    AFF4Hash notfound;
    status = GetHash(&resolver, subject, HashType::HASH_MD5, notfound);
    assert(status == NOT_FOUND);
    
    // Test GetAllHashes
    auto md5_hasher = HasherFactory::Create(HashType::HASH_MD5);
    AFF4Hash md5_hash;
    md5_hasher->HashString("test data", md5_hash);
    status = StoreHash(&resolver, subject, md5_hash);
    assert(status == STATUS_OK);
    
    std::vector<AFF4Hash> all_hashes;
    status = GetAllHashes(&resolver, subject, all_hashes);
    assert(status == STATUS_OK);
    assert(all_hashes.size() == 2);
    
    // Test lexicon URIs
    assert(GetHashAttributeURI(HashType::HASH_SHA256) == AFF4_HASH_SHA256);
    assert(GetImageHashAttributeURI(HashType::HASH_SHA256) == AFF4_IMAGE_HASH_SHA256);
    assert(GetBlockHashAttributeURI(HashType::HASH_SHA256) == AFF4_BLOCK_HASH_SHA256);
    
    std::cout << "PASS" << std::endl;
}

int main() {
    std::cout << "=== AFF4 Hash Module Tests ===" << std::endl;
    
    test_hash_types();
    test_single_hash();
    test_streaming_hash();
    test_multi_hasher();
    test_hex_conversion();
    test_hash_verification();
    test_supported_types();
    test_datastore_integration();
    
    std::cout << std::endl << "All tests PASSED!" << std::endl;
    return 0;
}
