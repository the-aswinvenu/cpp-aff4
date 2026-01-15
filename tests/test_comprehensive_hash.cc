/*
Copyright 2015-2017 Google Inc. All rights reserved.
Copyright 2018-present Velocidex Innovations.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.  You may obtain a copy of the
License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied.  See the License for the
specific language governing permissions and limitations under the License.
*/

/**
 * @file test_comprehensive_hash.cc
 * @brief Comprehensive test suite for AFF4 hashing functionality.
 *
 * Tests all aspects of the hashing implementation including:
 * - Hash computation during imaging
 * - Hash storage in metadata
 * - Hash verification
 * - Large file handling
 * - Multiple hash types
 * - Error cases
 */

#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <memory>
#include <chrono>
#include <random>

#include "aff4/libaff4.h"
#include "aff4/aff4_image.h"
#include "aff4/aff4_hash.h"
#include "aff4/zip.h"

namespace aff4 {

// Test utilities
class TestTimer {
public:
    TestTimer(const std::string& name) : name_(name), 
        start_(std::chrono::high_resolution_clock::now()) {}
    
    ~TestTimer() {
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start_);
        std::cout << "  [TIMING] " << name_ << ": " << duration.count() << " ms\n";
    }

private:
    std::string name_;
    std::chrono::high_resolution_clock::time_point start_;
};

int tests_passed = 0;
int tests_failed = 0;

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            std::cerr << "FAIL: " << message << " (at " << __FILE__ << ":" << __LINE__ << ")\n"; \
            tests_failed++; \
            return false; \
        } \
    } while(0)

#define TEST_PASS(name) \
    do { \
        std::cout << "PASS: " << name << "\n"; \
        tests_passed++; \
        return true; \
    } while(0)


// Helper to create a test file with known content
std::string CreateTestFile(const std::string& path, size_t size, uint8_t seed = 0) {
    std::ofstream file(path, std::ios::binary);
    
    // Use deterministic random for reproducible tests
    std::mt19937 gen(seed);
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    
    const size_t chunk_size = 4096;
    std::vector<uint8_t> buffer(chunk_size);
    
    size_t remaining = size;
    while (remaining > 0) {
        size_t to_write = std::min(remaining, chunk_size);
        for (size_t i = 0; i < to_write; i++) {
            buffer[i] = dist(gen);
        }
        file.write(reinterpret_cast<char*>(buffer.data()), to_write);
        remaining -= to_write;
    }
    
    file.close();
    return path;
}


// Test 1: Basic hash computation with MultiHasher
bool TestMultiHasherBasic() {
    std::cout << "\n=== Test: MultiHasher Basic ===\n";
    
    MultiHasher hasher;
    TEST_ASSERT(hasher.AddHashType(HashType::HASH_MD5) == STATUS_OK, "Add MD5");
    TEST_ASSERT(hasher.AddHashType(HashType::HASH_SHA256) == STATUS_OK, "Add SHA256");
    TEST_ASSERT(hasher.Init() == STATUS_OK, "Init");
    
    std::string data = "The quick brown fox jumps over the lazy dog";
    TEST_ASSERT(hasher.Update(data.data(), data.size()) == STATUS_OK, "Update");
    
    std::vector<AFF4Hash> results;
    TEST_ASSERT(hasher.Finalize(results) == STATUS_OK, "Finalize");
    TEST_ASSERT(results.size() == 2, "Should have 2 hashes");
    
    // Known correct values
    // MD5("The quick brown fox jumps over the lazy dog") = 9e107d9d372bb6826bd81d3542a419d6
    // SHA256("The quick brown fox jumps over the lazy dog") = d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
    
    bool found_md5 = false, found_sha256 = false;
    for (const auto& hash : results) {
        if (hash.type == HashType::HASH_MD5) {
            TEST_ASSERT(hash.HexDigest() == "9e107d9d372bb6826bd81d3542a419d6", "MD5 value");
            found_md5 = true;
        } else if (hash.type == HashType::HASH_SHA256) {
            TEST_ASSERT(hash.HexDigest() == "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", "SHA256 value");
            found_sha256 = true;
        }
    }
    TEST_ASSERT(found_md5 && found_sha256, "Both hashes found");
    
    TEST_PASS("MultiHasher Basic");
}


// Test 2: All hash types
bool TestAllHashTypes() {
    std::cout << "\n=== Test: All Hash Types ===\n";
    
    std::vector<HashType> types = {
        HashType::HASH_MD5,
        HashType::HASH_SHA1,
        HashType::HASH_SHA256,
        HashType::HASH_SHA512,
        HashType::HASH_BLAKE2B
    };
    
    for (auto type : types) {
        std::cout << "  Testing " << HashTypeToString(type) << "...\n";
        
        auto hasher = HasherFactory::Create(type);
        TEST_ASSERT(hasher != nullptr, "Hasher created for " + HashTypeToString(type));
        TEST_ASSERT(hasher->Init() == STATUS_OK, "Init");
        
        std::string data = "test data";
        TEST_ASSERT(hasher->Update(data.data(), data.size()) == STATUS_OK, "Update");
        
        AFF4Hash result;
        TEST_ASSERT(hasher->Finalize(result) == STATUS_OK, "Finalize");
        TEST_ASSERT(result.IsValid(), "Hash is valid");
        TEST_ASSERT(result.digest.size() == HashDigestLength(type), "Correct digest length");
        
        std::cout << "    " << HashTypeToString(type) << ": " << result.HexDigest() << "\n";
    }
    
    TEST_PASS("All Hash Types");
}


// Test 3: Image hashing during write
bool TestImageHashDuringWrite() {
    std::cout << "\n=== Test: Image Hash During Write ===\n";
    
    const std::string test_file = "/tmp/test_hash_write.bin";
    const std::string aff4_file = "/tmp/test_hash_write.aff4";
    const size_t test_size = 20 * 1024 * 1024;  // 20MB to force AFF4Image path
    
    // Create test file
    {
        TestTimer timer("Create test file");
        CreateTestFile(test_file, test_size, 42);
    }
    
    // Remove any existing AFF4 file
    std::remove(aff4_file.c_str());
    
    MemoryDataStore resolver;
    URN volume_urn;
    URN image_urn;
    
    // Create AFF4 volume and image with hashing
    {
        TestTimer timer("Create AFF4 image with hashing");
        
        AFF4Flusher<FileBackedObject> file;
        TEST_ASSERT(NewFileBackedObject(&resolver, aff4_file, "truncate", file) == STATUS_OK, "Create backing file");
        
        AFF4Flusher<ZipFile> zip;
        TEST_ASSERT(ZipFile::NewZipFile(&resolver, std::move(file), zip) == STATUS_OK, "Create zip");
        volume_urn = zip->urn;
        
        AFF4Flusher<AFF4Image> image;
        image_urn = volume_urn.Append("test_image");
        TEST_ASSERT(AFF4Image::NewAFF4Image(&resolver, image_urn, zip.get(), image) == STATUS_OK, "Create image");
        
        // Enable all hash types
        std::vector<HashType> hash_types = {
            HashType::HASH_MD5,
            HashType::HASH_SHA1,
            HashType::HASH_SHA256
        };
        image->EnableHashing(hash_types);
        image->compression = AFF4_IMAGE_COMPRESSION_ENUM_ZLIB;
        
        // Read and write the test file
        AFF4Flusher<FileBackedObject> input;
        TEST_ASSERT(NewFileBackedObject(&resolver, test_file, "read", input) == STATUS_OK, "Open input");
        
        DefaultProgress progress(&resolver);
        TEST_ASSERT(image->WriteStream(input.get(), &progress) == STATUS_OK, "Write stream");
        
        // Check computed hashes
        std::vector<AFF4Hash> computed;
        TEST_ASSERT(image->GetComputedHashes(computed) == STATUS_OK, "Get computed hashes");
        TEST_ASSERT(computed.size() == 3, "Should have 3 computed hashes");
        
        std::cout << "  Computed hashes:\n";
        for (const auto& hash : computed) {
            std::cout << "    " << HashTypeToString(hash.type) << ": " << hash.HexDigest() << "\n";
        }
    }
    
    // Verify hashes were stored in metadata
    {
        std::vector<AFF4Hash> stored_hashes;
        TEST_ASSERT(GetAllImageHashes(&resolver, image_urn, stored_hashes) == STATUS_OK, "Get stored hashes");
        TEST_ASSERT(stored_hashes.size() == 3, "Should have 3 stored hashes");
        
        std::cout << "  Stored hashes:\n";
        for (const auto& hash : stored_hashes) {
            std::cout << "    " << HashTypeToString(hash.type) << ": " << hash.HexDigest() << "\n";
        }
    }
    
    // Cleanup
    std::remove(test_file.c_str());
    std::remove(aff4_file.c_str());
    
    TEST_PASS("Image Hash During Write");
}


// Test 4: Hash verification
bool TestHashVerification() {
    std::cout << "\n=== Test: Hash Verification ===\n";
    
    const std::string test_file = "/tmp/test_hash_verify.bin";
    const std::string aff4_file = "/tmp/test_hash_verify.aff4";
    const size_t test_size = 15 * 1024 * 1024;  // 15MB
    
    // Create test file with known seed for reproducibility
    CreateTestFile(test_file, test_size, 123);
    std::remove(aff4_file.c_str());
    
    MemoryDataStore resolver;
    URN volume_urn;
    URN image_urn;
    std::string expected_sha256;
    
    // Create image with hashing
    {
        AFF4Flusher<FileBackedObject> file;
        TEST_ASSERT(NewFileBackedObject(&resolver, aff4_file, "truncate", file) == STATUS_OK, "Create backing file");
        
        AFF4Flusher<ZipFile> zip;
        TEST_ASSERT(ZipFile::NewZipFile(&resolver, std::move(file), zip) == STATUS_OK, "Create zip");
        volume_urn = zip->urn;
        
        AFF4Flusher<AFF4Image> image;
        image_urn = volume_urn.Append("test_image");
        TEST_ASSERT(AFF4Image::NewAFF4Image(&resolver, image_urn, zip.get(), image) == STATUS_OK, "Create image");
        
        image->EnableHashing({HashType::HASH_SHA256});
        image->compression = AFF4_IMAGE_COMPRESSION_ENUM_ZLIB;
        
        AFF4Flusher<FileBackedObject> input;
        TEST_ASSERT(NewFileBackedObject(&resolver, test_file, "read", input) == STATUS_OK, "Open input");
        
        DefaultProgress progress(&resolver);
        TEST_ASSERT(image->WriteStream(input.get(), &progress) == STATUS_OK, "Write stream");
        
        std::vector<AFF4Hash> computed;
        image->GetComputedHashes(computed);
        expected_sha256 = computed[0].HexDigest();
        std::cout << "  Expected SHA256: " << expected_sha256 << "\n";
    }
    
    // Reopen and verify
    {
        MemoryDataStore resolver2;
        
        AFF4Flusher<FileBackedObject> backing;
        TEST_ASSERT(NewFileBackedObject(&resolver2, aff4_file, "read", backing) == STATUS_OK, "Open backing");
        
        AFF4Flusher<ZipFile> zip;
        TEST_ASSERT(ZipFile::OpenZipFile(&resolver2, std::move(backing), zip) == STATUS_OK, "Open zip");
        
        // Get stored hash
        AFF4Hash stored_hash;
        TEST_ASSERT(GetImageHash(&resolver2, image_urn, HashType::HASH_SHA256, stored_hash) == STATUS_OK, "Get stored hash");
        TEST_ASSERT(stored_hash.HexDigest() == expected_sha256, "Stored hash matches expected");
        
        // Read image and compute hash
        AFF4Flusher<AFF4Stream> stream;
        VolumeGroup volumes(&resolver2);
        volumes.AddVolume(std::move(zip));
        
        TEST_ASSERT(volumes.GetStream(image_urn, stream) == STATUS_OK, "Get stream");
        
        MultiHasher hasher;
        hasher.AddHashType(HashType::HASH_SHA256);
        hasher.Init();
        
        const size_t buffer_size = 1024 * 1024;
        stream->Seek(0, SEEK_SET);
        while (true) {
            std::string data = stream->Read(buffer_size);
            if (data.empty()) break;
            hasher.Update(data.data(), data.size());
        }
        
        std::vector<AFF4Hash> computed;
        hasher.Finalize(computed);
        
        std::cout << "  Computed SHA256: " << computed[0].HexDigest() << "\n";
        TEST_ASSERT(computed[0].HexDigest() == expected_sha256, "Verification passed");
    }
    
    // Cleanup
    std::remove(test_file.c_str());
    std::remove(aff4_file.c_str());
    
    TEST_PASS("Hash Verification");
}


// Test 5: Large file performance test
bool TestLargeFileHashing(const std::string& vdisk_path) {
    std::cout << "\n=== Test: Large File Hashing (" << vdisk_path << ") ===\n";
    
    // Check if vdisk exists
    std::ifstream check(vdisk_path);
    if (!check.good()) {
        std::cout << "  SKIP: vdisk.raw not found at " << vdisk_path << "\n";
        return true;  // Not a failure
    }
    check.close();
    
    const std::string aff4_file = "/tmp/test_vdisk.aff4";
    std::remove(aff4_file.c_str());
    
    MemoryDataStore resolver;
    URN volume_urn;
    URN image_urn;
    
    // Create image with hashing
    {
        TestTimer timer("Image vdisk.raw with SHA256");
        
        AFF4Flusher<FileBackedObject> file;
        TEST_ASSERT(NewFileBackedObject(&resolver, aff4_file, "truncate", file) == STATUS_OK, "Create backing file");
        
        AFF4Flusher<ZipFile> zip;
        TEST_ASSERT(ZipFile::NewZipFile(&resolver, std::move(file), zip) == STATUS_OK, "Create zip");
        volume_urn = zip->urn;
        
        AFF4Flusher<AFF4Image> image;
        image_urn = volume_urn.Append("vdisk");
        TEST_ASSERT(AFF4Image::NewAFF4Image(&resolver, image_urn, zip.get(), image) == STATUS_OK, "Create image");
        
        image->EnableHashing({HashType::HASH_SHA256});
        image->compression = AFF4_IMAGE_COMPRESSION_ENUM_ZLIB;
        
        AFF4Flusher<FileBackedObject> input;
        TEST_ASSERT(NewFileBackedObject(&resolver, vdisk_path, "read", input) == STATUS_OK, "Open vdisk");
        
        std::cout << "  Input size: " << input->Size() << " bytes\n";
        
        DefaultProgress progress(&resolver);
        progress.length = input->Size();
        TEST_ASSERT(image->WriteStream(input.get(), &progress) == STATUS_OK, "Write stream");
        
        std::vector<AFF4Hash> computed;
        image->GetComputedHashes(computed);
        std::cout << "  SHA256: " << computed[0].HexDigest() << "\n";
    }
    
    // Verify
    {
        TestTimer timer("Verify vdisk image");
        
        MemoryDataStore resolver2;
        
        AFF4Flusher<FileBackedObject> backing;
        TEST_ASSERT(NewFileBackedObject(&resolver2, aff4_file, "read", backing) == STATUS_OK, "Open backing");
        
        AFF4Flusher<ZipFile> zip;
        TEST_ASSERT(ZipFile::OpenZipFile(&resolver2, std::move(backing), zip) == STATUS_OK, "Open zip");
        
        AFF4Hash stored_hash;
        TEST_ASSERT(GetImageHash(&resolver2, image_urn, HashType::HASH_SHA256, stored_hash) == STATUS_OK, "Get stored hash");
        
        VolumeGroup volumes(&resolver2);
        volumes.AddVolume(std::move(zip));
        
        AFF4Flusher<AFF4Stream> stream;
        TEST_ASSERT(volumes.GetStream(image_urn, stream) == STATUS_OK, "Get stream");
        
        MultiHasher hasher;
        hasher.AddHashType(HashType::HASH_SHA256);
        hasher.Init();
        
        const size_t buffer_size = 4 * 1024 * 1024;  // 4MB chunks for large file
        stream->Seek(0, SEEK_SET);
        size_t total_read = 0;
        while (true) {
            std::string data = stream->Read(buffer_size);
            if (data.empty()) break;
            hasher.Update(data.data(), data.size());
            total_read += data.size();
        }
        
        std::vector<AFF4Hash> computed;
        hasher.Finalize(computed);
        
        std::cout << "  Total read: " << total_read << " bytes\n";
        std::cout << "  Computed: " << computed[0].HexDigest() << "\n";
        std::cout << "  Stored:   " << stored_hash.HexDigest() << "\n";
        
        TEST_ASSERT(computed[0] == stored_hash, "Verification passed for large file");
    }
    
    // Cleanup (optional - can keep for inspection)
    // std::remove(aff4_file.c_str());
    std::cout << "  Output preserved at: " << aff4_file << "\n";
    
    TEST_PASS("Large File Hashing");
}


// Test 6: Hash type name conversions
bool TestHashTypeConversions() {
    std::cout << "\n=== Test: Hash Type Conversions ===\n";
    
    // Test string conversions
    TEST_ASSERT(HashTypeToString(HashType::HASH_MD5) == "md5", "MD5 to string");
    TEST_ASSERT(HashTypeToString(HashType::HASH_SHA1) == "sha1", "SHA1 to string");
    TEST_ASSERT(HashTypeToString(HashType::HASH_SHA256) == "sha256", "SHA256 to string");
    TEST_ASSERT(HashTypeToString(HashType::HASH_SHA512) == "sha512", "SHA512 to string");
    TEST_ASSERT(HashTypeToString(HashType::HASH_BLAKE2B) == "blake2b", "BLAKE2B to string");
    
    // Test from string
    TEST_ASSERT(HashTypeFromString("md5") == HashType::HASH_MD5, "String to MD5");
    TEST_ASSERT(HashTypeFromString("sha1") == HashType::HASH_SHA1, "String to SHA1");
    TEST_ASSERT(HashTypeFromString("sha256") == HashType::HASH_SHA256, "String to SHA256");
    TEST_ASSERT(HashTypeFromString("sha512") == HashType::HASH_SHA512, "String to SHA512");
    TEST_ASSERT(HashTypeFromString("blake2b") == HashType::HASH_BLAKE2B, "String to BLAKE2B");
    TEST_ASSERT(HashTypeFromString("unknown") == HashType::HASH_NONE, "Unknown returns NONE");
    
    // Test digest lengths
    TEST_ASSERT(HashDigestLength(HashType::HASH_MD5) == 16, "MD5 length");
    TEST_ASSERT(HashDigestLength(HashType::HASH_SHA1) == 20, "SHA1 length");
    TEST_ASSERT(HashDigestLength(HashType::HASH_SHA256) == 32, "SHA256 length");
    TEST_ASSERT(HashDigestLength(HashType::HASH_SHA512) == 64, "SHA512 length");
    TEST_ASSERT(HashDigestLength(HashType::HASH_BLAKE2B) == 64, "BLAKE2B length");
    
    TEST_PASS("Hash Type Conversions");
}


// Test 7: Hash equality
bool TestHashEquality() {
    std::cout << "\n=== Test: Hash Equality ===\n";
    
    AFF4Hash hash1(HashType::HASH_SHA256, "test_digest");
    AFF4Hash hash2(HashType::HASH_SHA256, "test_digest");
    AFF4Hash hash3(HashType::HASH_SHA256, "different_digest");
    AFF4Hash hash4(HashType::HASH_MD5, "test_digest");
    
    TEST_ASSERT(hash1 == hash2, "Same hash should be equal");
    TEST_ASSERT(hash1 != hash3, "Different digest should not be equal");
    TEST_ASSERT(hash1 != hash4, "Different type should not be equal");
    
    TEST_PASS("Hash Equality");
}


// Test 8: Empty data hashing
bool TestEmptyDataHash() {
    std::cout << "\n=== Test: Empty Data Hash ===\n";
    
    MultiHasher hasher;
    hasher.AddHashType(HashType::HASH_MD5);
    hasher.AddHashType(HashType::HASH_SHA256);
    hasher.Init();
    
    // Hash empty data
    std::vector<AFF4Hash> results;
    hasher.Finalize(results);
    
    // Known empty string hashes
    // MD5("") = d41d8cd98f00b204e9800998ecf8427e
    // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    
    for (const auto& hash : results) {
        if (hash.type == HashType::HASH_MD5) {
            TEST_ASSERT(hash.HexDigest() == "d41d8cd98f00b204e9800998ecf8427e", "MD5 of empty");
        } else if (hash.type == HashType::HASH_SHA256) {
            TEST_ASSERT(hash.HexDigest() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256 of empty");
        }
    }
    
    TEST_PASS("Empty Data Hash");
}


// Test 9: Incremental hashing
bool TestIncrementalHashing() {
    std::cout << "\n=== Test: Incremental Hashing ===\n";
    
    std::string full_data = "The quick brown fox jumps over the lazy dog";
    
    // Hash in one shot
    MultiHasher hasher1;
    hasher1.AddHashType(HashType::HASH_SHA256);
    hasher1.Init();
    hasher1.Update(full_data.data(), full_data.size());
    std::vector<AFF4Hash> result1;
    hasher1.Finalize(result1);
    
    // Hash incrementally
    MultiHasher hasher2;
    hasher2.AddHashType(HashType::HASH_SHA256);
    hasher2.Init();
    for (size_t i = 0; i < full_data.size(); i++) {
        hasher2.Update(&full_data[i], 1);
    }
    std::vector<AFF4Hash> result2;
    hasher2.Finalize(result2);
    
    TEST_ASSERT(result1[0] == result2[0], "Incremental hash should match one-shot hash");
    std::cout << "  One-shot:     " << result1[0].HexDigest() << "\n";
    std::cout << "  Incremental:  " << result2[0].HexDigest() << "\n";
    
    TEST_PASS("Incremental Hashing");
}


// Run all tests
int RunAllTests(const std::string& vdisk_path) {
    std::cout << "===========================================\n";
    std::cout << "AFF4 Comprehensive Hash Test Suite\n";
    std::cout << "===========================================\n";
    
    TestMultiHasherBasic();
    TestAllHashTypes();
    TestHashTypeConversions();
    TestHashEquality();
    TestEmptyDataHash();
    TestIncrementalHashing();
    TestImageHashDuringWrite();
    TestHashVerification();
    TestLargeFileHashing(vdisk_path);
    
    std::cout << "\n===========================================\n";
    std::cout << "Results: " << tests_passed << " passed, " << tests_failed << " failed\n";
    std::cout << "===========================================\n";
    
    return tests_failed > 0 ? 1 : 0;
}

}  // namespace aff4


int main(int argc, char** argv) {
    std::string vdisk_path = "/home/unknown/Project/AFF4/cpp-aff4/cpp-aff4/vdisk.raw";
    
    if (argc > 1) {
        vdisk_path = argv[1];
    }
    
    return aff4::RunAllTests(vdisk_path);
}
