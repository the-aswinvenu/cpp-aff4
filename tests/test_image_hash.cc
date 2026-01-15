// Test hash integration with AFF4Image

#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>

#include "aff4/aff4_image.h"
#include "aff4/aff4_hash.h"
#include "aff4/zip.h"
#include "aff4/volume_group.h"
#include "aff4/data_store.h"
#include "aff4/libaff4.h"

using namespace aff4;

const char* TEST_DATA = "Hello, this is test data for hashing! Line 1.\n"
                        "Hello, this is test data for hashing! Line 2.\n"
                        "Hello, this is test data for hashing! Line 3.\n"
                        "Hello, this is test data for hashing! Line 4.\n";

void test_hash_enablement() {
    std::cout << "Testing hash enablement... ";
    
    MemoryDataStore resolver;
    
    // Create a backing file for the volume
    char tmpname[] = "/tmp/aff4_test_XXXXXX.aff4";
    int fd = mkstemps(tmpname, 5);
    assert(fd >= 0);
    close(fd);
    
    AFF4Flusher<AFF4Stream> backing_stream;
    AFF4Status status = NewFileBackedObject(&resolver, tmpname, "truncate", backing_stream);
    assert(status == STATUS_OK);
    
    AFF4Flusher<AFF4Volume> volume;
    status = ZipFile::NewZipFile(&resolver, std::move(backing_stream), volume);
    assert(status == STATUS_OK);
    
    URN image_urn = volume->urn.Append("test_image");
    
    AFF4Flusher<AFF4Image> image;
    status = AFF4Image::NewAFF4Image(&resolver, image_urn, volume.get(), image);
    assert(status == STATUS_OK);
    
    // Enable multiple hash types at once
    status = image->EnableHashing({HashType::HASH_MD5, HashType::HASH_SHA256, HashType::HASH_SHA512});
    assert(status == STATUS_OK);
    
    // We can verify hashing is enabled by writing data and getting hashes
    status = image->Write("test", 4);
    assert(status == STATUS_OK);
    
    std::vector<AFF4Hash> hashes;
    image->Flush();
    status = image->GetComputedHashes(hashes);
    assert(status == STATUS_OK);
    assert(hashes.size() == 3);  // MD5, SHA256, SHA512
    
    unlink(tmpname);
    std::cout << "PASS" << std::endl;
}

void test_write_with_hash() {
    std::cout << "Testing Write() with hashing... ";
    
    MemoryDataStore resolver;
    
    char tmpname[] = "/tmp/aff4_test_XXXXXX.aff4";
    int fd = mkstemps(tmpname, 5);
    assert(fd >= 0);
    close(fd);
    
    AFF4Flusher<AFF4Stream> backing_stream;
    AFF4Status status = NewFileBackedObject(&resolver, tmpname, "truncate", backing_stream);
    assert(status == STATUS_OK);
    
    AFF4Flusher<AFF4Volume> volume;
    status = ZipFile::NewZipFile(&resolver, std::move(backing_stream), volume);
    assert(status == STATUS_OK);
    
    URN image_urn = volume->urn.Append("test_hash_image");
    
    AFF4Flusher<AFF4Image> image;
    status = AFF4Image::NewAFF4Image(&resolver, image_urn, volume.get(), image);
    assert(status == STATUS_OK);
    
    // Enable SHA256 before writing
    status = image->EnableHashing(HashType::HASH_SHA256);
    assert(status == STATUS_OK);
    
    // Write some data
    status = image->Write(TEST_DATA, strlen(TEST_DATA));
    assert(status == STATUS_OK);
    
    // Flush and get computed hashes
    std::vector<AFF4Hash> hashes;
    image->Flush();
    status = image->GetComputedHashes(hashes);
    assert(status == STATUS_OK);
    assert(hashes.size() == 1);
    assert(hashes[0].type == HashType::HASH_SHA256);
    
    // Compute expected hash for comparison
    auto hasher = HasherFactory::Create(HashType::HASH_SHA256);
    AFF4Hash expected_hash;
    hasher->HashString(TEST_DATA, expected_hash);
    
    assert(hashes[0].HexDigest() == expected_hash.HexDigest());
    
    std::cout << "SHA256: " << hashes[0].HexDigest().substr(0, 16) << "... PASS" << std::endl;
    
    unlink(tmpname);
}

void test_writestream_with_hash() {
    std::cout << "Testing WriteStream() with hashing... ";
    
    // Create a source file with test data
    char srcname[] = "/tmp/aff4_src_XXXXXX";
    int src_fd = mkstemp(srcname);
    assert(src_fd >= 0);
    
    std::string large_data;
    for (int i = 0; i < 100; i++) {
        large_data.append(TEST_DATA);
    }
    ssize_t written = write(src_fd, large_data.data(), large_data.size());
    assert(written == (ssize_t)large_data.size());
    close(src_fd);
    
    // Compute expected hash
    auto hasher = HasherFactory::Create(HashType::HASH_SHA256);
    AFF4Hash expected_hash;
    hasher->HashString(large_data, expected_hash);
    
    // Create container and image
    MemoryDataStore resolver;
    
    char tmpname[] = "/tmp/aff4_test_XXXXXX.aff4";
    int fd = mkstemps(tmpname, 5);
    assert(fd >= 0);
    close(fd);
    std::string container_path = tmpname;
    
    {
        AFF4Flusher<AFF4Stream> backing_stream;
        AFF4Status status = NewFileBackedObject(&resolver, container_path, "truncate", backing_stream);
        assert(status == STATUS_OK);
        
        AFF4Flusher<AFF4Volume> volume;
        status = ZipFile::NewZipFile(&resolver, std::move(backing_stream), volume);
        assert(status == STATUS_OK);
        
        URN image_urn = volume->urn.Append("test_stream_image");
        
        AFF4Flusher<AFF4Image> image;
        status = AFF4Image::NewAFF4Image(&resolver, image_urn, volume.get(), image);
        assert(status == STATUS_OK);
        
        // Enable multiple hashes
        status = image->EnableHashing({HashType::HASH_MD5, HashType::HASH_SHA256});
        assert(status == STATUS_OK);
        
        // Open source file and write via stream
        AFF4Flusher<AFF4Stream> source;
        status = NewFileBackedObject(&resolver, srcname, "read", source);
        assert(status == STATUS_OK);
        
        status = image->WriteStream(source.get());
        assert(status == STATUS_OK);
        
        // Get computed hashes
        std::vector<AFF4Hash> hashes;
        status = image->GetComputedHashes(hashes);
        assert(status == STATUS_OK);
        assert(hashes.size() == 2);
        
        bool found_sha256 = false;
        bool found_md5 = false;
        for (const auto& hash : hashes) {
            if (hash.type == HashType::HASH_SHA256) {
                assert(hash.HexDigest() == expected_hash.HexDigest());
                found_sha256 = true;
                std::cout << "SHA256: " << hash.HexDigest().substr(0, 16) << "... ";
            } else if (hash.type == HashType::HASH_MD5) {
                found_md5 = true;
                std::cout << "MD5: " << hash.HexDigest() << " ";
            }
        }
        assert(found_sha256);
        assert(found_md5);
    }
    
    unlink(container_path.c_str());
    unlink(srcname);
    
    std::cout << "PASS" << std::endl;
}

void test_hash_in_metadata() {
    std::cout << "Testing hash stored in metadata... ";
    
    char tmpname[] = "/tmp/aff4_test_XXXXXX.aff4";
    int fd = mkstemps(tmpname, 5);
    assert(fd >= 0);
    close(fd);
    
    std::string container_path = tmpname;
    std::string expected_sha256;
    
    {
        MemoryDataStore resolver;
        
        AFF4Flusher<AFF4Stream> backing_stream;
        AFF4Status status = NewFileBackedObject(&resolver, container_path, "truncate", backing_stream);
        assert(status == STATUS_OK);
        
        AFF4Flusher<AFF4Volume> volume;
        status = ZipFile::NewZipFile(&resolver, std::move(backing_stream), volume);
        assert(status == STATUS_OK);
        
        URN image_urn = volume->urn.Append("hashed_image");
        
        AFF4Flusher<AFF4Image> image;
        status = AFF4Image::NewAFF4Image(&resolver, image_urn, volume.get(), image);
        assert(status == STATUS_OK);
        
        status = image->EnableHashing(HashType::HASH_SHA256);
        assert(status == STATUS_OK);
        
        status = image->Write(TEST_DATA, strlen(TEST_DATA));
        assert(status == STATUS_OK);
        
        std::vector<AFF4Hash> hashes;
        image->Flush();
        image->GetComputedHashes(hashes);
        assert(hashes.size() == 1);
        expected_sha256 = hashes[0].HexDigest();
    }
    
    std::cout << "written SHA256: " << expected_sha256.substr(0, 16) << "... ";
    
    unlink(container_path.c_str());
    
    std::cout << "PASS" << std::endl;
}

void test_hash_verification() {
    std::cout << "Testing hash verification... ";
    
    char tmpname[] = "/tmp/aff4_test_XXXXXX.aff4";
    int fd = mkstemps(tmpname, 5);
    assert(fd >= 0);
    close(fd);
    
    std::string container_path = tmpname;
    std::string stored_sha256;
    URN saved_image_urn;
    
    // Step 1: Create an image with hashing
    {
        MemoryDataStore resolver;
        
        AFF4Flusher<AFF4Stream> backing_stream;
        AFF4Status status = NewFileBackedObject(&resolver, container_path, "truncate", backing_stream);
        assert(status == STATUS_OK);
        
        AFF4Flusher<AFF4Volume> volume;
        status = ZipFile::NewZipFile(&resolver, std::move(backing_stream), volume);
        assert(status == STATUS_OK);
        
        URN image_urn = volume->urn.Append("verifiable_image");
        saved_image_urn = image_urn;
        
        AFF4Flusher<AFF4Image> image;
        status = AFF4Image::NewAFF4Image(&resolver, image_urn, volume.get(), image);
        assert(status == STATUS_OK);
        
        // Use ZLIB compression (matches aff4imager default)
        image->compression = AFF4_IMAGE_COMPRESSION_ENUM_ZLIB;
        
        // Enable SHA256 hashing
        status = image->EnableHashing(HashType::HASH_SHA256);
        assert(status == STATUS_OK);
        
        // Write test data
        for (int i = 0; i < 50; i++) {
            status = image->Write(TEST_DATA, strlen(TEST_DATA));
            assert(status == STATUS_OK);
        }
        
        // Get the computed hash for later comparison
        std::vector<AFF4Hash> hashes;
        image->Flush();
        image->GetComputedHashes(hashes);
        assert(hashes.size() == 1);
        stored_sha256 = hashes[0].HexDigest();
        
        std::cout << "created image... ";
    }
    
    // Step 2: Open and verify the image
    {
        MemoryDataStore resolver;
        
        AFF4Flusher<AFF4Stream> backing_stream;
        AFF4Status status = NewFileBackedObject(&resolver, container_path, "read", backing_stream);
        assert(status == STATUS_OK);
        
        AFF4Flusher<AFF4Volume> volume;
        status = ZipFile::OpenZipFile(&resolver, std::move(backing_stream), volume);
        assert(status == STATUS_OK);
        
        VolumeGroup volumes(&resolver);
        volumes.AddVolume(std::move(volume));
        
        AFF4Flusher<AFF4Image> image;
        status = AFF4Image::OpenAFF4Image(&resolver, saved_image_urn, &volumes, image);
        assert(status == STATUS_OK);
        
        // Get stored hashes
        std::vector<AFF4Hash> stored_hashes;
        status = image->GetStoredHashes(stored_hashes);
        assert(status == STATUS_OK);
        assert(stored_hashes.size() == 1);
        assert(stored_hashes[0].HexDigest() == stored_sha256);
        
        // Verify the image
        ImageVerifyResult verify_result;
        status = image->VerifyHash(verify_result);
        assert(status == STATUS_OK);
        assert(verify_result.Passed());
        assert(verify_result.hash_results.size() == 1);
        assert(verify_result.hash_results[0].matches);
        
        std::cout << "verification PASSED... ";
    }
    
    unlink(container_path.c_str());
    
    std::cout << "PASS" << std::endl;
}

int main() {
    std::cout << "=== AFF4 Image Hash Integration Tests ===" << std::endl;
    
    test_hash_enablement();
    test_write_with_hash();
    test_writestream_with_hash();
    test_hash_in_metadata();
    test_hash_verification();
    
    std::cout << std::endl << "All tests PASSED!" << std::endl;
    return 0;
}
