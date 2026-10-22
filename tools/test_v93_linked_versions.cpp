#include "../cryptopp/cryptlib.h"
#include "../zlib/zlib.h"
#include "../libpng/png.h"
#include "../id3lib/include/id3/globals.h"
#include <cstdio>
#include <cstring>
#include <vector>
// Version API ABI is independent of the mbedTLS structure layouts. Query the
// linked binary directly; never interpret a header macro as binary evidence.
extern "C" const char* mbedtls_version_get_string(void);
int main() {
    const auto crypto=CryptoPP::LibraryVersion();
    const auto z=zlibVersion();
    const auto png=png_get_libpng_ver(nullptr);
    const auto tls=mbedtls_version_get_string();
    png_image image{}; image.version=PNG_IMAGE_VERSION;
    image.width=1; image.height=1; image.format=PNG_FORMAT_RGBA;
    const unsigned char pixel[]={23,87,161,255};
    png_alloc_size_t length=0;
    if(!png_image_write_to_memory(&image,nullptr,&length,0,pixel,0,nullptr) || !length || length>4096) return 2;
    std::vector<unsigned char> encoded(static_cast<std::size_t>(length));
    if(!png_image_write_to_memory(&image,encoded.data(),&length,0,pixel,0,nullptr)) return 3;
    png_image decoded{}; decoded.version=PNG_IMAGE_VERSION;
    if(!png_image_begin_read_from_memory(&decoded,encoded.data(),length)) return 4;
    decoded.format=PNG_FORMAT_RGBA;
    unsigned char actual[4]{};
    const bool roundtrip=decoded.width==1 && decoded.height==1 &&
        png_image_finish_read(&decoded,nullptr,actual,0,nullptr)!=0;
    png_image_free(&decoded);
    if(!roundtrip || std::memcmp(actual,pixel,sizeof(pixel))) return 5;
    std::printf("{\"cryptopp\":%d,\"zlib\":\"%s\",\"libpng\":\"%s\",\"mbedtls\":\"%s\",\"id3lib\":\"%d.%d.%d\"}\n",
        crypto,z,png,tls,ID3LIB_MAJOR_VERSION,ID3LIB_MINOR_VERSION,ID3LIB_PATCH_VERSION);
    return crypto!=CRYPTOPP_VERSION || std::strcmp(z,ZLIB_VERSION) ||
        std::strcmp(png,PNG_LIBPNG_VER_STRING) || std::strcmp(tls,"4.0.0") ||
        ID3LIB_MAJOR_VERSION!=3 || ID3LIB_MINOR_VERSION!=9 || ID3LIB_PATCH_VERSION!=0;
}
