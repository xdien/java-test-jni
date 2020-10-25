cmake_minimum_required(VERSION 3.4.1)

# Specifies a library name, specifies whether the library is STATIC or
# SHARED, and provides relative paths to the source code. You can
# define multiple libraries by adding multiple add_library() commands,
# and CMake builds them for you. When you build your app, Gradle
# automatically packages shared libraries with your APK.

project(native-lib)
set (CMAKE_CXX_STANDARD 11)
add_library( # Specifies the name of the library.
             native-lib

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
#            src/main/cpp/security.cpp
        src/main/cpp/crypter.cpp
        src/main/cpp/base64.cpp
        )

include_directories(/home/xdien/workspace/Barcode-Reader/MyApplication2/app/libs/include)
add_library(crypto SHARED IMPORTED )
set_target_properties(crypto
        PROPERTIES IMPORTED_LOCATION
        ${PROJECT_SOURCE_DIR}/libs/${ANDROID_ABI}/libcrypto_1_1.so)

add_library(ssl SHARED IMPORTED )
set_target_properties(ssl
        PROPERTIES IMPORTED_LOCATION
        ${PROJECT_SOURCE_DIR}/libs/${ANDROID_ABI}/libssl_1_1.so)

find_library(zlib-lib z)
set_property(TARGET ssl APPEND PROPERTY INTERFACE_LINK_LIBRARIES ${zlib-lib})

#target_link_libraries( native-lib ssl crypto app-glue ${log-lib} )
target_link_libraries( native-lib ssl crypto ${log-lib} )
