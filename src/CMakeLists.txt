add_executable(main main.cpp)

target_include_directories(main PRIVATE ${CMAKE_SOURCE_DIR}/src/syslog ${CMAKE_SOURCE_DIR}/3rdParty/openssl/include)

add_definitions(-DOPENSSL_USE_STATIC_LIBS)
target_link_libraries(main syslog ${CMAKE_SOURCE_DIR}/3rdParty/openssl/lib/libssl.lib ${CMAKE_SOURCE_DIR}/3rdParty/openssl/lib/libcrypto.lib)

# 