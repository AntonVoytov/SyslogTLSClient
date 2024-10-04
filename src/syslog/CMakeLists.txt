add_library(syslog syslog.cpp syslog.hpp)

target_include_directories(syslog PRIVATE ${CMAKE_SOURCE_DIR}/3rdParty/openssl/include)
target_include_directories(syslog PUBLIC include)

add_definitions(-DOPENSSL_USE_STATIC_LIBS)
target_link_libraries(syslog ${CMAKE_SOURCE_DIR}/3rdParty/openssl/lib/libssl.lib ${CMAKE_SOURCE_DIR}/3rdParty/openssl/lib/libcrypto.lib)
