find_package(OpenSSL REQUIRED)


SET(header_files  CryptoUtils.h
                  KeyUtils.h
                  KCVCalculator.h
                  VKey.h)

SET(SOURCES       CryptoUtils.cpp
                  KeyUtils.cpp
                  KCVCalculator.cpp
                  ${header_files})

source_group("Headers" FILES ${header_files})


INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})


ADD_EXECUTABLE(KCVCalculator ${SOURCES})


TARGET_LINK_LIBRARIES(KCVCalculator ${OPENSSL_LIBRARIES})


INSTALL(TARGETS KCVCalculator DESTINATION bin)
