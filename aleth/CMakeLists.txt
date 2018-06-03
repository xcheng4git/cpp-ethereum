set(
    sources
    AccountManager.cpp AccountManager.h
    main.cpp
    MinerAux.h
)

add_executable(aleth ${sources})
target_link_libraries(
    aleth
    PRIVATE ethereum ethashseal evm web3jsonrpc webthree devcore utils Boost::program_options ${CURL_LIBRARY} ${MHD_LIBRARY} 
    /usr/lib/x86_64-linux-gnu/libjsonrpccpp-common.so
    /usr/lib/x86_64-linux-gnu/libjsonrpccpp-client.so
    /usr/lib/x86_64-linux-gnu/libjsonrpccpp-server.so
)

target_include_directories(aleth PRIVATE ../utils)

if(MINIUPNPC)
    target_compile_definitions(aleth PRIVATE ETH_MINIUPNPC)
endif()

install(TARGETS aleth DESTINATION bin)
