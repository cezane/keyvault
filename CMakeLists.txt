project (keyvault C)

set (SRC host/main.c)

add_executable (${PROJECT_NAME} ${SRC})

include_directories (${CRYPTO_DIR})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include)

target_link_libraries (${PROJECT_NAME} PRIVATE teec PRIVATE crypto)

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
