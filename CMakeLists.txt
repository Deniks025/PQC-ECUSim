cmake_minimum_required(VERSION 3.10)
project(pqc-ecusim)

set(CMAKE_CXX_STANDARD 17)
set(PROJECT_INCLUDES ${PROJECT_SOURCE_DIR}/include)
set(LIB_DIR ${PROJECT_SOURCE_DIR}/lib)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

include_directories(${PROJECT_INCLUDES})
link_directories(${LIB_DIR})
find_package(OpenSSL REQUIRED)

add_executable(pqc-ecusim main.cpp)
add_executable(clusterA src/cluster_manager_A.cpp)
add_executable(clusterB src/cluster_manager_B.cpp)
add_executable(rpm src/rpm.cpp)
add_executable(spd src/spd.cpp)
add_executable(motor src/motor.cpp)
add_executable(trm src/auto_trm.cpp)
add_executable(candump src/candump.cpp)


target_link_libraries(pqc-ecusim PRIVATE SilKit oqs OpenSSL::Crypto ncurses pthread)
target_link_libraries(clusterA PRIVATE SilKit oqs OpenSSL::Crypto ncurses pthread)
target_link_libraries(clusterB PRIVATE SilKit oqs OpenSSL::Crypto ncurses pthread)
target_link_libraries(rpm PRIVATE SilKit oqs OpenSSL::Crypto ncurses pthread)
target_link_libraries(spd PRIVATE SilKit oqs OpenSSL::Crypto ncurses pthread)
target_link_libraries(motor PRIVATE SilKit oqs OpenSSL::Crypto ncurses pthread)
target_link_libraries(trm PRIVATE SilKit oqs OpenSSL::Crypto ncurses pthread)
target_link_libraries(candump PRIVATE SilKit oqs OpenSSL::Crypto)

