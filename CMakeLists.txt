cmake_minimum_required(VERSION 3.21)

project(Carventory VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

qt_add_executable(Carventory
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
)

target_link_libraries(Carventory PRIVATE Qt6::Widgets)
target_link_libraries(Carventory PRIVATE
    Qt6::Widgets
    OpenSSL::Crypto
)
install(TARGETS Carventory
    RUNTIME DESTINATION bin
)
