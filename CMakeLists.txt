cmake_minimum_required(VERSION 3.20)
project(NetScope VERSION 1.0.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_library(netscope_core src/parser.cpp src/pcap.cpp src/flow.cpp src/filter.cpp src/analytics.cpp src/indexed_pcap.cpp src/conversation.cpp)
target_include_directories(netscope_core PUBLIC include)
if(MSVC)
  target_compile_options(netscope_core PRIVATE /W4)
else()
  target_compile_options(netscope_core PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_executable(netscope src/main.cpp)
target_link_libraries(netscope PRIVATE netscope_core)
include(CTest)
if(BUILD_TESTING)
  add_executable(netscope_tests tests/test_parser.cpp)
  target_link_libraries(netscope_tests PRIVATE netscope_core)
  add_test(NAME parser_tests COMMAND netscope_tests)
  add_executable(netscope_flow_tests tests/test_flow.cpp)
  target_link_libraries(netscope_flow_tests PRIVATE netscope_core)
  add_test(NAME flow_tests COMMAND netscope_flow_tests)
  add_executable(netscope_filter_tests tests/test_filter.cpp)
  target_link_libraries(netscope_filter_tests PRIVATE netscope_core)
  add_test(NAME filter_tests COMMAND netscope_filter_tests)
  add_executable(netscope_analytics_tests tests/test_analytics.cpp)
  target_link_libraries(netscope_analytics_tests PRIVATE netscope_core)
  add_test(NAME analytics_tests COMMAND netscope_analytics_tests "${CMAKE_CURRENT_SOURCE_DIR}/showcase.pcap")
  add_executable(netscope_index_tests tests/test_indexed_pcap.cpp)
  target_link_libraries(netscope_index_tests PRIVATE netscope_core)
  add_test(NAME indexed_pcap_tests COMMAND netscope_index_tests "${CMAKE_CURRENT_SOURCE_DIR}/showcase.pcap")
  add_executable(netscope_performance_tests tests/test_performance.cpp)
  target_link_libraries(netscope_performance_tests PRIVATE netscope_core)
  add_test(NAME performance_tests COMMAND netscope_performance_tests "${CMAKE_CURRENT_SOURCE_DIR}/showcase.pcap")
  add_executable(netscope_conversation_tests tests/test_conversation.cpp)
  target_link_libraries(netscope_conversation_tests PRIVATE netscope_core)
  add_test(NAME conversation_tests COMMAND netscope_conversation_tests)
endif()
option(NETSCOPE_BUILD_GUI "Build Qt 6 desktop GUI when Qt is available" ON)
if(NETSCOPE_BUILD_GUI)
  find_package(Qt6 COMPONENTS Widgets REQUIRED)
  if(Qt6_FOUND)
    add_executable(netscope-gui WIN32 gui/main.cpp gui/mainwindow.cpp gui/mainwindow.hpp gui/packetmodel.cpp gui/packetmodel.hpp gui/capture.hpp)
    target_link_libraries(netscope-gui PRIVATE netscope_core Qt6::Widgets)
    message(STATUS "Qt6 Widgets found: building netscope-gui")
  else()
    message(STATUS "Qt6 Widgets not found: building CLI only (set CMAKE_PREFIX_PATH for Qt)")
  endif()
endif()

# Reproducible Windows portable distribution (Qt + recursive MSYS2 dependency closure).
option(NETSCOPE_PACKAGE_WINDOWS "Add Windows portable distribution target" OFF)
if(WIN32 AND NETSCOPE_PACKAGE_WINDOWS AND TARGET netscope-gui)
  find_program(WINDEPLOYQT_EXECUTABLE NAMES windeployqt windeployqt6
    HINTS "${Qt6_DIR}/../../../bin")
  if(NOT WINDEPLOYQT_EXECUTABLE)
    message(FATAL_ERROR "windeployqt not found; set CMAKE_PREFIX_PATH to MSYS2 UCRT64")
  endif()
  get_filename_component(NETSCOPE_TOOLCHAIN_BIN "${WINDEPLOYQT_EXECUTABLE}" DIRECTORY)
  find_program(NETSCOPE_POWERSHELL NAMES powershell.exe powershell REQUIRED)
  add_custom_target(package-windows
    COMMAND "${NETSCOPE_POWERSHELL}" -NoProfile -ExecutionPolicy Bypass
      -File "${CMAKE_CURRENT_SOURCE_DIR}/packaging/package-windows.ps1"
      -GuiExe "$<TARGET_FILE:netscope-gui>"
      -CliExe "$<TARGET_FILE:netscope>"
      -OutputDir "${CMAKE_BINARY_DIR}/NetScope-portable"
      -ToolchainBin "${NETSCOPE_TOOLCHAIN_BIN}"
      -Windeployqt "${WINDEPLOYQT_EXECUTABLE}"
      -SampleCapture "${CMAKE_CURRENT_SOURCE_DIR}/showcase.pcap"
      -ReadmeFile "${CMAKE_CURRENT_SOURCE_DIR}/README.md"
      -CreateZip
    DEPENDS netscope-gui netscope
    COMMENT "Clean portable package, recursive DLL dependency closure and ZIP"
    VERBATIM)
endif()
