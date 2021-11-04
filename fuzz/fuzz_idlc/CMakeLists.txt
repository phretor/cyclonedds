#
# Copyright(c) 2021 ADLINK Technology Limited and others
#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License v. 2.0 which is available at
# http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
# v. 1.0 which is available at
# http://www.eclipse.org/org/documents/edl-v10.php.
#
# SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
#

include(CheckIncludeFile)

check_include_file(getopt.h HAVE_GETOPT_H)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../../src/tools/idlc/src/config.h.in config.h)

set(headers
 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/tools/idlc/src/descriptor.h
 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/tools/idlc/src/generator.h
 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/tools/idlc/src/options.h
 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/tools/idlc/src/plugin.h
 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/tools/idlc/include/idlc/generator.h
 ${CMAKE_CURRENT_BINARY_DIR}/config.h)
set(sources
 fuzz_idlc.c
 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/tools/idlc/src/plugin.c
 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/tools/idlc/src/options.c
 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/tools/idlc/src/generator.c
 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/tools/idlc/src/descriptor.c
 ${CMAKE_CURRENT_SOURCE_DIR}/../../src/tools/idlc/src/types.c)

add_executable(fuzz_idlc ${sources} ${headers})

target_link_libraries(fuzz_idlc PRIVATE idl idlpp ${CMAKE_DL_LIBS} $ENV{LIB_FUZZING_ENGINE})
target_include_directories(
  fuzz_idlc PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../src/tools/idlc/src>"
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../src/tools/idlc/include>"
    $<BUILD_INTERFACE:$<TARGET_PROPERTY:ddsc,INTERFACE_INCLUDE_DIRECTORIES>>)

# add_executable(${PROJECT_NAME}::idlc ALIAS idlc)

install(
  DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../../src/tools/idlc/include/idlc"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  COMPONENT dev
  FILES_MATCHING PATTERN "*.h")

# install(
#   TARGETS fuzz_idlc
#   EXPORT "${CMAKE_PROJECT_NAME}"
#   DESTINATION "${CMAKE_INSTALL_BINDIR}"
#   COMPONENT dev)

install(
  FILES "${CMAKE_SOURCE_DIR}/cmake/Modules/Generate.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}/idlc"
  COMPONENT dev)

include("${CMAKE_SOURCE_DIR}/cmake/Modules/Generate.cmake")

