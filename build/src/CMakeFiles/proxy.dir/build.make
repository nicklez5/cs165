# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.17

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /home/jackson/CLionProjects/untitled1/extern/cmake/bin/cmake

# The command to remove a file.
RM = /home/jackson/CLionProjects/untitled1/extern/cmake/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/jackson/CLionProjects/untitled1

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/jackson/CLionProjects/untitled1/build

# Include any dependencies generated for this target.
include src/CMakeFiles/proxy.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/proxy.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/proxy.dir/flags.make

src/CMakeFiles/proxy.dir/proxy/proxy.c.o: src/CMakeFiles/proxy.dir/flags.make
src/CMakeFiles/proxy.dir/proxy/proxy.c.o: ../src/proxy/proxy.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jackson/CLionProjects/untitled1/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/CMakeFiles/proxy.dir/proxy/proxy.c.o"
	cd /home/jackson/CLionProjects/untitled1/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/proxy.dir/proxy/proxy.c.o   -c /home/jackson/CLionProjects/untitled1/src/proxy/proxy.c

src/CMakeFiles/proxy.dir/proxy/proxy.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/proxy.dir/proxy/proxy.c.i"
	cd /home/jackson/CLionProjects/untitled1/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/jackson/CLionProjects/untitled1/src/proxy/proxy.c > CMakeFiles/proxy.dir/proxy/proxy.c.i

src/CMakeFiles/proxy.dir/proxy/proxy.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/proxy.dir/proxy/proxy.c.s"
	cd /home/jackson/CLionProjects/untitled1/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/jackson/CLionProjects/untitled1/src/proxy/proxy.c -o CMakeFiles/proxy.dir/proxy/proxy.c.s

src/CMakeFiles/proxy.dir/proxy/bloom.c.o: src/CMakeFiles/proxy.dir/flags.make
src/CMakeFiles/proxy.dir/proxy/bloom.c.o: ../src/proxy/bloom.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/jackson/CLionProjects/untitled1/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object src/CMakeFiles/proxy.dir/proxy/bloom.c.o"
	cd /home/jackson/CLionProjects/untitled1/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/proxy.dir/proxy/bloom.c.o   -c /home/jackson/CLionProjects/untitled1/src/proxy/bloom.c

src/CMakeFiles/proxy.dir/proxy/bloom.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/proxy.dir/proxy/bloom.c.i"
	cd /home/jackson/CLionProjects/untitled1/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/jackson/CLionProjects/untitled1/src/proxy/bloom.c > CMakeFiles/proxy.dir/proxy/bloom.c.i

src/CMakeFiles/proxy.dir/proxy/bloom.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/proxy.dir/proxy/bloom.c.s"
	cd /home/jackson/CLionProjects/untitled1/build/src && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/jackson/CLionProjects/untitled1/src/proxy/bloom.c -o CMakeFiles/proxy.dir/proxy/bloom.c.s

# Object files for target proxy
proxy_OBJECTS = \
"CMakeFiles/proxy.dir/proxy/proxy.c.o" \
"CMakeFiles/proxy.dir/proxy/bloom.c.o"

# External object files for target proxy
proxy_EXTERNAL_OBJECTS =

src/proxy: src/CMakeFiles/proxy.dir/proxy/proxy.c.o
src/proxy: src/CMakeFiles/proxy.dir/proxy/bloom.c.o
src/proxy: src/CMakeFiles/proxy.dir/build.make
src/proxy: ../extern/libressl_install/lib/libtls.so
src/proxy: ../extern/libressl_install/lib/libssl.so
src/proxy: ../extern/libressl_install/lib/libcrypto.so
src/proxy: src/CMakeFiles/proxy.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/jackson/CLionProjects/untitled1/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable proxy"
	cd /home/jackson/CLionProjects/untitled1/build/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/proxy.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/proxy.dir/build: src/proxy

.PHONY : src/CMakeFiles/proxy.dir/build

src/CMakeFiles/proxy.dir/clean:
	cd /home/jackson/CLionProjects/untitled1/build/src && $(CMAKE_COMMAND) -P CMakeFiles/proxy.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/proxy.dir/clean

src/CMakeFiles/proxy.dir/depend:
	cd /home/jackson/CLionProjects/untitled1/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jackson/CLionProjects/untitled1 /home/jackson/CLionProjects/untitled1/src /home/jackson/CLionProjects/untitled1/build /home/jackson/CLionProjects/untitled1/build/src /home/jackson/CLionProjects/untitled1/build/src/CMakeFiles/proxy.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/proxy.dir/depend

