set(LLVM_LINK_COMPONENTS core support)

#add_definitions(${LLVM_DEFINITIONS})
#include_directories(${LLVM_INCLUDE_DIRS})

add_llvm_library(clang-sa MODULE
	clang-sa.cpp
	)

