#ifndef _COMMON_H
#define _COMMON_H

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/raw_ostream.h>

#include <bitset>
#include <chrono>
#include <unistd.h>

using namespace llvm;

extern cl::list<std::string> InputFilenames;
extern cl::opt<unsigned> VerboseLevel;


#endif
