#ifndef _CALL_CSA_H
#define _CALL_CSA_H


#include <llvm/ADT/iterator_range.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/DebugLoc.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Support/raw_ostream.h>

#include <map>
#include <set>
#include <unordered_map>
#include <vector>


#include "Common.h"
#include "GlobalCtx.h"
//#include "CallGraph.h"
using namespace llvm;
//using namespace std;
//typedef std::vector<std::pair<llvm::Value *, llvm::Value *>> targetNode;
typedef std::vector<std::pair<llvm::Function *, llvm::CallInst *>> CallGraphPath;
class CallsiteInfo {
private:

public:
};


//#endif

class CallsiteAnalyzer{
private:

public:
    std::vector<std::pair<llvm::Module *, llvm::StringRef>> global_modules;
    FuncMap Funcs;
    //CallsiteAnalyzer() {}
    void run(llvm::Module *M, const llvm::DataLayout *layout);
    void collectStructInfo(llvm::Module *M, std::set<Function *> *);
    void dataflowBackwardTraceControlStruct(Value *v, std::set<llvm::Value* > *, std::vector<llvm::Value *> *, std::vector<llvm::Value *> *);
    void dataflowForwardTraceControlStruct(Value *v, std::set<llvm::Value* > *, std::set<llvm::StoreInst *> *, std::vector<llvm::Value *> *);
    
    void dataflowCrossTraceControlStruct(Value *alloc, Value *copy, std::set<llvm::Value* > *, std::vector<llvm::Value *> *, std::vector<llvm::Value *> *, 
	    CallGraphPath *allocPath, CallGraphPath *copyPath);
    
    bool structContainsStruct(llvm::StructType* outerStruct, llvm::StructType* innerStruct);
    bool hasLowerDirectPageAllocCall(llvm::CallInst* callInst, const std::string& subsystem, CallerMap &Callers, std::set<llvm::Value *> visited);
    bool isFunctionBodyEmpty(llvm::Function* F);
    llvm::Instruction* findStructPointerForward(llvm::Instruction* currentInst);
    llvm::StructType* fixStructType(llvm::StructType* structType, llvm::Value* toFixValue);
    llvm::Value* findRemapControlStructureBackward(llvm::Value* startingPointi, std::string subsystem);
    llvm::Value* findAllocationControlStructureForward(llvm::Function* targetFunction, const std::string& subsystem,  CallerMap &callerMap);
    llvm::Value* dataflowCrossTraceAllocationControlStruct(Value *alloc, std::set<llvm::Value *> *, std::vector<llvm::Value *>*, std::vector<llvm::Value *>*, CallGraphPath *);
    llvm::Value* dataflowCrossTraceCopyWriteControlStruct(Value *copy, std::set<llvm::Value *> *, std::vector<llvm::Value *>*, std::vector<llvm::Value *>*, CallGraphPath *);
    llvm::Value *dataflowTraceNestedAllocation(Value *allocUse, CallInst *);
    llvm::Value *dataflowTraceNestedCopyWrite(Value *, CallInst *);
    llvm::CallInst *searchFromPath(CallGraphPath *, CallInst *);
    llvm::Type *getApiType(CallInst *);
    bool isCall2Alloc(CallInst *CI);
    bool isCall2Copy(CallInst *CI);
    llvm::Value *getOffset(llvm::GetElementPtrInst *GEP);

    //void dumpMmapRef(GlobalContext *);
//    void crossAnalyze(CallGraphPass &CGPass,std::string A, std::string B); 
    //void printCallsiteInfo() const;
};

#endif 
