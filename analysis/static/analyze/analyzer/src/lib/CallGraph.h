#ifndef _CALL_GRAPH_H
#define _CALL_GRAPH_H

#include "GlobalCtx.h"
#include "CallsiteAnalyzer.h"
#include "config.h"

typedef std::vector<std::pair<llvm::Function *, llvm::CallInst *>> CallGraphPath;
//typedef std::vector<std::pair<llvm::Value *, llvm::Value *>> targetNode;

class CallGraphPass : public IterativeModulePass {

private:
  llvm::Function *getFuncDef(llvm::Function *F);
  bool runOnFunction(llvm::Function *);
  void processInitializers(llvm::Module *, llvm::Constant *,
                           llvm::GlobalValue *, std::string);
  bool findCallees(llvm::CallInst *, FuncSet &);
  bool isCompatibleType(llvm::Type *T1, llvm::Type *T2);
  bool findCalleesByType(llvm::CallInst *, FuncSet &);
  bool mergeFuncSet(FuncSet &S, const std::string &Id, bool InsertEmpty);
  bool mergeFuncSet(std::string &Id, const FuncSet &S, bool InsertEmpty);
  bool mergeFuncSet(FuncSet &Dst, const FuncSet &Src);
  bool findFunctions(llvm::Value *, FuncSet &);
  bool findFunctions(llvm::Value *, FuncSet &,
                     llvm::SmallPtrSet<llvm::Value *, 4>);
  bool ifReachable(llvm::Value *, llvm::CallInst *);
  bool filterBacktraceracePaths(llvm::Function *);
  //bool analyzeFunctions(llvm::)

public:
  CallGraphPass(GlobalContext *Ctx_) : IterativeModulePass(Ctx_, "CallGraph") {}
  
  virtual bool doInitialization(llvm::Module *);
  
  virtual bool doFinalization(llvm::Module *);
  virtual bool doModulePass(llvm::Module *);

  
  // debug
  void dumpFuncPtrs();
  void dumpCallees(std::string targetFuncName);
  void dumpCallers();
  unsigned int getLineNumber(Instruction* I);
    
  bool equals(const llvm::Type *left, const llvm::Type *right);
  void backtraceRootInterface(std::string rootInterface, CallGraphPath &callGraphPath);
  std::set<llvm::Function*> findRootInterfaceUpper(std::string rootInterface, CallGraphPath &callGraphPath, std::string subsystem);
  void backtraceRootInterfaceShallow(std::string rootInterface, CallGraphPath &callGraphPath);
  void crossAnalyze(std::string A, std::string B, CallsiteAnalyzer *); 
  void zerocopyAnalyze(std::string function, std::set<Function *> *mmapRefList, CallsiteAnalyzer *); 
};

#endif
