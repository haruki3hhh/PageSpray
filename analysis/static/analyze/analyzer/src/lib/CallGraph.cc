#include <llvm/ADT/StringExtras.h>
#include <llvm/Analysis/CallGraph.h>
//#include <llvm/IR/CallSite.h>
#include <llvm/IR/AbstractCallSite.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>
#include <llvm/Support/Debug.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/Transforms/Utils/FunctionComparator.h>
#include <string.h>
#include <string>
#include <cstring>
#include "Annotation.h"
#include "CallGraph.h"
#include "CallsiteAnalyzer.h"
#include <vector>
#include <queue>

using namespace llvm;

std::vector<std::string> needToBeFiltered = {
    "__ubsan_handle_type_mismatch_v1",
    "ERR_PTR",
    "__ubsan_handle_load_invalid_value",
    "IS_ERR",
    "__ubsan_handle_type_mismatch_v1",
    "__ubsan_handle_out_of_bounds",
    "printk",
    "__kcsan_disable_current",
    "__kcsan_enable_current",
    "__ubsan_handle_out_of_bounds",
    "llvm.dbg.value",
    "kcsan_check_access",
    "kasan_check_write",
    "llvm.lifetime.start.p0i8",
    "llvm.lifetime.end.p0i8",
    "kasan_check_read",
    "memset",
    "__check_object_size",
    "get_current",
    "llvm.read_register.i64",
    "refcount_read",
    "__raw_spin_unlock",
    "PTR_ERR",
    "__ubsan_handle_shift_out_of_bounds",
    "strlen"
};

bool CallGraphPass::doInitialization(Module *M) {

  outs() << "[+] Initializing " << M->getModuleIdentifier() << "\n";
  // collect function pointer assignments in global initializers
  for (GlobalVariable &G : M->globals()) {
    if (G.hasInitializer())
      processInitializers(M, G.getInitializer(), &G, "");
  }

  for (Function &F : *M) {
    // Lewis: we don't give a shit to functions in .init.text
    if (F.hasSection() && F.getSection().str() == ".init.text")
      continue;
    // collect address-taken functions
    if (F.hasAddressTaken())
      Ctx->AddressTakenFuncs.insert(&F);
  }

  return false;
}

bool CallGraphPass::doFinalization(Module *M) {

 //outs()<<" CallGraphPass::doFinalization() ->"<<M->getName()<<"\n";
    // update callee and caller mapping
  for (Function &F : *M) {
    for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; ++i) {
      // map callsite to possible callees
      if (CallInst *CI = dyn_cast<CallInst>(&*i)) {
        FuncSet &FS = Ctx->Callees[CI];
        // calculate the caller info here
        for (Function *CF : FS) {
          CallInstSet &CIS = Ctx->Callers[CF];
          CIS.insert(CI);
        }
      }
    }
  }

  return false;
}


void CallGraphPass::processInitializers(Module *M, Constant *C, GlobalValue *V,
                                        std::string Id) {
  // structs
  if (ConstantStruct *CS = dyn_cast<ConstantStruct>(C)) {
    StructType *STy = CS->getType();

    if (!STy->hasName() && Id.empty()) {
      if (V != nullptr)
        Id = getVarId(V);
      else
        Id = "bullshit"; // Lewis: quick fix for V is nullptr
    }

    for (unsigned i = 0; i != STy->getNumElements(); ++i) {
      Type *ETy = STy->getElementType(i);
      if (ETy->isStructTy()) {
        std::string new_id;
        if (Id.empty())
        {
          outs()<<STy->getStructName().str()<<"\n";
          new_id = STy->getStructName().str() + "," + std::to_string(i);
        }
        else
          new_id = Id + "," + std::to_string(i);
        processInitializers(M, CS->getOperand(i), NULL, new_id);
      } else if (ETy->isArrayTy()) {
        // nested array of struct
        processInitializers(M, CS->getOperand(i), NULL, "");
      } else if (isFunctionPointer(ETy)) {
        // found function pointers in struct fields
        if (Function *F = dyn_cast<Function>(CS->getOperand(i))) {
          std::string new_id;
          if (!STy->isLiteral()) {
            if (STy->getStructName().startswith("struct.anon.") ||
                STy->getStructName().startswith("union.anon")) {
              if (Id.empty())
                new_id = getStructId(STy, M, i);
            } else {
              new_id = getStructId(STy, M, i);
            }
          }
          if (new_id.empty()) {
            assert(!Id.empty());
            new_id = Id + "," + std::to_string(i);
          }
          Ctx->FuncPtrs[new_id].insert(getFuncDef(F));
        }
      }
    }
  } else if (ConstantArray *CA = dyn_cast<ConstantArray>(C)) {
    // array, conservatively collects all possible pointers
    for (unsigned i = 0; i != CA->getNumOperands(); ++i)
      processInitializers(M, CA->getOperand(i), V, Id);
  } else if (Function *F = dyn_cast<Function>(C)) {
    // global function pointer variables
    if (V) {
      std::string Id = getVarId(V);
      Ctx->FuncPtrs[Id].insert(getFuncDef(F));
    }
  }
}
/*
unsigned int CallGraphPass::getLineNumber(Instruction *I) {
    return 0;
    if (MDNode *N = I->getMetadata("dbg")) {
        DILocation Loc =  DILocation(N);
        unsigned Line = Loc.getLineNumber();
        return Line;
    } else {
	errs()<<"Could get Line Number\n";
	exit(-1);
	//return NULL;
    }

}
*/
Function *CallGraphPass::getFuncDef(Function *F) {
  FuncMap::iterator it = Ctx->Funcs.find(getScopeName(F));
  if (it != Ctx->Funcs.end())
    return it->second;
  else
    return F;
}


/* This function is used for finding every `call` inst's called function, and insert into FuncSet */
bool CallGraphPass::findCallees(CallInst *CI, FuncSet &FS) {
  Function *CF = CI->getCalledFunction();

  // real function, S = S + {F}
  if (CF) {
    std::string functionName = CF->getName().str();
    // filter some funcs...
    for(auto &s : needToBeFiltered) {
	if (strstr(s.c_str(), functionName.c_str())) {
	    return false;
	}
    }
    //outs()<<"\t\t\t[+] `call "<<functionName<<"`"<<"\n";
    // prefer the real definition to declarations
    CF = getFuncDef(CF);
    //outs()<<"\t\t\t[*] insert to "<< &FS << " -> "<<CF<<" : "<<CF->getName()<<"\n";		    // What if the same called function, but the CF instructions are in different address?
    return FS.insert(CF).second;
  }

  // save called values for point-to analysis
  Ctx->IndirectCallInsts.push_back(CI);

#ifdef TYPE_BASED
  // use type matching to concervatively find
  // possible targets of indirect call
  return findCalleesByType(CI, FS);
#else
  // use assignments based approach to find possible targets
  //outs() << "`indirect call "<<*CI->getCalledOperand()<<"\n";
  return findFunctions(CI->getCalledOperand(), FS);
#endif
}

bool CallGraphPass::mergeFuncSet(FuncSet &S, const std::string &Id,
                                 bool InsertEmpty) {
  FuncPtrMap::iterator i = Ctx->FuncPtrs.find(Id);
  if (i != Ctx->FuncPtrs.end())
    return mergeFuncSet(S, i->second);
  else if (InsertEmpty)
    Ctx->FuncPtrs.insert(std::make_pair(Id, FuncSet()));
  return false;
}

bool CallGraphPass::mergeFuncSet(std::string &Id, const FuncSet &S,
                                 bool InsertEmpty) {
  FuncPtrMap::iterator i = Ctx->FuncPtrs.find(Id);
  if (i != Ctx->FuncPtrs.end())
    return mergeFuncSet(i->second, S);
  else if (!S.empty())
    return mergeFuncSet(Ctx->FuncPtrs[Id], S);
  else if (InsertEmpty)
    Ctx->FuncPtrs.insert(std::make_pair(Id, FuncSet()));
  return false;
}

bool CallGraphPass::mergeFuncSet(FuncSet &Dst, const FuncSet &Src) {
  bool Changed = false;
  for (FuncSet::const_iterator i = Src.begin(), e = Src.end(); i != e; ++i) {
    assert(*i);
    Changed |= Dst.insert(*i).second;
  }
  return Changed;
}


bool CallGraphPass::findFunctions(Value *V, FuncSet &S) {
  SmallPtrSet<Value *, 4> Visited;
  return findFunctions(V, S, Visited);
}


bool CallGraphPass::findFunctions(Value *V, FuncSet &S,
                                  SmallPtrSet<Value *, 4> Visited) {
  if (!Visited.insert(V).second)
    return false;

  // real function, S = S + {F}
  if (Function *F = dyn_cast<Function>(V)) {
    // prefer the real definition to declarations
    F = getFuncDef(F);
    return S.insert(F).second;
  }

  // bitcast, ignore the cast
  if (CastInst *B = dyn_cast<CastInst>(V))
    return findFunctions(B->getOperand(0), S, Visited);

  // const bitcast, ignore the cast
  if (ConstantExpr *C = dyn_cast<ConstantExpr>(V)) {
    if (C->isCast()) {
      return findFunctions(C->getOperand(0), S, Visited);
    }
    // FIXME GEP
  }

  if (GetElementPtrInst *G = dyn_cast<GetElementPtrInst>(V)) {
    return false;
  } else if (isa<ExtractValueInst>(V)) {
    return false;
  }

  if (isa<AllocaInst>(V)) {
    return false;
  }

  if (BinaryOperator *BO = dyn_cast<BinaryOperator>(V)) {
    Value *op0 = BO->getOperand(0);
    Value *op1 = BO->getOperand(1);
    if (!isa<Constant>(op0) && isa<Constant>(op1))
      return findFunctions(op0, S, Visited);
    else if (isa<Constant>(op0) && !isa<Constant>(op1))
      return findFunctions(op1, S, Visited);
    else
      return false;
  }

  // PHI node, recursively collect all incoming values
  if (PHINode *P = dyn_cast<PHINode>(V)) {
    bool Changed = false;
    for (unsigned i = 0; i != P->getNumIncomingValues(); ++i)
      Changed |= findFunctions(P->getIncomingValue(i), S, Visited);
    return Changed;
  }

  // select, recursively collect both paths
  if (SelectInst *SI = dyn_cast<SelectInst>(V)) {
    bool Changed = false;
    Changed |= findFunctions(SI->getTrueValue(), S, Visited);
    Changed |= findFunctions(SI->getFalseValue(), S, Visited);
    return Changed;
  }

  // arguement, S = S + FuncPtrs[arg.ID]
  if (Argument *A = dyn_cast<Argument>(V)) {
    bool InsertEmpty = isFunctionPointer(A->getType());
    return mergeFuncSet(S, getArgId(A), InsertEmpty);
  }

  // return value, S = S + FuncPtrs[ret.ID]
  if (CallInst *CI = dyn_cast<CallInst>(V)) {
    // update callsite info first
    FuncSet &FS = Ctx->Callees[CI];
    // FS.setCallerInfo(CI, &Ctx->Callers);
    findFunctions(CI->getCalledOperand(), FS);
    bool Changed = false;
    for (Function *CF : FS) {
      bool InsertEmpty = isFunctionPointer(CI->getType());
      Changed |= mergeFuncSet(S, getRetId(CF), InsertEmpty);
    }
    return Changed;
  }

  // loads, S = S + FuncPtrs[struct.ID]
  if (LoadInst *L = dyn_cast<LoadInst>(V)) {
    std::string Id = getLoadId(L);
    if (!Id.empty()) {
      bool InsertEmpty = isFunctionPointer(L->getType());
      return mergeFuncSet(S, Id, InsertEmpty);
    } else {
      Function *f = L->getParent()->getParent();
      // errs() << "Empty LoadID: " << f->getName() << "::" << *L << "\n";
      return false;
    }
  }

  // ignore other constant (usually null), inline asm and inttoptr
  if (isa<Constant>(V) || isa<InlineAsm>(V) || isa<IntToPtrInst>(V))
    return false;

  // V->dump();
  // report_fatal_error("findFunctions: unhandled value type\n");
  // errs() << "findFunctions: unhandled value type: " << *V << "\n";
  return false;
}




bool CallGraphPass::doModulePass(Module *M) {
    
    //outs()<<"CallGraphPass::doMoudlePass(): "<<M->getName()<<"\n";
    bool Changed = true, ret = false;

    // For every function in Module we will call runOnFunction();
    while (Changed) {
	Changed = false;
	for (Function &F : *M)
	    Changed |= runOnFunction(&F);
	    ret |= Changed;
    }

    //outs()<<"\n\nCallGraphPass::doModulePass() end\n\n";
    return ret;
}


bool CallGraphPass::runOnFunction(Function *F) {

    // Lewis: we don't give a shit to functions in .init.text
    if ((F->hasSection() && F->getSection().str() == ".init.text")) {
	return false;
    }

    std::string functionName = F->getName().str();
    // filter some funcs...
    for(auto &s : needToBeFiltered) {
	if (strstr(s.c_str(), functionName.c_str())) {
	    return false;
	}
    }

    bool Changed = false;

    //outs()<<"\t\t[*] CallGraphPass::runOnFunction -> "<<F->getName()<<"\n";

    // Searching all insts inside a function to find if there is a `call func` ...
    for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; ++i) 
    {
	Instruction *I = &*i;
	// map callsite to possible callees
	if (CallInst *CI = dyn_cast<CallInst>(I)) 
	{
	    // ignore inline asm or intrinsic calls
	    if (CI->isInlineAsm() || (CI->getCalledFunction() && CI->getCalledFunction()->isIntrinsic()))
		continue;

	    // might be an indirect call, find all possible callees

	    // Filter here
	    unsigned needFilter = 0;
	    //std::string CalledFunctionName = CI->getCalledFunction();
	    if (CI->getCalledFunction()){
	    std::string CalledFunctionName = CI->getCalledFunction()->getName().str();
 	
	    for(auto &s : needToBeFiltered) {
		if (strstr(s.c_str(), CalledFunctionName.c_str())) {
		    needFilter = 1;
		    break;
		}
	    }	
	    }
	    if (needFilter == 0){
		// For every `call` instructions, we will call findCallees() to find the called function and save to related FuncSet;
		FuncSet &FS = Ctx->Callees[CI];
		if (!findCallees(CI, FS))
		    continue;
		
		/*
		outs()<<*CI<<"\t";
		for (FuncSet::iterator j = FS.begin(), ej = FS.end(); j != ej; ++j) {
		    outs()<<"\t\t\tFuncSet: "<<(*j)<<" : "<<(*j)->getName()<<", father func: "<<CI->getParent()->getParent()->getName()<<"\n";
		}
		*/
		
	    }
	}

    }
  //outs()<<"runOnFunction End\n";
  return Changed;
}



// debug
void CallGraphPass::dumpFuncPtrs() {
    raw_ostream &OS = outs();
    for (FuncPtrMap::iterator i = Ctx->FuncPtrs.begin(),
         e = Ctx->FuncPtrs.end(); i != e; ++i) {
        //if (i->second.empty())
        //    continue;
        OS << i->first << "\n";
        FuncSet &v = i->second;
        for (FuncSet::iterator j = v.begin(), ej = v.end(); j != ej; ++j) {
            OS << "  " << ((*j)->hasInternalLinkage() ? "f" : "F")
                << " " << (*j)->getName().str() << "\n";
        }
    }
}

bool findInPreVec(const std::string &fName, CallInst *ci, const CallGraphPath &callGraphPath) {
    for (const auto &item : callGraphPath) {
        if (ci == item.second) {
            return true;
        }
    }
    return false;
}

bool traceUses(llvm::Value *V, llvm::Instruction *Target, std::set<llvm::Value*> &Visited) {
    if (Visited.find(V) != Visited.end()) {
        return false;
    }

    Visited.insert(V);

    if (V == Target) {
        return true;
    }

    if (llvm::Instruction *Inst = llvm::dyn_cast<llvm::Instruction>(V)) {
        for (auto U : Inst->users()) {
            if (llvm::Instruction *UserInst = llvm::dyn_cast<llvm::Instruction>(U)) {
                if (traceUses(UserInst, Target, Visited)) {
                    return true;
                }
            }
        }
    }

    return false;
}

/* We need to take the reachability between `allocation` and `copywrite` */
bool CallGraphPass::ifReachable(Value *alloc, CallInst *copy) {
    std::set<llvm::Value*> Visited;
    bool found = false;
    // first handle some corner cases.
    if (llvm::CallInst *callInst = llvm::dyn_cast<llvm::CallInst>(alloc)) {
        if (callInst->getCalledFunction() && callInst->getCalledFunction()->getName() == "skb_page_frag_refill") {
            if (callInst->getNumOperands() > 1) {
                llvm::Value *secondOperand = callInst->getOperand(1);
                // Try to find the GEP instruction.
                for (auto *U : secondOperand->users()) {
                    if (llvm::GetElementPtrInst *gepInst = llvm::dyn_cast<llvm::GetElementPtrInst>(U)) {
                        // scan all users of GEP instruction, try to find Load instruction
                        for (auto *gepUser : gepInst->users()) {
                            if (llvm::LoadInst *loadInst = llvm::dyn_cast<llvm::LoadInst>(gepUser)) {
                                // trace every Load instruction
                                if (traceUses(loadInst, copy, Visited)) {
                                    found = true; // if found, set found flag to true, and break the loop.
                                    break;
                                }
                                Visited.clear(); //reset the visited set, prepare for next Load instruction.
                            }
                        }
                        if (found) break; // if found, break the loop, don't need to check other GEP users.
                    }
                }
            }
        } else if (callInst->getCalledFunction() && callInst->getCalledFunction()->getName() == "mptcp_page_frag_refill") {
            llvm::Value *secondOperand = callInst->getOperand(1);
            for (auto *U : secondOperand->users()) {
              if( U <= callInst) continue;
              if (llvm::CallInst *subcallInst = llvm::dyn_cast<llvm::CallInst>(U)) {
                  //outs()<<"found =>"<<*subcallInst<<"\n";
                  if (subcallInst->getCalledFunction()->getName() == "mptcp_carve_data_frag")
                      alloc = subcallInst; //
              }
            }
        }
    }

    if (!found) {
        // if not found related Load instruction, or alloc is not the call of skb_page_frag_refill, just trace alloc.
        found = traceUses(alloc, copy, Visited);
    }

    return found;
}
//CallGraphPath callGraphPath;
void  CallGraphPass::backtraceRootInterfaceShallow(std::string rootInterface, CallGraphPath &callGraphPath) {
    int flag = 0;
    for (CalleeMap::iterator i = Ctx->Callees.begin(), e = Ctx->Callees.end(); i != e; ++i)
    {
	CallInst *CI = i->first;
	Function *F = CI->getParent()->getParent();
	FuncSet &v = i->second;	
	if(v.empty())
	    continue;
	for (FuncSet::iterator j = v.begin(), ej = v.end(); j != ej; ++j)
	{
	    int skip = 0;
	    std::string foundFuncName = (*j)->getName().str();
	    if ( foundFuncName == rootInterface)
	    {
		if (std::find(AllocAPIs.begin(),AllocAPIs.end(),F->getName()) != AllocAPIs.end() || std::find(CopyAPIs.begin(),CopyAPIs.end(),F->getName()) != CopyAPIs.end() || std::find(RemapAPIs.begin(),RemapAPIs.end(),F->getName()) != RemapAPIs.end()) 
		{
		    skip = 1;
		}
		
		if (skip) continue;
	
		std::string FName = F->getName().str();
		if (findInPreVec(FName,CI,callGraphPath)){
		    continue;
		}
		std::pair<llvm::Function *, llvm::CallInst *> node;
		node.first = F;
		node.second = CI;
		//outs()<<F->getName()<<" => "<<*CI<<" => "<<*CI->getType()<<"\n";
		callGraphPath.push_back(node);
		flag = 1;
	    }
        }
    }
}

bool CallGraphPass::filterBacktraceracePaths(Function *F) {
    std::set<llvm::StringRef> list = {"_sys_","llvm","ubsan","free","kasan","kcsan","rcu","kcsan","test_bit","check_","atomic","arch_","xen","print","seccomp","exit","fault","_pte","load_elf_binary","_pmd","hv_","ext4_","slab_","kmem_cache_create","selinux","kmalloc","execve","mm_populate","security_","battery","acpi","unregister","delete","destroy","change_page","apparmor","close","cleanup","copy_process","cgroup","remove","hugepage","scsi","_release","_chip","_kexec","_thermal","raw_probe_proto_opt"};
    for (auto i : list) {
	if (F->getName().rfind(i) != -1)
	    return true;
    }
    return false;

}
void  CallGraphPass::backtraceRootInterface(std::string rootInterface, CallGraphPath &callGraphPath){
    int flag = 0;
    for (CalleeMap::iterator i = Ctx->Callees.begin(), e = Ctx->Callees.end(); i != e; ++i)
    {
	      CallInst *CI = i->first;
        Function *F = CI->getParent()->getParent();
        FuncSet &v = i->second;	
        if(v.empty())
            continue;

        for (FuncSet::iterator j = v.begin(), ej = v.end(); j != ej; ++j)
        {
            int skip = 0;
            std::string foundFuncName = (*j)->getName().str();
            if ( foundFuncName == rootInterface)
            {
                if (std::find(AllocAPIs.begin(),AllocAPIs.end(),F->getName()) != AllocAPIs.end() || std::find(CopyAPIs.begin(),CopyAPIs.end(),F->getName()) != CopyAPIs.end() || std::find(RemapAPIs.begin(),RemapAPIs.end(),F->getName()) != RemapAPIs.end()) 
                    continue;
                
                std::string FName = F->getName().str();
                if (filterBacktraceracePaths(F))
                    continue;

                if (findInPreVec(FName,CI,callGraphPath))
                    continue;

                std::pair<llvm::Function *, llvm::CallInst *> node;
                node.first = F;
                node.second = CI;
            //		outs()<<F->getName()<<" => "<<*CI<<"\n";;
                callGraphPath.push_back(node);
                flag = 1;
                backtraceRootInterface(FName,callGraphPath);
            }
        }
    }
}

void CallGraphPass::dumpCallees(std::string targetFuncName) {
  raw_ostream &OS = outs();
  OS<<"["<<targetFuncName<<"] ";
  for (CalleeMap::iterator i = Ctx->Callees.begin(), e = Ctx->Callees.end(); i != e; ++i) 
  {
    CallInst *CI = i->first;
    Function *F = CI->getParent()->getParent();
    FuncSet &v = i->second;
    if ( v.empty() ){
	continue;
    }
#if 1
    for (FuncSet::iterator j = v.begin(), ej = v.end(); j != ej; ++j) 
	{
            
	    int skip = 0;
	    std::string foundFuncName = (*j)->getName().str();
	    if ( foundFuncName == targetFuncName){
		if ((std::find(AllocAPIs.begin(), AllocAPIs.end(), F->getName()) != AllocAPIs.end()) 
		    || std::find(CopyAPIs.begin(), CopyAPIs.end(), F->getName()) != CopyAPIs.end())
		{
		    skip = 1;
		}
		
		if (skip) continue;
		OS <<"\t "<<" -> "<<F->getName().str()<<"\n";
		dumpCallees(F->getName().str()); 
	    }
        }

#endif

  }
  outs()<<" [END] "<<"\n";
}


void CallGraphPass::dumpCallers() {
  outs()<<"\n[dumpCallers]\n";
  for (auto M : Ctx->Callers) {
    Function *F = M.first;
    CallInstSet &CIS = M.second;
    outs()<<"F : " << getScopeName(F) << "\n";

    for (CallInst *CI : CIS) {
      Function *CallerF = CI->getParent()->getParent();
      outs()<<"\t";
      if (CallerF && CallerF->hasName()) {
        outs()<<"(" << getScopeName(CallerF) << ") ";
      } else {
        outs()<<"(anonymous) ";
      }

      outs()<<*CI << "\n";
    }
  }
  outs()<<"\n[End of dumpCallers]\n";
}

void CallGraphPass::crossAnalyze(std::string A, std::string B, CallsiteAnalyzer *analyzer) {

    outs()<<"\nCross Analyzing => ["<<A<<"]"<<" x "<<"["<<B<<"]"<<"\n";
    CallGraphPath pathA, pathB;
    backtraceRootInterface(A, pathA);
    outs()<<"[+] Path of ["<<A<<"] build done\n";
    backtraceRootInterface(B, pathB);
    outs()<<"[+] Path of ["<<B<<"] build done\n";
    
    std::set<llvm::Function *> preSaved;
    for (auto &i : pathA)
    {
	for (auto &j : pathB)
	{
	    if ((i.first)->getName().str() == (j.first)->getName().str()  &&  (i.second) != (j.second) && (i.second)->getCalledFunction() != (j.second)->getCalledFunction())		// In two paths, if we found the same `father()` function
	    {
		
		if (std::find(preSaved.begin(),preSaved.end(),(i.first)) != preSaved.end() || std::find(preSaved.begin(),preSaved.end(),(i.second)->getCalledFunction()) != preSaved.end() || 
		    std::find(preSaved.begin(), preSaved.end(),(j.second)->getCalledFunction()) != preSaved.end())
		    continue;

		/* FIXME 
		 * 
		 * We may filter all the HOOK function?
		 *
		 * */
		if ((i.first)->getName().rfind("HOOK") != -1 || (j.second)->getName().rfind("hook") != -1 || (i.second)->getCalledFunction()->getName().rfind("HOOK") != -1 || (i.second)->getCalledFunction()->getName().rfind("hook") != -1 ||  (j.second)->getCalledFunction()->getName().rfind("hook") != -1 ||  (j.second)->getCalledFunction()->getName().rfind("HOOK") != -1)
		    continue;
		
		/* And we need to make sure the copywrite happened behind the allocation. */
		
	
		unsigned allocLine = (i.second)->getDebugLoc().getLine();
		unsigned copyLine = (j.second)->getDebugLoc().getLine();
		if (copyLine < allocLine) {
		    continue;
		}

	
		if (ifReachable((i.second), (j.second)) == false)  {
      outs()<<"ifReachable() => false => "<<*(i.second)<<" => "<<*(j.second)<<"\n";
			continue;
    }
		
		

		preSaved.insert(i.first);
    //outs()<<"\t"<<"Found => "<<(i.first)->getName()<<"\n";
		outs()<<"\t"<<"{"<<(i.first)->getName()<<"}"<<"\n\t\t"<<*(i.second)<<"\n\t\t"<<*(j.second)<<"\n";
		std::set<llvm::Value* > trackedSet;
		std::vector<llvm::Value *> srcSet;
		std::vector<llvm::Value *> targetSet;
#if TRACE_CS
		analyzer->dataflowCrossTraceControlStruct((i.second), (j.second), &trackedSet, &srcSet, &targetSet, &pathA, &pathB);
#endif
	    }
	}
    }
}

std::set<llvm::Function*> CallGraphPass::findRootInterfaceUpper(std::string rootInterface, CallGraphPath &callGraphPath, std::string subsystem) {
   std::queue<llvm::Function *> bfsQueue; // BFS 队列
    std::set<llvm::Function *> visited; // 访问过的函数集合
    std::set<std::string> foundFunctionNames; // 存储找到的函数名
    std::map<std::string, llvm::Function *> nameToFunctionMap; // 函数名到函数对象的映射

    // 初始化 BFS 队列
    for (auto &i : Ctx->Callees) {
        llvm::CallInst *CI = i.first;
        llvm::Function *F = CI->getParent()->getParent();
        if (F->getName().str() == rootInterface) {
            for (llvm::Function *callerFunc : i.second) {
                bfsQueue.push(callerFunc);
            }
        }
    }

    while (!bfsQueue.empty()) {
        llvm::Function *currentFunc = bfsQueue.front();
        bfsQueue.pop();

        if (visited.find(currentFunc) != visited.end()) {
            continue;
        }
        visited.insert(currentFunc);

        std::string currentFuncName = currentFunc->getName().str();
        if (currentFuncName.find(subsystem + '_') == 0)
        {
            foundFunctionNames.insert(currentFuncName);
            nameToFunctionMap[currentFuncName] = currentFunc;
        }

        for (llvm::CallInst *caller : Ctx->Callers[currentFunc]) {
            llvm::Function *callerFunc = caller->getParent()->getParent();
            bfsQueue.push(callerFunc);
        }
    }

    std::set<std::string> callerFunctionNames;
    std::set<llvm::Function*> targetFunctions;
    for (const auto &funcName : foundFunctionNames) {
        llvm::Function *func = nameToFunctionMap[funcName];
        for (User *user : func->users()) {
            if (llvm::CallInst *caller = llvm::dyn_cast<llvm::CallInst>(user)) {
                llvm::Function *callerFunc = caller->getFunction();
                if (callerFunc && foundFunctionNames.find(callerFunc->getName().str()) != foundFunctionNames.end()) {
                    callerFunctionNames.insert(callerFunc->getName().str());
                }
            }
        }
    }

    
    for (const auto &funcName : foundFunctionNames) {
        if (callerFunctionNames.find(funcName) == callerFunctionNames.end()) {
            llvm::Function* func = nameToFunctionMap[funcName];
            llvm::Module* module = func->getParent();
            if (module && module->getName().rfind("_"+subsystem+"_")) {
                if (funcName.find("_alloc") != std::string::npos || 
                    funcName.find("_set_") != std::string::npos ||
                    funcName.find("_init") != std::string::npos) {
                    targetFunctions.insert(func);
                    //outs() << "[+] Found in Subsystem Module => " << funcName << "\n";
                }
            }
        }
    }
    return targetFunctions;
}
void CallGraphPass::zerocopyAnalyze(std::string function, std::set<Function *> *mmapRefList, CallsiteAnalyzer *analyzer){
    outs()<<"Calltrace Analyzing => "<<"["<<function<<"]"<<"\n";
    CallGraphPath pathA;
    CallGraphPath pathB;
    CallGraphPath pathAlloc;
    //std::set<llvm::Value* > trackedSet;
    //std::vector<llvm::Value *> srcSet;
    //std::vector<llvm::Value *> targetSet;
    backtraceRootInterface(function, pathA);
    for (auto &i : pathA)
    {
        if(((i.first)->getName().rfind("_mmap") != -1) && (mmapRefList->find((i.first)) != mmapRefList->end())) // Make sure the mmap func we found is part of mmapRefList
        {
            std::set<llvm::Value* > trackedSet;
            std::vector<llvm::Value *> srcSet;
            std::vector<llvm::Value *> targetSet;
            llvm::StringRef nameRef = (i.first)->getName();
            Type *typeA;
            Type *typeB;
            //outs()<<"\t"<<"{"<<(i.first)->getName()<<"}"<<"\n\t\t"<<*(i.second)<<"\n";
            //analyzer->dataflowBackwardTraceControlStruct((i.second), &trackedSet, &srcSet, &targetSet); 

            std::istringstream iss(nameRef.str());
            std::string subsystem;
            std::getline(iss, subsystem, '_');
            //outs()<<"subsystem => "<<subsystem<<"\n";
            // We scan all the instructions we tracked in `dataflowTraceControlStruct()` in order to analyze the potential control struct
            // also `io_mem_alloc()` is only used in io_uring
            if ((i.first)->getName().rfind(subsystem + "_") != -1) {
                //outs()<<"find => "<<(i.first)->getName()<<"\n"; 
                std::set<llvm::Function*> targetFunctions;
                targetFunctions = findRootInterfaceUpper("alloc_pg_vec", pathAlloc, subsystem);

                if (targetFunctions.empty()) {
                    targetFunctions = findRootInterfaceUpper("__get_free_page", pathAlloc, subsystem);
                }

                if (targetFunctions.empty()) {
                    targetFunctions = findRootInterfaceUpper("alloc_pages", pathAlloc, subsystem);
                }

                if (targetFunctions.empty()) {
                    outs() << "\t\t\t" << "[!] No suitable allocation function found\n";
                    continue;
                }

                for (auto j : targetFunctions) {
                    llvm::Value* result_remap;
                    llvm::Value* result_alloc;
                    llvm::GetElementPtrInst* cs_remap;
                    llvm::GetElementPtrInst* cs_alloc;
                    //outs() << "\t[remapping site] => " << (i.first)->getName() << "\n\t[potential allocation site] => " << j->getName() << "\n";

                    if ((i.second)->getCalledFunction()->getName() == "vm_insert_page") {
                          //outs()<<"find vm_insert_page => "<<*(i.second)<<"\n";
                          result_remap = analyzer->findRemapControlStructureBackward((i.second)->getOperand(2), subsystem);
                          // if(result_remap)
                          //     outs()<<" result_remap => "<<*result_remap<<"\n";

                          result_alloc = analyzer->findAllocationControlStructureForward(j, subsystem, Ctx->Callers);
                          // if(result_alloc)
                          //     outs()<<" result_alloc => "<<*result_alloc<<"\n";
                          if(result_remap && result_alloc) {
                                cs_remap = dyn_cast<llvm::GetElementPtrInst>(result_remap);
                                cs_alloc = dyn_cast<llvm::GetElementPtrInst>(result_alloc);
                                outs() << "\t[remapping site] => " << (i.first)->getName() << "\n";
                                outs()<<"\t[potential allocation site] => " << j->getName() << "\n";

                                if (llvm::dyn_cast<llvm::StructType>(cs_remap->getPointerOperandType()->getPointerElementType())->getName() == llvm::dyn_cast<llvm::StructType>(cs_alloc->getPointerOperandType()->getPointerElementType())->getName() ||
                                 analyzer->structContainsStruct(llvm::dyn_cast<llvm::StructType>(cs_remap->getPointerOperandType()->getPointerElementType()), llvm::dyn_cast<llvm::StructType>(cs_alloc->getPointerOperandType()->getPointerElementType()))
                                 ) {
                                outs()<<"\t[potential cs in remap] => "<<llvm::dyn_cast<llvm::StructType>(cs_remap->getPointerOperandType()->getPointerElementType())->getName()<<"\n";
                                
                                outs()<<"\t[potential cs in allocation] => "<<llvm::dyn_cast<llvm::StructType>(cs_alloc->getPointerOperandType()->getPointerElementType())->getName()<<"\n\n"; 
                                 }
                          }
                    } 
                    else if ((i.second)->getCalledFunction()->getName() == "remap_pfn_range") {
                          //outs()<<"find remap_pfn_range op 2=> "<<*(i.second)->getOperand(2)<<"\n";
                          //outs()<<"start => "<<(i.first)->getName()<<"\n";
                          result_remap = analyzer->findRemapControlStructureBackward((i.second)->getOperand(2), subsystem);
                          //if(result_remap)
                          //   outs()<<" result_remap => "<<*result_remap<<"\n";
                          //outs()<<"check allocation => "<<j->getName()<<"\n";
                          result_alloc = analyzer->findAllocationControlStructureForward(j, subsystem, Ctx->Callers);
                          //outs()<<result_alloc<<"\n";
                          if(result_remap && result_alloc) {
                            cs_remap = dyn_cast<llvm::GetElementPtrInst>(result_remap);
                            outs() << "\t[remapping site] => " << (i.first)->getName() << "\n";
                            outs()<<"\t[potential cs in remap] => "<<llvm::dyn_cast<llvm::StructType>(cs_remap->getPointerOperandType()->getPointerElementType())->getName()<<"\n";
                            outs()<<"\t[potential allocation site] => " << j->getName() << "\n";

                            if (isa<GetElementPtrInst>(result_alloc)) {
                                cs_alloc = dyn_cast<llvm::GetElementPtrInst>(result_alloc);
                                outs()<<"\t[potential cs in allocation] => "<<llvm::dyn_cast<llvm::StructType>(cs_alloc->getPointerOperandType()->getPointerElementType())->getName()<<"\n\n"; 
                            } else if (isa<CallInst>(result_alloc)) {
                                outs()<<"\t[potential cs in allocation] => "<<llvm::dyn_cast<llvm::StructType>(result_alloc->getType()->getPointerElementType())->getName()<<"\n\n"; 
                            }
                            //else if (isa<CallInst>(result_alloc))
                          }
                    } else if ((i.second)->getCalledFunction()->getName() == "remap_vmalloc_range") {
                          //outs()<<"find remap_pfn_range op 2=> "<<*(i.second)->getOperand(2)<<"\n";
                          //outs()<<"start => "<<(i.first)->getName()<<"\n";
                          //outs()<<subsystem<<"\n";
                          result_remap = analyzer->findRemapControlStructureBackward((i.second)->getOperand(1), subsystem);
                          if(result_remap)
                            //outs()<<" result_remap => "<<*result_remap<<"\n";
                          
                          //outs()<<"check allocation => "<<j->getName()<<"\n";
                          result_alloc = analyzer->findAllocationControlStructureForward(j, subsystem, Ctx->Callers);
                          if(result_alloc)
                            //outs()<<" result_alloc => "<<*result_alloc<<"\n";
                          //outs()<<result_alloc<<"\n";
                          if(result_remap && result_alloc) {
                            cs_remap = dyn_cast<llvm::GetElementPtrInst>(result_remap);


                            if (isa<GetElementPtrInst>(result_alloc)) {
                                cs_alloc = dyn_cast<llvm::GetElementPtrInst>(result_alloc);
                                outs() << "\t[remapping site] => " << (i.first)->getName() << "\n";
                                outs()<<"\t[potential cs in remap] => "<<llvm::dyn_cast<llvm::StructType>(cs_remap->getPointerOperandType()->getPointerElementType())->getName()<<"\n";
                                outs()<<"\t[potential allocation site] => " << j->getName() << "\n";
                                outs()<<"\t[potential cs in allocation] => "<<llvm::dyn_cast<llvm::StructType>(cs_alloc->getPointerOperandType()->getPointerElementType())->getName()<<"\n\n"; 
                            } else if (isa<CallInst>(result_alloc)) {
                               CallInst *call_arg = dyn_cast<CallInst>(result_alloc);
                                outs() << "\t[remapping site] => " << (i.first)->getName() << "\n";
                                 Argument *arg; 
                                if (isa<Argument>(result_remap)) {
                                    arg = dyn_cast<Argument>(result_remap);
                                    // if (!arg->isStructTy()) {
                                    //     outs()<<*result_remap<<"is not struct!"<<"\n";
                                    // }

                                    if (arg->getType()->isPointerTy()) {
                                        outs()<<"\t[potential cs in remap] => "<<llvm::dyn_cast<llvm::StructType>(arg->getType()->getPointerElementType())->getName()<<"\n";
                                    }
                                    //outs()<<"\t[potential cs in remap] => "<<*arg<<"\n";
                                } else {
                                    outs()<<"\t[potential cs in remap] => "<<llvm::dyn_cast<llvm::StructType>(cs_remap->getPointerOperandType()->getPointerElementType())->getName()<<"\n";
                                }
                                
                                outs()<<"\t[potential allocation site] => " << j->getName() << "\n";
                                
                                llvm::Type* elementType = nullptr;
                                if (call_arg->getType()->isPointerTy()) {
                                  elementType = call_arg->getType()->getPointerElementType();
                                }
                                if (elementType && elementType->isStructTy()) {
                                    if(analyzer->structContainsStruct(llvm::dyn_cast<llvm::StructType>(cs_remap->getPointerOperandType()->getPointerElementType()), llvm::dyn_cast<llvm::StructType>(elementType))) {
                                      outs()<<"\t[potential cs in allocation] => "<<elementType->getStructName()<<"\n\n"; 
                                    }
                                    else
                                        outs()<<"error! => "<<elementType->getStructName()<<"\n";
                                    //outs()<<"\t[potential cs in allocation] => "<<elementType->getStructName()<<"\n\n"; 
                                } else {
                                    // it could be that after allocation, return a tmp value(void *), and will be casted to a struct pointer later.
                                    // so we do a quick forward analysis.
                                    
                                    llvm::Instruction* structPointerInst = analyzer->findStructPointerForward(llvm::dyn_cast<llvm::Instruction>(call_arg));
                                    //outs()<<"\tNot struct [potential cs in allocation] => "<<*call_arg<<"\n\n"; 
                                    if (structPointerInst) {
                                        llvm::Type* targetType = nullptr;

                                        if (auto* bitcastInst = llvm::dyn_cast<llvm::BitCastInst>(structPointerInst)) {
                                            targetType = bitcastInst->getDestTy(); 
                                        }

                                        if (targetType && targetType->isPointerTy()) {
                                            llvm::Type* elementType = targetType->getPointerElementType();
                                            if (elementType->isStructTy()) {
                                                llvm::StructType* structType = llvm::cast<llvm::StructType>(elementType);
                                                if (structType->hasName()) {
                                                  if( analyzer->structContainsStruct(llvm::dyn_cast<llvm::StructType>(llvm::dyn_cast<llvm::StructType>(structType)), llvm::dyn_cast<llvm::StructType>(arg->getType()->getPointerElementType()))) {
                                                    outs() << "\t[potential cs in allocation] => " << structType->getName() << "\n\n";
                                                  }
                                                }
                                            }
                                        }
                                    }

                                } 
                            } else if (isa<Argument>(result_alloc)) {
                               Argument *arg = dyn_cast<Argument>(result_alloc);
                                outs() << "\t[remapping site] => " << (i.first)->getName() << "\n";
                                outs()<<"\t[potential cs in remap] => "<<result_alloc->getName()<<"\n";
                                outs()<<"\t[potential allocation site] => " << j->getName() << "\n";
                             
                                outs()<<"\t[potential cs in allocation] => "<<*arg<<"\n"; 
                            }
                            //else if (isa<CallInst>(result_alloc))
                          }
                    }
                }
            }
        }
    }
}
