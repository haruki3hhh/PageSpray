#include <llvm/IR/TypeFinder.h>
#include <llvm/Support/raw_ostream.h>

#include "Annotation.h"
#include "CallsiteAnalyzer.h"
#include <queue>

#//include "GlobalCtx.h"

using namespace llvm;


void CallsiteAnalyzer::run(Module *M, const DataLayout *layout) {

    std::string ModuleName = M->getSourceFileName();
    outs()<<"\t[*] CallsiteAnalyzer::run(): "<<ModuleName<<"\n";
    
    
    /*
    TypeFinder usedStructTypes;
    usedStructTypes.run(*M, false);
  for (TypeFinder::iterator itr = usedStructTypes.begin(),
                            ite = usedStructTypes.end();
       itr != ite; ++itr) {
    const StructType *st = *itr;

    // handle non-literal first
    if (st->isLiteral()) {
      addStructInfo(st, M, layout);
      continue;
    }

    // only add non-opaque type
    if (!st->isOpaque()) {
      // process new struct only
      if (structMap.insert(std::make_pair(getScopeName(st, M), st)).second)
        addStructInfo(st, M, layout);
    }
  }
  */
}


bool CallsiteAnalyzer::isCall2Alloc(CallInst *CI) {
	Function *callee = CI->getCalledFunction();
	if (!callee) {
		outs()<<"[ERROR] isCall2Alloc => "<<*CI<<"\n";
		return false;
	}
    StringRef calleeName = callee->getName();
    if (std::find(AllocAPIs.begin(), AllocAPIs.end(), calleeName) != AllocAPIs.end())
    {
	return true;
    }
    else
    {
	//outs()<<"isCall2Alloc() => "<<calleeName<<"\n";
	return false;
    }
}
bool CallsiteAnalyzer::isCall2Copy(CallInst *CI) {
	Function *callee = CI->getCalledFunction();
	if (!callee) {
		outs()<<"[ERROR] isCall2Copy => "<<*CI<<"\n";
		return false;
	}
    StringRef calleeName = callee->getName();

    if (std::find(CopyAPIs.begin(), CopyAPIs.end(), calleeName) != CopyAPIs.end())
    {
	return true;
    }
    else
    {
	//outs()<<"isCall2Alloc() => "<<calleeName<<"\n";
	return false;
    }   
}
llvm::Value *CallsiteAnalyzer::getOffset(llvm::GetElementPtrInst *GEP) {
    return GEP->getOperand(GEP->getNumIndices());     
}

bool CallsiteAnalyzer::isFunctionBodyEmpty(llvm::Function* F) {
	return F->empty() || std::all_of(F->begin(), F->end(), [](const llvm::BasicBlock &BB) {
	return BB.empty();
});
}
 
// fast search 
bool CallsiteAnalyzer::hasLowerDirectPageAllocCall(llvm::CallInst* callInst,  const std::string&  subsystem, CallerMap &Callers, std::set<llvm::Value *> visited) {
 	 
	if (!callInst || !callInst->getCalledFunction()) return false;

	
    llvm::Function* calledFunction = callInst->getCalledFunction();
	llvm::Function* precalledFunction = nullptr;
	//outs()<<"fast search => "<<calledFunction->getName()<<"\n";
	if (isFunctionBodyEmpty(calledFunction)) {
		//outs()<<"empty function => "<<calledFunction->getName()<<"\n";
		for (auto &m : global_modules) {
			if (m.second.rfind(subsystem) != std::string::npos) {
				llvm::Module *M = m.first;
				//outs()<<"find module => "<<M->getName()<<"\n";
				for (auto &F : *M) {
					//outs()<<"find function => "<<F.getName()<<" in "<<M->getName()<<"\n";
					if (F.getName() == calledFunction->getName() && !F.empty()) {
						//outs()<<"function => "<<F.getName()<<" in "<<M->getName()<<"\n";
						calledFunction = &F;
						break;
					}
				}
			}
		}
		//xskq_create is in another module
	}
	//outs()<<"fast search => "<<*callInst<<" in => "<<callInst->getParent()->getParent()->getParent()->getName()<<"\n";  
	// do a fast seracing in the calledFunction
	//outs()<<"calledFunction => "<<calledFunction->getName()<<"\n";
	for (auto *call : Callers[calledFunction]) {
			//outs()<<"call in fast search => "<<*call<<"\n";	
			if (call->getCalledFunction()->empty()) {
				//outs()<<"empty function => "<<call->getCalledFunction()->getName()<<"\n";
				goto err;
			}

		    	
			if (call->getCalledFunction() && callInst->getParent()->getParent()) {
				if (DirectPageAlloc.find(call->getCalledFunction()->getName()) != DirectPageAlloc.end()) {
					return true;
				} else if(
						call->getCalledFunction()->getName() != callInst->getParent()->getParent()->getName()
						
						) {
							
							if (call->getCalledFunction()->getName().contains("create") || call->getCalledFunction()->getName().contains("alloc") || call->getCalledFunction()->getName().contains("init")) {
								//outs()<<"deeper search => "<<*call<<"\n";
								precalledFunction = callInst->getParent()->getParent(); 
								//outs()<<"precalledFunction => "<<precalledFunction->getName()<<"\n";
								//outs()<<"call parent => "<<call->getParent()->getParent()->getName()<<"\n";
								// outs()<<"calledfunction => "<<call->getCalledFunction()->getName()<<"\n";
								// outs()<<"call => "<<*call<<"\n";	
								//if (call->getParent()->getParent() != precalledFunction) {
									if (!visited.insert(precalledFunction).second) {
										//outs()<<"have visited => "<<precalledFunction->getName()<<"\n";
										continue; 
										//return false;		// if we have visited this function, then we can skip it.(maybe recursion)
									}
									
									//outs()<<"recusive to => "<<call->getCalledFunction()->getName()<<"\n";
									bool res = hasLowerDirectPageAllocCall(call, subsystem, Callers, visited); 
									if (res) {
										return true;
									} else {
										outs()<<"not found => "<<call->getCalledFunction()->getName()<<"\n";
										continue;
									}
								//}
							}
						} 
			}
	}

	err: 
    for (auto& BB : *calledFunction) {
        for (auto& I : BB) {
            if (llvm::CallInst* innerCallInst = llvm::dyn_cast<llvm::CallInst>(&I)) {
				//outs()<<"hasLowerDirectPageAllocCall => "<<*innerCallInst<<" in "<<calledFunction->getParent()->getName()<<"\n";
                llvm::Function* innerCalledFunction = innerCallInst->getCalledFunction();
                if (innerCalledFunction) {
                    llvm::StringRef functionName = innerCalledFunction->getName();
                    if (DirectPageAlloc.find(functionName) != DirectPageAlloc.end()) {
                        return true;
                    } 
                }
            }
        }
    }
    return false;
}


llvm::CallInst *CallsiteAnalyzer::searchFromPath(CallGraphPath *path, CallInst *CI) {
    //outs()<<"search => "<<*CI<<"\n";
    Function *F;
    while (1)
    {
	for (auto &i : (*path))
	{
	    
	    if (CI && (i.first) == CI->getParent()->getParent() && (i.second)->getCalledFunction() == CI->getCalledFunction())
	    {
		if (isCall2Alloc(CI) || isCall2Copy(CI))
		    return CI;
		else
		    //outs()<<"search to => "<<*CI<<"\n";
		    F = CI->getCalledFunction(); 
		    CI = NULL;
	    }
	    else if (F && (i.first)->getName() == F->getName())
	    {
		if (isCall2Alloc(i.second) || isCall2Copy(i.second))
		    return i.second;
		F = (i.second)->getCalledFunction();
	//	outs()<<"F => "<<F->getName()<<"\n";
	    }
	}
    }	
}

llvm::Type *CallsiteAnalyzer::getApiType(CallInst *CI) {
    Value *V = CI;
    std::set<llvm::Value *> trackedSet; 
    std::vector<llvm::Value *> srcSet; 
    std::vector<llvm::Value *> targetSet;

    if (CI->getCalledFunction()->getName().rfind("sock_alloc_send_pskb") != std::string::npos) {
        return CI->getType();	
    } else if (CI->getCalledFunction()->getName().rfind("sock_alloc_send_skb") != std::string::npos) {
        // invalid
        return CI->getType();
    } else if (CI->getCalledFunction()->getName().rfind("skb_copy_datagram_from_iter") != std::string::npos) {
        return CI->getOperand(0)->getType();
    } else if (CI->getCalledFunction()->getName().rfind("memcpy_from_msg") != std::string::npos) {	
        dataflowBackwardTraceControlStruct(V, &trackedSet, &srcSet, &targetSet);
        for (auto i : srcSet) {
            if (CallInst *ci = dyn_cast<CallInst>(i)) {
                //outs() << "CALL => " << *ci << "\n";
                if (ci->getCalledFunction()->getName().rfind("ip_hdr") != std::string::npos) {
                    //outs() << "dataflow find ip_hdr" << "\n";
                    //CI = ci;
                    return ci->getOperand(0)->getType();
                }
            }
        }
        outs() << "[ERROR] => " << *CI << "\n";
        return NULL;
        //return CI->getOperand(0)->getType();
    } else if (CI->getCalledFunction()->getName().rfind("copy_page_from_iter") != std::string::npos) {
        return CI->getOperand(0)->getType();
    } else if (CI->getCalledFunction()->getName().rfind("skb_page_frag_refill") != std::string::npos) {
		return CI->getOperand(1)->getType();
	} else if (CI->getCalledFunction()->getName().rfind("zerocopy_sg_from_iter") != std::string::npos) {
		return CI->getOperand(0)->getType();
	}
	else {
		//dataflowBackwardTraceControlStruct(V, &trackedSet, &srcSet, &targetSet);
		//outs()<<"[ERROR] Cannot found Api function => "<<*CI<<"\n";
		return NULL;
        // Additional handling for other cases can be added here
    }
    return NULL;
}


Value* CallsiteAnalyzer::dataflowCrossTraceAllocationControlStruct(Value *alloc, std::set<llvm::Value *> *trackedSet, std::vector<llvm::Value *> *srcSet, std::vector<llvm::Value *> *targetSet, CallGraphPath *path) {
    //outs()<<"alloc => "<<*alloc<<"\n";
    CallInst *allocCI = dyn_cast<CallInst>(alloc);
    Function *calledFunc = allocCI->getCalledFunction();
    Type *allocType = getApiType(allocCI);
    if (allocType)
    {
	//outs()<<"\t\t\tAllocation\t["<<*allocType<<"]\n";
	return allocCI;
    }
    else
    {
	/* We directly search from CallGraphPath */
	//outs()<<"searchFromPath => "<<*allocCI<<"\n";
	CallInst *CI = searchFromPath(path,allocCI);
	if (CI)
	{
	    //allocType = getApiType(CI);
	    //outs()<<"\t\t\t\tAllocation\t["<<*allocType<<"]\n";
	    return CI;
	}
	outs()<<"ERROR => "<<*CI<<"\n";
	
    }
    return NULL;
}

Value* CallsiteAnalyzer::dataflowCrossTraceCopyWriteControlStruct(Value *copy, std::set<llvm::Value *> *trackedSet, std::vector<llvm::Value *> *srcSet, std::vector<llvm::Value *> *targetSet, CallGraphPath *path) {
    //outs()<<"copy => "<<*copy<<"\n";
    CallInst *copyCI = dyn_cast<CallInst>(copy);
    Function *calledFunc = copyCI->getCalledFunction();
    Type *copyType = getApiType(copyCI);
    if (copyType)
    {
	//outs()<<"\t\t\tCopyWrite\t["<<*copyType<<"]\n";
	return copyCI;
    }
    else
    {
	/* We directly search from CallGraphPath */
	CallInst *CI = searchFromPath(path,copyCI);
	if (CI)
	{
	    //copyType = getApiType(CI);
	    //outs()<<"\t\t\t\tCopyWrite\t["<<*copyType<<"]\n";
	    return CI;
	}
	outs()<<"ERROR => "<<*CI<<"\n";
	
    }   
    return NULL;
}

llvm::Value *CallsiteAnalyzer::dataflowTraceNestedCopyWrite(Value *vAlloc, CallInst* copyCI) {
    Function *callee = copyCI->getCalledFunction();
    
    for (BasicBlock &BB : *callee)
    {
	for (Instruction &I : BB)
	{
	    if (CallInst *CI = dyn_cast<CallInst>(&I))
	    {
		Function *F = CI->getCalledFunction();
		if (!F || F->getName().rfind("llvm") != -1 || F->getName().rfind("ubsan") != -1 || F->getName().rfind("free") != -1 || F->getName().rfind("kasan") != -1 || F->getName().rfind("Kcsan") != -1 || F->getName().rfind("rcu") != -1)
		    continue;
	
		//outs()<<*vAlloc<<"\n";
		//outs()<<*CI<<"\n";
		if (isCall2Copy(CI))
		{
		    return CI;
		}
		else if (vAlloc->getType() == CI->getType())
		{
		    return CI;
		}	
		dataflowTraceNestedCopyWrite(vAlloc, CI);
	    }
	}
    }
    return NULL;
}
llvm::Value *CallsiteAnalyzer::dataflowTraceNestedAllocation(Value *vCopy, CallInst* allocCI) {
    Function *callee = allocCI->getCalledFunction();
    //outs()<<"Call => "<<callee->getName()<<"\n";
    // Scan BB the pick the `call` and check if the call is in the allocAPIs
    for(BasicBlock &BB : *callee)
    {
	for(Instruction &I : BB)
	{
	    outs()<<"Inst => "<<I<<"\n";
	    if (CallInst* CI = dyn_cast<CallInst>(&I))
	    {  
		Function *F = CI->getCalledFunction();
		//outs()<<"CI=> "<<*CI<<"\n";

		if (!F || F->getName().rfind("llvm") != -1 || F->getName().rfind("ubsan") != -1 || F->getName().rfind("free") != -1 || F->getName().rfind("kasan") != -1 || F->getName().rfind("kcsan") != -1 || F->getName().rfind("rcu") != -1 || F->getName().rfind("kcsan") != -1 || F->getName().rfind("test_bit") != -1 || F->getName().rfind("check_") != -1 || F->getName().rfind("atomic") != -1 || F->getName().rfind("memcpy") != -1)
		    continue;
		
		outs()<<"subCall => "<<*CI<<"\n";

		//outs()<<"vCopy=> "<<vCopy<<";;\n";

		if (isCall2Alloc(CI))
		{
		    return CI;
		}
		else if (vCopy->getType() == CI->getType())
		{
		    return CI;
		}
		//outs()<<"Call => "<<*CI<<"\n";
		dataflowTraceNestedAllocation(vCopy, CI);
	    }
	}
    }
    return NULL;
}
void CallsiteAnalyzer::dataflowCrossTraceControlStruct(Value *alloc, Value *copy, std::set<llvm::Value* > *trackedSet, std::vector<llvm::Value *> *srcSet, std::vector<llvm::Value *> *targetSet, CallGraphPath *allocPath, CallGraphPath *copyPath) {
    CallInst *allocCI = dyn_cast<CallInst>(alloc);
    CallInst *copyCI = dyn_cast<CallInst>(copy);
    Type *allocType;
    Type *copyType;
    int nested_alloc = 1;
    int nested_copy = 1;
    Value *vAlloc;
    Value *vCopy;
    
    vAlloc = dataflowCrossTraceAllocationControlStruct(alloc, trackedSet, srcSet, targetSet, allocPath);
    //outs()<<"vAlloc Build Done\n";
    vCopy = dataflowCrossTraceCopyWriteControlStruct(copy, trackedSet, srcSet, targetSet, copyPath);
    //outs()<<"vCopy Build Done\n"; 
	allocType = getApiType(dyn_cast<CallInst>(vAlloc));
	copyType = getApiType(dyn_cast<CallInst>(vCopy));
	//outs()<<"allocType => "<<*allocType<<"\n";
	//outs()<<"copyType => "<<*copyType<<"\n";
	
	// We don't need to check if `allocType == copyType` here, because in ifReachable() we make sure they are reachable in dataflow.
	// Example: 
	/*
	%56 = call zeroext i1 @skb_page_frag_refill(i32 %31, %struct.page_frag* %15, i32 3264) #19, !dbg !15743
	...
	%68 = getelementptr inbounds %struct.page_frag, %struct.page_frag* %15, i32 0, i32 0, !dbg !15748
	...
	%92 = load %struct.page*, %struct.page** %68, align 8, !dbg !15751
	...
	%103 = call i64 @copy_page_from_iter(%struct.page* %92, i64 %101, i64 %102, %struct.iov_iter* %2) #19, !dbg !15756
	*/
	outs()<<"\t\t\tControl Stucture => "<<*copyType<<"\n";
	//outs()<<"\t\t\tCopyWrite\t["<<*copyType<<"]\n";
	return;
}


void CallsiteAnalyzer::dataflowForwardTraceControlStruct(Value *V, std::set<llvm::Value* > *trackedSet, std::set<llvm::StoreInst *> *StoreInstSet, std::vector<llvm::Value *> *targetSet) {
    for (auto User : V->users())
    {
	if(trackedSet->find(User) != trackedSet->end())
	{    
	    continue;
	}

	trackedSet->insert(User);

	if(StoreInst *SI = dyn_cast<StoreInst>(User))
	{
	    /*
	    if (StoreInstSet->find(SI) != StoreInstSet->end())
	    {
		break;		    // Try to avoid recursion
	    }
	    */
	    StoreInstSet->insert(SI);

	    Value *SV = SI->getValueOperand();
	    Value *SP = SI->getPointerOperand();

	    for(auto *StoreU : SP->users())
	    {
		if(dyn_cast<LoadInst>(StoreU))		// if found `store` --> `load` pair 
		{
		    dataflowForwardTraceControlStruct(StoreU, trackedSet, StoreInstSet, targetSet);
		}
	    }

	    if(auto *GEP = dyn_cast<GetElementPtrInst>(SP))
	    {
		Value *red_offset = getOffset(GEP);
		Value *red_obj = GEP->getOperand(0);
		for (auto *gepU : GEP->users())		    
		{
		    if (auto *gepUStore = dyn_cast<StoreInst>(gepU))	// if we found gep -> store, then we may find the target control struct used by them.
		    {	
			targetSet->push_back(SP);
			// save <GEP, gepuStore> to targetSet, and compare the type of GEP
		    }
		}
	    }
	}
	else if(dyn_cast<GetElementPtrInst>(User) || dyn_cast<ICmpInst>(User) || dyn_cast<BranchInst>(User) || dyn_cast<BinaryOperator>(User))
	{
	    dataflowForwardTraceControlStruct(User, trackedSet, StoreInstSet, targetSet);
	}
	else if(dyn_cast<CallInst>(User) || dyn_cast<CallBrInst>(User) || dyn_cast<SwitchInst>(User) || dyn_cast<ReturnInst>(User))
	{
	    //outs()<<"[SKIP] => "<<*User<<"\n";
	    continue;
	}
	else if(dyn_cast<SExtInst>(User) || dyn_cast<ZExtInst>(User) || dyn_cast<TruncInst>(User))
	{
	    dataflowForwardTraceControlStruct(User, trackedSet, StoreInstSet, targetSet);
	}
	else if(dyn_cast<PHINode>(User) || dyn_cast<SelectInst>(User) || dyn_cast<LoadInst>(User) || dyn_cast<UnaryInstruction>(User))
	{
	    dataflowForwardTraceControlStruct(User, trackedSet, StoreInstSet, targetSet);
	}
	else 
	{
	    errs() << "\nForwardTrace Fatal errors , please handle [" << *User << "]\n";
	}
    }
    //return;
}

bool CallsiteAnalyzer::structContainsStruct(llvm::StructType* outerStruct, llvm::StructType* innerStruct) {
    if (!outerStruct || !innerStruct) return false;

    for (unsigned i = 0; i < outerStruct->getNumElements(); ++i) {
        llvm::Type* elementType = outerStruct->getElementType(i);
        
        if (elementType == innerStruct) {
            return true;
        }

        if (elementType->isPointerTy() && elementType->getPointerElementType() == innerStruct) {
            return true;
        }

        if (llvm::StructType* nestedStruct = llvm::dyn_cast<llvm::StructType>(elementType)) {
            if (structContainsStruct(nestedStruct, innerStruct)) {
                return true;
            }
        }
    }

    return false;
}

llvm::Instruction* CallsiteAnalyzer::findStructPointerForward(llvm::Instruction* currentInst) {
    if (!currentInst) return nullptr;

    if (auto* callInst = llvm::dyn_cast<llvm::CallInst>(currentInst)) {
        if (callInst->getType()->isPointerTy()) {
            for (auto* user : callInst->users()) {
                if (auto* userInst = llvm::dyn_cast<llvm::Instruction>(user)) {
                    llvm::Instruction* result = findStructPointerForward(userInst);
                    if (result) return result;
                }
            }
        }
    }

    if (auto* gepInst = llvm::dyn_cast<llvm::GetElementPtrInst>(currentInst)) {
        if (gepInst->getPointerOperandType()->getPointerElementType()->isStructTy()) {
            return gepInst;
        }
    } else if (auto* bitcastInst = llvm::dyn_cast<llvm::BitCastInst>(currentInst)) {
        if (bitcastInst->getDestTy()->getPointerElementType()->isStructTy()) {
            return bitcastInst;
        }
    }


    if (auto* brInst = llvm::dyn_cast<llvm::BranchInst>(currentInst)) {
        if (brInst->isConditional()) {
            llvm::BasicBlock* falseBlock = brInst->getSuccessor(1);
            llvm::Instruction* foundInFalse = findStructPointerForward(falseBlock->getFirstNonPHIOrDbgOrLifetime());
            llvm::BasicBlock* trueBlock = brInst->getSuccessor(0);
            llvm::Instruction* foundInTrue = findStructPointerForward(trueBlock->getFirstNonPHIOrDbgOrLifetime());
            return foundInFalse ? foundInFalse : foundInTrue;
        }
    }

    return findStructPointerForward(currentInst->getNextNode());
}

llvm::StructType* CallsiteAnalyzer::fixStructType(llvm::StructType* structType, llvm::Value* toFixValue) {
	outs()<<*structType<<" ---> "<<*toFixValue<<"\n";
}
llvm::Value* CallsiteAnalyzer::findAllocationControlStructureForward(llvm::Function* targetFunction, const std::string& subsystem, CallerMap &Callers) {
    if (!targetFunction) return nullptr;

    std::queue<llvm::Value *> analysisQueue;
    std::set<llvm::Value *> visited;

	llvm::Function* preFunction = nullptr;
	llvm::Value* lastValue = nullptr;

	Module *moduleNow = targetFunction->getParent();
	//outs()<<"moduleNow => "<<moduleNow->getName()<<"\n";

	retry:
    for (auto& BB : *targetFunction) {
        for (auto& I : BB) {
            if (llvm::CallInst* callInst = llvm::dyn_cast<llvm::CallInst>(&I)) {
				//outs()<<"\tcheck callInst ==> "<<*callInst<<"\n";
                if (isCall2Alloc(callInst)) {
                    llvm::Function* calledFunction = callInst->getCalledFunction();
                    if (calledFunction && 
                        !calledFunction->getName().startswith("k") &&
                        !calledFunction->getName().startswith("__k")) {
                        analysisQueue.push(callInst);		// we don't need kmalloc/kcalloc/kzalloc and etc...
                    }
                } else if (preFunction && callInst->getCalledFunction() == preFunction) {
					//outs()<<"in Upper function => "<<*callInst<<"\n";
					analysisQueue.push(callInst);		//retry hit;
				} else if ((callInst->getCalledFunction() && (!callInst->getCalledFunction()->getName().find(subsystem) || !callInst->getCalledFunction()->getName().find("bpf"))) && (callInst->getCalledFunction()->getName().contains("alloc") || callInst->getCalledFunction()->getName().contains("create") || callInst->getCalledFunction()->getName().contains("init")))
				{	
					//outs()<<"enter => "<<callInst->getCalledFunction()->getName()<<"\n";	
					std::set<llvm::Value *> visited;
					if (hasLowerDirectPageAllocCall(callInst,subsystem, Callers, visited)) {
						// assume here a related subsystem wrapper function is used to allocate memory.
						//outs()<<"find a call => "<<*callInst<<"\n";
						return callInst;
						analysisQueue.push(callInst);
					} 
					//if (CallInst) 
					//outs()<<"reset => "<<callInst->getCalledFunction()->getName()<<"\n";
					// else if (Funcs[callInst->getCalledFunction()->getName().str()]) {
					// 	Function* exportFunction = Funcs[callInst->getCalledFunction()->getName().str()];
					// 	outs()<<"may be another module => "<< exportFunction->getParent()->getName()<<"\n"; 
					// }
					if (callInst->getCalledFunction()->empty() && !callInst->getCalledFunction()->getName().contains("kzalloc")){
						//outs()<<"empty => "<<callInst->getCalledFunction()->getName()<<"\n";
						
						if (Funcs[callInst->getCalledFunction()->getName().str()]) {
								Function* exportFunction = Funcs[callInst->getCalledFunction()->getName().str()];
								//outs()<<"may be another module => "<< exportFunction->getParent()->getName()<<"\n"; 
								for (auto &BB : *exportFunction) {
       									 for (auto& I : BB) {
											if (llvm::CallInst* innerCallInst = llvm::dyn_cast<llvm::CallInst>(&I)) {
												
												if(innerCallInst->getCalledFunction() && innerCallInst->getCalledFunction()->getName().contains("alloc") && !innerCallInst->getCalledFunction()->getName().contains("kzalloc") && !innerCallInst->getCalledFunction()->getName().contains("kcalloc")){
													//outs()<<"deep innerCallInst => "<<*innerCallInst<<"\n";
												
												if (hasLowerDirectPageAllocCall(innerCallInst,subsystem, Callers, visited)) {
													// assume here a related subsystem wrapper function is used to allocate memory.
														// better filter by module name.
														if (callInst->getCalledFunction()->getName().contains("bpf") && callInst->getParent()->getParent()->getName().contains("xsk")) {
															//outs()<<"filter => "<<callInst->getCalledFunction()->getName()<<" in "<<callInst->getParent()->getParent()->getName()<<"\n";
															continue;
														}

														//outs()<<"find a critical call => "<<*callInst<<"\n";		// don't return inner call, because inner call's return value could be corrupt.
														return callInst;
														//analysisQueue.push(callInst);
													}

												}
											}
									}
								}
								// nothing in another
								continue;

						}
					}
					targetFunction = callInst->getCalledFunction();
					goto retry;	
					//continue;//?
					// do a fast search.
					//analysisQueue.push(callInst);
				} 
            }
        }
    }

    while (!analysisQueue.empty()) {
        llvm::Value *current = analysisQueue.front();
        analysisQueue.pop();



        if (!visited.insert(current).second) {
            continue;
        }


		// if(targetFunction->getName() == "io_allocate_scq_urings" && isa<Instruction>(current)) {
		// 	outs()<<"current => "<<*current<<"\n";
		// }

		//outs()<<"current => "<<*current<<"\n";
        if (llvm::GetElementPtrInst *gepInst = llvm::dyn_cast<llvm::GetElementPtrInst>(current)) {
            llvm::Type* operandType = gepInst->getPointerOperandType()->getPointerElementType();
            if (operandType->isStructTy()) {
                llvm::StructType* structType = llvm::dyn_cast<llvm::StructType>(operandType);
				//outs()<<structType->getName()<<"\n";
                if (structType && structType->hasName() && structType->getName().startswith("struct."+subsystem)) {
					//outs()<<"find => "<<*gepInst<<"\n";
                    return gepInst;
                }
            }
            analysisQueue.push(gepInst->getPointerOperand());
            continue;
        }
		// if some alloc function in instruction.
		if (llvm::CallInst *callInst = llvm::dyn_cast<llvm::CallInst>(current)) {
			if (callInst->getCalledFunction()->getName() == "__get_free_pages") {
				analysisQueue.push(callInst->getOperand(1));
				continue;
        	} else  if (callInst->getCalledFunction()->getName() == "get_order") {
				analysisQueue.push(callInst->getOperand(0));
				continue;
        	}
		}

        for (auto user : current->users()) {
            if (llvm::Instruction *userInst = llvm::dyn_cast<llvm::Instruction>(user)) {
                // 处理 StoreInst
                if (llvm::StoreInst *storeInst = llvm::dyn_cast<llvm::StoreInst>(userInst)) {
                    llvm::Value *storeAddress = storeInst->getPointerOperand();
					//outs()<<"store => "<<*storeInst<<"\tstoreAddress => "<<*storeAddress<<"\n";
                    analysisQueue.push(storeAddress);
                    continue;
                }

                // ...

                analysisQueue.push(userInst);
            }
        }

		lastValue = current;
    }

	if(lastValue) {
		//outs()<<"lastValue => "<<*lastValue<<"\n";
		for (auto &arg : targetFunction->args()) {
        if (lastValue == &arg) {		// finish all trace in this function.
            auto callers = Callers[targetFunction];
            for (auto caller : callers) {
                llvm::Function* parentFunction = caller->getParent()->getParent();
				preFunction = targetFunction;
				targetFunction = parentFunction; 
				//outs()<<"parentFunction => "<<parentFunction->getName()<<"\n";
				goto retry;
            
			}
            break;
        }
    }
	}

    return nullptr;
}


llvm::Value* CallsiteAnalyzer::findRemapControlStructureBackward(llvm::Value* startingPoint, std::string subsystem) {
    std::queue<llvm::Value *> analysisQueue;
    std::set<llvm::Value *> visited;
    analysisQueue.push(startingPoint);
	Function *targetFunction;
	
	if (isa<Instruction>(startingPoint)) {
		targetFunction = dyn_cast<Instruction>(startingPoint)->getParent()->getParent();
	}
	
	//outs()<<"searching in subsystem => "<<subsystem<<"\n";

    while (!analysisQueue.empty()) {
        llvm::Value *current = analysisQueue.front();
        analysisQueue.pop();

        if (!visited.insert(current).second) {
            continue;
        }

		//outs()<<"current => "<<*current<<"\n";
        if (llvm::CallInst *callInst = llvm::dyn_cast<llvm::CallInst>(current)) {
			//outs()<<"current CallInst => "<<*current<<"\n";
            if (callInst->getCalledFunction() && callInst->getNumOperands() > 0) {
                if (callInst->getCalledFunction()->getName() == "pgv_to_page" ) {
					// remapping function (struct X ==> page)
					llvm::Value *newStartingPoint = callInst->getArgOperand(0);
					analysisQueue.push(newStartingPoint);
					continue;
				} else if (callInst->getCalledFunction() &&  
                       callInst->getCalledFunction()->getName().rfind(subsystem+"_map") != std::string::npos) {
					   // Caculate the address of.
					   //outs()<<"found a wrapper map/kaddr function => "<<*callInst<<"\n";
					   llvm::Value *newStartingPoint = callInst->getArgOperand(0);
					   analysisQueue.push(newStartingPoint);
					   continue;
				} 
            }
			//outs()<<"miss CallInst => "<<*callInst<<"\n";
        }

        if (llvm::GetElementPtrInst *gepInst = llvm::dyn_cast<llvm::GetElementPtrInst>(current)) {
			// if(subsystem == "xsk")
			// 		outs()<<"gepInst => "<<*gepInst<<"\n";
            llvm::Type* operandType = gepInst->getPointerOperandType()->getPointerElementType();
            if (operandType->isStructTy()) {
                llvm::StructType* structType = llvm::dyn_cast<llvm::StructType>(operandType);
				//outs()<<structType->getName()<<"\n";
                if (structType && structType->hasName() && structType->getName().startswith("struct."+subsystem)) {
                    return gepInst;
                } else if (structType && structType->hasName() && structType->getName().startswith("struct.bpf_"+subsystem)) {
                    return gepInst;
                }
            }
            analysisQueue.push(gepInst->getPointerOperand());
            continue;
        }

        if (llvm::PHINode *phiNode = llvm::dyn_cast<llvm::PHINode>(current)) {
			//outs()<<*phiNode<<"\n";
            for (unsigned i = 0; i < phiNode->getNumIncomingValues(); ++i) {
                llvm::Value *incomingValue = phiNode->getIncomingValue(i);
                analysisQueue.push(incomingValue);
            }
        }

		if (llvm::LoadInst *loadInst = llvm::dyn_cast<llvm::LoadInst>(current)) {
            llvm::Value *newStartingPoint = loadInst->getPointerOperand();
            analysisQueue.push(newStartingPoint);
            continue;
        }

        if (llvm::BitCastInst *bitCastInst = llvm::dyn_cast<llvm::BitCastInst>(current)) {
			//outs()<<*bitCastInst<<"\n";
            llvm::Value *newStartingPoint = bitCastInst->getOperand(0);
            analysisQueue.push(newStartingPoint);
            continue;
        }

        if (llvm::ReturnInst *retInst = llvm::dyn_cast<llvm::ReturnInst>(current)) {
            if (retInst->getNumOperands() > 0) {
                llvm::Value *returnOperand = retInst->getOperand(0);
                analysisQueue.push(returnOperand);
                continue;
            }
        }

        if (llvm::Instruction *inst = llvm::dyn_cast<llvm::Instruction>(current)) {
            for (auto user : inst->users()) {
                if (llvm::Instruction *userInst = llvm::dyn_cast<llvm::Instruction>(user)) {
                    analysisQueue.push(userInst);
                }
            }
        }
		
		// sometimes we may meet a constant value.(like the param of function)
    	if (llvm::Argument* arg = llvm::dyn_cast<llvm::Argument>(current)) {
			outs() << "current is a function argument: " << *arg << "\n";
			if (targetFunction && arg->getParent() == targetFunction) {
				//outs() << "Finished backward analysis: current is an argument of the target function.\n";
				return arg;
			}
   		}
    }


   if (analysisQueue.empty()) {
        if (llvm::Instruction *inst = llvm::dyn_cast<llvm::Instruction>(startingPoint)) {
            if (llvm::BinaryOperator *binaryOp = llvm::dyn_cast<llvm::BinaryOperator>(inst)) {
                for (unsigned i = 0; i < binaryOp->getNumOperands(); ++i) {
                    llvm::Value *operand = binaryOp->getOperand(i);
                    if (llvm::CallInst *callInst = llvm::dyn_cast<llvm::CallInst>(operand)) {
                        if (callInst->getCalledFunction() && 
                            callInst->getCalledFunction()->getName() == "virt_to_phys" &&
                            callInst->getNumOperands() > 0) {
							llvm::Value *virtToPhysArg = callInst->getArgOperand(0);
							if (llvm::CallInst *nestCall = dyn_cast<CallInst>(virtToPhysArg)) {
								if (nestCall->getOperand(0) == &*(nestCall->getParent()->getParent()->arg_begin())) {
									//outs()<<"virt_to_phys => "<<*nestCall<<"\n";
									    for (auto& BB : *nestCall->getCalledFunction()) {
											if (llvm::ReturnInst* RI = llvm::dyn_cast<llvm::ReturnInst>(BB.getTerminator())) {
												//returnInstructions.push_back(RI);
												//outs()<<"return => "<<*RI<<"\n";
												return findRemapControlStructureBackward(RI, subsystem);
											}
										}
								}
							}
							if (llvm::BitCastInst *bitcast = dyn_cast<BitCastInst>(virtToPhysArg)) {
								//outs()<<"bitcast => "<<*bitcast->getOperand(0)<<"\n";
								return findRemapControlStructureBackward(bitcast->getOperand(0), subsystem);
							}
							outs()<<"virt_to_phys => "<<*virtToPhysArg<<"\n";
							analysisQueue.push(virtToPhysArg);
							break;
                        } 
                    }
                }
            }
        } 
    }
	
	out:
    return nullptr;
}

void CallsiteAnalyzer::dataflowBackwardTraceControlStruct(Value *V, std::set<llvm::Value* > *trackedSet, std::vector<llvm::Value *> *srcSet, std::vector<llvm::Value *> *targetSet) {


    if (trackedSet->count(V) != 0)
    {
	return;		    // We need to make sure that it won't cause recursive backtrace, which could be a problem when handling `phi`
    }
    
    trackedSet->insert(V);

    if (CallInst* CI = dyn_cast<CallInst>(V)) 
    {

	Function *callee = CI->getCalledFunction();
	if (callee->getName().rfind("vm_insert_page") != -1)
	{
	    Value* page = CI->getOperand(2);
	    dataflowBackwardTraceControlStruct(page,trackedSet, srcSet, targetSet);
        }
	else if (callee->getName().rfind("vm_iomap_memory") != -1 || callee->getName().rfind("remap_vmalloc_range") != -1 )
	{
	    Value* page = CI->getOperand(1);
	    dataflowBackwardTraceControlStruct(page,trackedSet, srcSet, targetSet);
	}
	else if (callee->getName().rfind("pgv_to_page") != -1 || callee->getName().rfind("pkt_sk") != -1 || callee->getName().rfind("file_fb_info") != -1 || callee->getName().rfind("array_map_vmalloc_addr") != -1 )
	{
	   Value* v = CI->getOperand(0);
	   dataflowBackwardTraceControlStruct(v,trackedSet, srcSet, targetSet);
	}
	else if (callee->getName().rfind("remap_pfn_range") != -1)
	{
	   Value *v = CI->getOperand(2);
	   dataflowBackwardTraceControlStruct(v,trackedSet, srcSet, targetSet);
	}
	else if (callee->getName().rfind("virt_to_phys") != -1 || callee->getName().rfind("__phys_addr_nodebug") != -1)
	{
	   dataflowBackwardTraceControlStruct(CI->getOperand(0), trackedSet, srcSet, targetSet); 
	}
	else if (callee->getName().rfind("memcpy_from_msg") != -1)
	{
	    dataflowBackwardTraceControlStruct(CI->getOperand(0), trackedSet, srcSet, targetSet); 
	}
	else if (callee->getName().rfind("ip_hdr") != -1)
	{
	    srcSet->push_back(V);		// if find a ip_hdr, the arg is `skb`
	    return;
	}
	else if (callee->getName().rfind("io_uring_validate_mmap_request") != -1)		// We need to trace the inst in `io_uring_validate_mmap_request`, ptr is returned by here.
	{
	    for (const BasicBlock &BB : *callee)
	    {
		for(const Instruction &I : BB)
		{
		    if(const ReturnInst *RI = dyn_cast<ReturnInst>(&I))
		    {
			if(Value *rValue = RI->getReturnValue())
			{
			    dataflowBackwardTraceControlStruct(rValue, trackedSet, srcSet, targetSet);	// we need to trace `ret`
			}
		    }
		}
	    }
	}
	else if (callee->getName().rfind("ERR_PTR") != -1)
	{
	    
	}
	else if (isCall2Alloc(CI))
	{
	    outs()<<"backward find AllocAPIS => \t"<<*CI<<"\n";

	    for (auto i : CI->users())
	    {
		//outs()<<"Alloc Users() => \t"<<*i<<"\n";
	    }
	}
	else if (callee->getName().rfind("xdp_sk") != -1)
	{
	    return;
	}
	else
	{
	    outs()<<"\t[BackwardTraceControlStruct Unknow Call] => "<<*CI<<"\n";
	}

	return;
    }

    if (BitCastInst *BCI = dyn_cast<BitCastInst>(V))
    {
	dataflowBackwardTraceControlStruct(BCI->getOperand(0), trackedSet, srcSet, targetSet);
    }

    if (dyn_cast<GlobalVariable>(V)) 
    {
    }

    if (ConstantExpr* CE = dyn_cast<ConstantExpr>(V)) 
    {
	//outs()<<*CE<<"\n";
    }

    if (Argument* A = dyn_cast<Argument>(V)) 
    {
	srcSet->push_back(V);
    }

    if (LoadInst* LI = dyn_cast<LoadInst>(V)) 
    {
	Function *F = LI->getFunction();
	if(!F) return;
	
	srcSet->push_back(V);
	dataflowBackwardTraceControlStruct(LI->getPointerOperand(), trackedSet, srcSet, targetSet);
	return;
    }

    if (StoreInst* SI = dyn_cast<StoreInst>(V)) 
    {
	//outs()<<*SI<<"\n";
    }

    if (SelectInst* SI = dyn_cast<SelectInst>(V)) 
    {
	//outs()<<*SI<<"\n";
    }

    if (GetElementPtrInst* GEP = dyn_cast<GetElementPtrInst>(V)) 
    {
	srcSet->push_back(V);
	//outs()<<*GEP<<"\n";
	dataflowBackwardTraceControlStruct(GEP->getPointerOperand(),trackedSet, srcSet, targetSet);
	return;
    }

    if (PHINode* PN = dyn_cast<PHINode>(V)) 
    {
	//srcSet->push_back(V);
	//outs()<<*PN<<"\n";
	for (unsigned i = 0, e = PN->getNumIncomingValues(); i != e; i++) 
	{
	    //outs()<<"PHINode :"<<i<<"\n";
	    Value* IV = PN->getIncomingValue(i);
	    //outs()<<*IV<<"\n";
	    dataflowBackwardTraceControlStruct(IV, trackedSet, srcSet, targetSet);
	}
	return;
    }

    if (ICmpInst* ICmp = dyn_cast<ICmpInst>(V)) 
    {
	//outs()<<*ICmp<<"\n";
    }

    if (BinaryOperator* BO = dyn_cast<BinaryOperator>(V)) 
    {
	//outs()<<"BO => "<<*BO<<"\n";
	dataflowBackwardTraceControlStruct(BO->getOperand(0), trackedSet, srcSet, targetSet);	
    }

    if (UnaryInstruction* UI = dyn_cast<UnaryInstruction>(V)) 
    {
	//outs()<<*UI<<"\n";
	return;
    }

    return;
}
void CallsiteAnalyzer::collectStructInfo(llvm::Module *M, std::set<Function *> *mmapRefListPtr) {
  
    //if (M->getName().rfind("bpf/ringbuf.c") == -1){return;}
	for (auto GV=M->global_begin();GV!=M->global_end();GV++)
	{
              GlobalVariable *GVPtr=&*GV;
	      if (GVPtr->hasInitializer())// && (GVPtr->hasPrivateLinkage()||GVPtr->hasInternalLinkage()))
	      {
		    if (GVPtr->getName().rfind("ops") != -1)
		    {
			if (ConstantStruct *CS=dyn_cast<ConstantStruct>(GVPtr->getInitializer()))
			{
			    int globalNums = CS->getNumOperands();
			    for (int i = 0 ; i < globalNums ; i++)
			    {
				llvm::Value* v = CS->getOperand(i);
				if (llvm::isa<llvm::Function>(v) && (v->getName().rfind("_mmap") != -1))
				{
				    Function *F = dyn_cast<llvm::Function>(v);
				    //outs()<<F->getName()<<"\n";
				    //if (mmapRefListPtr->count(F) == 0)	
					mmapRefListPtr->insert(F);
				}
			    }
			}
		    }
	      }
	}
}
