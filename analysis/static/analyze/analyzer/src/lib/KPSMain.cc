/*
 * main function
 *
 * Copyright (C) 2012 Xi Wang, Haogang Chen, Nickolai Zeldovich
 * Copyright (C) 2015 Byoungyoung Lee
 * Copyright (C) 2015 - 2019 Chengyu Song
 * Copyright (C) 2016 Kangjie Lu
 * Copyright (C) 2019 Yueqi Chen
 *
 * For licensing details see LICENSE
 */

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/ManagedStatic.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/PrettyStackTrace.h>
#include <llvm/Support/Signals.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/SystemUtils.h>
#include <llvm/Support/ToolOutputFile.h>
#include<algorithm>
#include <memory>
#include <sstream>
#include <sys/resource.h>
#include <vector>


#include "Common.h"
#include "GlobalCtx.h"
#include "CallGraph.h"

using namespace llvm;

cl::list<std::string> InputFilenames(cl::Positional, cl::OneOrMore, cl::desc("<input bitcode files>"));



GlobalContext GlobalCtx;


void IterativeModulePass::run(ModuleList &modules) {

    ModuleList::iterator i, e;

    outs()<<"Initializing "<< modules.size() << " modules.\n";


    bool again = false;
    while (again) {
	again = false;
	for (i = modules.begin(), e = modules.end(); i != e; ++i) {
	outs() << "[" << i->second << "]\n";

	    again |= doInitialization(i->first);
	}
    }

    outs() << "[" << ID << "] Processing " << modules.size() << " modules.\n";
    unsigned iter = 0, changed = 1;
    while (changed) {
	++iter;
	changed = 0;
	for (i = modules.begin(), e = modules.end(); i != e; ++i) {
	    //outs() << "[" << ID << " / " << iter << "] ";
	    // FIXME: Seems the module name is incorrect, and perhaps it's a bug.
	    //outs() << "[" << i->second << "]\n";

	    bool ret = doModulePass(i->first);
	    if (ret) {
		++changed;
		//outs() << "\t [CHANGED]\n";
	    } else {
		//outs() << "\n";
	    }
	}
	//outs() << "[" << ID << "] Updated in " << changed << " modules.\n";
    }

    outs() << "[" << ID << "] Finalizing " << modules.size() << " modules.\n";
   
    // For every module, we will use doFinalization, it will scan the functions in files and pick up every `call` and use `call` to find out the called functions `CF` in FuncSet saved in Map Callees[CI] and insert the `call` insts for every callers.
    again = true;
    while (again) {
	again = false;
	for (i = modules.begin(), e = modules.end(); i != e; ++i) {
	    again |= doFinalization(i->first);
	}
    }
    
    outs() << "[" << ID << "] Done!\n\n";
    
    return;

}


void doBasicInitialization(Module *M) {
  // callsite analysis
  //GlobalCtx.callsiteAnalyzer.run(M, &(M->getDataLayout()));
  
  //if (VerboseLevel >= 2)
  //  GlobalCtx.callsiteAnalyzer.printCallsiteInfo();

  // collect global object definitions
  for (GlobalVariable &G : M->globals()) {
    if (G.hasExternalLinkage())
    {
      GlobalCtx.Gobjs[G.getName().str()] = &G;
      //outs()<<G.getName()<<"\n";
    } 
    //outs()<<G.getName()<<"\n";
 }

  // collect global function definitions
  for (Function &F : *M) {
    if (F.hasExternalLinkage() && !F.empty()) {
            // external linkage always ends up with the function name
            StringRef FNameRef = F.getName();
            std::string FName = "";
            if (FNameRef.startswith("__sys_"))
                FName = "sys_" + FNameRef.str().substr(6);
            else
                FName = FNameRef.str();
            //fprintf(stdout, "FName: %s\n", FName.c_str());
	    // assert(GlobalCtx.Funcs.count(FName) == 0); // force only one defintion
            GlobalCtx.Funcs[FName] = &F;
        }
    }

  return;
}


void Preparation(){
 
    
    struct rlimit rl;
    if (getrlimit(RLIMIT_STACK, &rl) == 0) {
	rl.rlim_cur = 64L * 1024L * 1024L;
	setrlimit(RLIMIT_STACK, &rl);
    }
    

    //sys::PrintStackTraceOnErrorSignal(StringRef());

    llvm_shutdown_obj Y;
}

void dumpMmapRef() {
    for (auto &F : GlobalCtx.mmapRefList)
    {
	outs()<<F<<" => "<<F->getName()<<"\n";
    }
}

std::vector<std::pair<llvm::Module *, llvm::StringRef>> global_modules;
int main(int argc, char **argv)
{

    #define SET_STACK_SIZE 64L * 1024L * 1024L
    #ifdef SET_STACK_SIZE
    struct rlimit rl;
    if (getrlimit(RLIMIT_STACK, &rl) == 0) {
	rl.rlim_cur = SET_STACK_SIZE;
	setrlimit(RLIMIT_STACK, &rl);
    }
    #endif

    // Print a stack trace if we signal out.
    #if LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR < 9
    sys::PrintStackTraceOnErrorSignal();
    #else
    sys::PrintStackTraceOnErrorSignal(StringRef());
    #endif
    PrettyStackTraceProgram X(argc, argv);

    // Call llvm_shutdown() on exit.
    llvm_shutdown_obj Y;

    //Preparation();

    SMDiagnostic Err;    
    
    cl::ParseCommandLineOptions(argc, argv, "kernel page spray analysis\n");

    outs()<< "[+] Total " << InputFilenames.size() << " file(s)\n";
   
    

    for (unsigned i = 0; i < InputFilenames.size(); ++i) {
        // Use separate LLVMContext to avoid type renaming 
        LLVMContext *LLVMCtx = new LLVMContext();
        std::unique_ptr<Module> M = parseIRFile(InputFilenames[i], Err, *LLVMCtx);

        if (M == NULL) 
        {
            errs() << argv[0] << ": error loading file '" << InputFilenames[i] << "'\n";
            continue;
        
        }
        //outs() << "\t[" <<i<< "] " << InputFilenames[i] << "\n";

        Module *Module = M.release();
        StringRef MName = StringRef(strdup(InputFilenames[i].data()));
        GlobalCtx.Modules.push_back(std::make_pair(Module, MName));
        GlobalCtx.ModuleMaps[Module] = InputFilenames[i];
        doBasicInitialization(Module);

    }

    outs()<< "[+] Build Seperate LLVMContext Done, start CallGraph analyzing..." << "\n";
    
    CallGraphPass CGPass(&GlobalCtx);
    CGPass.run(GlobalCtx.Modules);

    //std::set<Function *> mmapRefList;
    CallsiteAnalyzer CA;
    for (auto &i : GlobalCtx.Modules)
    {
	CA.collectStructInfo(i.first, &GlobalCtx.mmapRefList);
    }
    outs()<<"collectStructInfo done\n";

    CA.global_modules = GlobalCtx.Modules;
    CA.Funcs = GlobalCtx.Funcs; 
    
    outs()<<"func => "<<*GlobalCtx.Funcs["bpf_map_area_alloc"]<<"\n"<<GlobalCtx.Funcs["bpf_map_area_alloc"]->getParent()->getName()<<"\n";
    //outs()<<"func => "<<*GlobalCtx.Funcs["__bpf_map_area_alloc"]<<"\n"<<GlobalCtx.Funcs["__bpf_map_area_alloc"]->getParent()->getName()<<"\n";

   CGPass.zerocopyAnalyze("vm_insert_page", &GlobalCtx.mmapRefList, &CA);
   CGPass.zerocopyAnalyze("remap_pfn_range", &GlobalCtx.mmapRefList, &CA);	//CGPass.zerocopyAnalyze("remap_pfn_range", &GlobalCtx.mmapRefList, &CA);
   CGPass.zerocopyAnalyze("remap_vmalloc_range", &GlobalCtx.mmapRefList, &CA);


    //CGPass.crossAnalyze("sock_alloc_send_pskb", "skb_copy_datagram_from_iter", &CA);
    //CGPass.crossAnalyze("skb_page_frag_refill","copy_page_from_iter",&CA);
    //CGPass.crossAnalyze("alloc_pages", "copy_page_from_iter", &CA);
    //CGPass.crossAnalyze("alloc_pages", "memcpy_from_msg", &CA);
    //CGPass.crossAnalyze("__get_free_page", "copy_page_from_iter", &CA);
    
    
    //dumpMmapRef(); 
    return 0;
}
