set(KPSource KPSMain.cc Annotation.cc CallsiteAnalyzer.cc CallGraph.cc)

    #Annotation.cc StructAnalyzer.cc CallGraph.cc CredAnalyzer.cc)

#Build libraries.
#add_library(KAObj OBJECT ${KASource})
#add_library(KAShared SHARED $ <TARGET_OBJECTS : KAObj>)
#add_library(KAStatic STATIC $ <TARGET_OBJECTS : KAObj>)

#Build executable, analyzer.
    set(EXECUTABLE_OUTPUT_PATH ${KPS_BINARY_DIR})
	link_directories(${KPS_BINARY_DIR} / lib)
	    add_executable(kpsanalyzer ${KPSource})
                target_link_libraries(kpsanalyzer LLVMAsmParser LLVMSupport
                                          LLVMCore LLVMAnalysis LLVMIRReader)
#KAStatic
#)
