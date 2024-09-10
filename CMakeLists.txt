
include_directories(${CMAKE_CURRENT_LIST_DIR}/../../src/modules/common/include)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../../thirds/glog/include)
link_directories(${CMAKE_CURRENT_LIST_DIR}/../../thirds/glog/lib)

set(LIB_SRC
        ${CMAKE_CURRENT_LIST_DIR}/../../src/modules/common/src/glog_fmt.cpp
)

add_library(sim STATIC ${LIB_SRC})

set(LIBS
        sim
        ${GLOG_LIB}
)

add_executable(sim_manager main.cpp)
add_dependencies(sim_manager sim)
target_link_libraries(sim_manager ${LIBS})
