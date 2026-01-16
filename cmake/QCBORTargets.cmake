# QCBORTargets.cmake

add_library(QCBOR::QCBOR UNKNOWN IMPORTED)

set_target_properties(QCBOR::QCBOR PROPERTIES
  IMPORTED_LOCATION "${_QCBOR_LIBRARY}"
  INTERFACE_INCLUDE_DIRECTORIES "${_QCBOR_INCLUDE_DIR}"
)

# Optional extra system libs (translated from EXTRA_LIBS)
if (_QCBOR_EXTRA_LIBS)
  target_link_libraries(QCBOR::QCBOR
    INTERFACE ${_QCBOR_EXTRA_LIBS}
  )
endif()
