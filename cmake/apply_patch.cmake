# Applies PATCH to SRC, skipping it if it is already applied.
#
# FetchContent re-runs PATCH_COMMAND whenever it re-checks out a dependency, and
# a second `git apply` of the same patch fails -- so test for it first.

execute_process(
	COMMAND git apply --reverse --check "${PATCH}"
	WORKING_DIRECTORY "${SRC}"
	RESULT_VARIABLE already_applied
	OUTPUT_QUIET ERROR_QUIET)

if(already_applied EQUAL 0)
	message(STATUS "patch already applied: ${PATCH}")
	return()
endif()

execute_process(
	COMMAND git apply "${PATCH}"
	WORKING_DIRECTORY "${SRC}"
	RESULT_VARIABLE rc
	ERROR_VARIABLE err)

if(NOT rc EQUAL 0)
	message(FATAL_ERROR "failed to apply ${PATCH}:\n${err}")
endif()

message(STATUS "applied patch: ${PATCH}")
