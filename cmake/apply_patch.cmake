# Applies each patch in PATCHES to SRC, skipping any that is already applied.
#
# FetchContent re-runs PATCH_COMMAND whenever it re-checks out a dependency, and
# a second `git apply` of the same patch fails -- so test for it first.

foreach(patch IN LISTS PATCHES)
	execute_process(
		COMMAND git apply --reverse --check "${patch}"
		WORKING_DIRECTORY "${SRC}"
		RESULT_VARIABLE already_applied
		OUTPUT_QUIET ERROR_QUIET)

	if(already_applied EQUAL 0)
		message(STATUS "patch already applied: ${patch}")
		continue()
	endif()

	execute_process(
		COMMAND git apply "${patch}"
		WORKING_DIRECTORY "${SRC}"
		RESULT_VARIABLE rc
		ERROR_VARIABLE err)

	if(NOT rc EQUAL 0)
		message(FATAL_ERROR "failed to apply ${patch}:\n${err}")
	endif()

	message(STATUS "applied patch: ${patch}")
endforeach()
