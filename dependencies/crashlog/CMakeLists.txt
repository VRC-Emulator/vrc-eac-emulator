message(STATUS "Fetching crashlog...")

FetchContent_Declare(
  crashlog
  GIT_REPOSITORY https://github.com/huzun1/crashlog
  GIT_TAG        main
)

FetchContent_MakeAvailable(crashlog)