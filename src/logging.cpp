#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/cfg/helpers.h>

#include "logging.h"

namespace {
  std::once_flag onceFlag;
  bool isLoggerSetup = false;
  bool initializationError = false;
  const char* initializationErrorMessage = "\0";

  std::string GetExeName() {
    char exeName[MAX_PATH];
    GetModuleFileName(nullptr, exeName, MAX_PATH);
    return exeName;
  }

  void SetupLogger() {
    TCHAR envLogLevel[32767];
    GetEnvironmentVariable("SAFEDISCSHIM_LOGLEVEL", envLogLevel, sizeof(envLogLevel));

    if ( GetLastError() == ERROR_ENVVAR_NOT_FOUND ) {
#ifdef _DEBUG
      spdlog::set_level(spdlog::level::debug);
      spdlog::flush_on(spdlog::level::debug);
#else
      // don't output logs if envvar is not defined
      return;
#endif
    }
    else spdlog::cfg::helpers::load_levels(envLogLevel);

    // return early if logs are off, so files are not created
    if ( spdlog::get_level() == spdlog::level::off )
      return;

    const std::string loggerFileName = GetExeName() + "_safediscshim.log";
    const auto logger = spdlog::basic_logger_mt("SafeDiscShim",
      loggerFileName, true);
    spdlog::set_default_logger(logger);
    logger->info("SafeDiscShim"); // TODO: make this grab the version number

    /* we can't output to the log during initialization due to DllMain
     * restrictions, so do it now */
    if( initializationError )
      logger->critical("{}", initializationErrorMessage);

    isLoggerSetup = true;
  }
}

void logging::SetupLoggerIfNeeded() {
  if ( !isLoggerSetup )
    std::call_once(onceFlag, SetupLogger);
}

void logging::SetInitializationError(const char* message) {
  /* NOTE: This function is designed to be called from DllMain, make sure it
   * does not do anything forbidden! */
  initializationError = true;
  initializationErrorMessage = message;
}
