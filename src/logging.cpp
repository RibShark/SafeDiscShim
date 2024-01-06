#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/cfg/helpers.h>

#include "logging.h"
#include "version.h"

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
#else
      // don't output logs if envvar is not defined
      return;
#endif
    }
    else spdlog::cfg::helpers::load_levels(envLogLevel);

    // return early if logs are off, so files are not created
    if ( spdlog::get_level() == spdlog::level::off )
      return;

    const auto stdoutLogger = spdlog::stdout_color_mt("stdout");
    spdlog::set_default_logger(stdoutLogger);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
    try {
      const std::string loggerFileName = GetExeName() + "_safediscshim.log";
      const auto logger = spdlog::basic_logger_mt("file",
        loggerFileName, true);
      spdlog::set_default_logger(logger);
    }
    catch (const spdlog::spdlog_ex &ex) {
      spdlog::info("Error logging to file ({}), logging to stdout instead.",
        ex.what());
    }
    spdlog::flush_on(spdlog::level::trace);
    spdlog::info("SafeDiscShim version {}.{}.{}", SAFEDISCSHIM_VERSION_MAJOR,
      SAFEDISCSHIM_VERSION_MINOR, SAFEDISCSHIM_VERSION_PATCH);

    /* we can't output to the log during initialization due to DllMain
     * restrictions, so do it now */
    if( initializationError )
      spdlog::critical("{}", initializationErrorMessage);

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
