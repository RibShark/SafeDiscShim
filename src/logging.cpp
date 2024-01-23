#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/ringbuffer_sink.h>
#include <spdlog/cfg/helpers.h>

#include "logging.h"
#include "version.h"

namespace {
  auto ringbufferSink = std::make_shared<spdlog::sinks::ringbuffer_sink_mt>(32);
}

void logging::SetupLogger() {
  /* Set log level */
  TCHAR envLogLevel[32767];
  GetEnvironmentVariable("SAFEDISCSHIM_LOGLEVEL", envLogLevel, sizeof(envLogLevel));
  if ( GetLastError() == ERROR_ENVVAR_NOT_FOUND ) {
#ifdef _DEBUG
    spdlog::set_level(spdlog::level::trace);
#else
    // don't output logs if envvar is not defined
    return;
#endif
  }
  else spdlog::cfg::helpers::load_levels(envLogLevel);

  /* Return early if logs are off, so files are not created */
  if ( spdlog::get_level() == spdlog::level::off )
    return;

  /* Log to ringbuffer until we can determine log file name later */
  auto logger = std::make_shared<spdlog::logger>("ringbuffer", ringbufferSink);
  spdlog::set_default_logger(logger);

  spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
  spdlog::flush_on(spdlog::level::trace);

  spdlog::info("SafeDiscShim version {}.{}.{}", SAFEDISCSHIM_VERSION_MAJOR,
    SAFEDISCSHIM_VERSION_MINOR, SAFEDISCSHIM_VERSION_PATCH);
}

void logging::SetLoggerFileName(const std::string& fileName) {
  try {
    const auto logger = spdlog::basic_logger_mt("file",
      fileName, true);
    spdlog::set_default_logger(logger);
  }
  catch (const spdlog::spdlog_ex &ex) {
    spdlog::info("Error logging to file ({}), logging to stdout instead.",
      ex.what());
  }

  // temporarily remove formatting since ringbuffer logs are already formatted
  spdlog::set_pattern("%v");

  std::vector<std::string> logMessages = ringbufferSink->last_formatted();

  // output all logs in buffer to file
  for (const auto& message : logMessages) {
    spdlog::info(message);
  }
  // restore formatting
  spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
}
