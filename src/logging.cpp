#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

#include "logging.h"

void logging::SetupLogger() {
  auto logger = spdlog::basic_logger_mt("SafeDiscShim",
    "SafeDiscShim_log.txt", true);
  spdlog::set_default_logger(logger);
  spdlog::set_level(spdlog::level::info);
  spdlog::flush_on(spdlog::level::info);

  logging::isLoggerSetup = true;
}
