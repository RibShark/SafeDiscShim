#ifndef LOGGER_H
#define LOGGER_H
#include <spdlog/spdlog.h>

namespace logging {
  typedef spdlog::level::level_enum level;

  void SetupLogger();
  void SetLoggerFileName(const std::string&);
}

#endif //LOGGER_H
