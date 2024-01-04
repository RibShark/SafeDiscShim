#ifndef LOGGER_H
#define LOGGER_H
#include <spdlog/spdlog.h>

namespace logging {
  typedef spdlog::level::level_enum level;

  void SetupLoggerIfNeeded();
  void SetInitializationError(const char*);
}

#endif //LOGGER_H
