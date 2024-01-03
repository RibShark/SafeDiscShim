#ifndef LOGGER_H
#define LOGGER_H

#include <atomic>

namespace logging {
  inline std::atomic_bool isLoggerSetup;

  void SetupLogger();
}

#endif //LOGGER_H
