#ifndef RELAUNCH_H
#define RELAUNCH_H

namespace process {
  void RelaunchGame(HANDLE);
  void InjectIntoExecutable(HANDLE, HANDLE, bool);
}

#endif //RELAUNCH_H
