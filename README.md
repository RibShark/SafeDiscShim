# SafeDiscShim
## Disclaimer
SafeDiscShim is purely designed as a compatibility tool: no security mechanisms are bypassed in the operation of this 
tool and SafeDisc protected games still require their original discs in order to function, even when using this tool.
Certain games may have additional compatibility issues outside of the SafeDisc protection; this tool makes no attempt to
fix such issues. Due to the techniques used, certain anti-malware programs may wrongly detect this software as being
malicious.

## Introduction
SafeDiscShim is a compatibility tool that allows for SafeDisc protected games which utilize the insecure Macrovision
Security Driver ("secdrv.sys") to run on modern versions of Windows which have said driver blacklisted. Previous methods
to restore functionality to these games relied on forcefully installing the driver, potentially opening security risks.

In contrast, this tool does not rely on any drivers to function. Instead, it automatically loads alongside SafeDisc
protected games and intercepts any communication requests that would have been sent to the driver, instead sending the 
expected response itself and allowing the game to boot.

## Installation Instructions
Simply download the [latest release](https://github.com/RibShark/SafeDiscShim/releases/latest) and run the installer.
Once installed, SafeDiscShim should automatically insert itself into most SafeDisc protected games.

For a few games utilizing SafeDisc v1, SafeDiscShim may not work properly without first deleting the "drvmgt.dll" file
that is located in the same folder as the game executable. If you find a game where this is the case, please write an 
[issue report](https://github.com/RibShark/SafeDiscShim/issues) detailing the name and specific release of the game so
a specific compatibility profile can be created to bypass the problem.

## Logging
To aid with debugging, beta versions of SafeDiscShim will automatically create log files in the same folder as the 
executable. If you wish to disable this, set the environment variable "SAFEDISCSHIM_LOGLEVEL" with a value of "none".
