# Sliver-CPPImplant2

Code for a C++ implant compatible with my fork [refactor/teamserver-interaction](https://github.com/MrAle98/sliver/tree/refactor/teamserver-interaction) of sliver C2. For me it was an exercise to learn C++.
It may teach you how to **NOT** write code in C++. For sure It has issues.

## Supported commands

* pwd
* execute-assembly with flag -i. It support only in process execute assembly. etw bypass and amsi bypass are applied by default with old technique of patching. 
* cd
* ls
* ppload
* download
* mkdir
* rm
* make-token
* rev2self
* execute
* impersonate
* list-tokens
* ps
* execute extensions DLL
* execute BOFs
* pivot commands
