# ProcessHollowing32-64

ProcessHollowing32-64 is a simple Process Hollowing project that you can compile the same code to a 32 bit version and to a 64 bit version.
You just have to change the build configuration on Visual Studio.

## Difference between 32 bit process hollowing and 64 bit process hollowing
On a 32 bit process, when a process is started, ebx register is pointing to the TIB, and eax is pointing to the entry point.
On a 64 bit process, rdx is pointing to the TIB, and rcx is pointing to the entry point.

## Credit
Most of the code was taken from:
http://www.rohitab.com/discuss/topic/40262-dynamic-forking-process-hollowing/