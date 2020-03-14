# Operating System Project on Pintos

## Project 1 (on branch: Proj1)
- In this project we were supposed to extend the minimal functionality of thread system in PintOS
- Implementing `thread synchorinization` for a better alarm clock, `thread scheduling` in which we had to 
do `priority donation` and `multilevel feedback queue`

## Project 2 (on branch: Proj2)
- Providing/Denying file system access
- Argument Passing: PintOS does not take arguments for system calls. Here we were supposed to parse the arguments by white spaces
and push them in reverse order on to the stack.
- System Calls: For User program to execute some kernel level commands it makes syscall interrupt.
For this purpose we needed 13 system calls (halt, exit, exec, wait, create, remove, open, filesize, read, write, seek, tell, close) to be implemented.
