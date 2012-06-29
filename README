I'd like to present a standalone command line vanity address generator 
called vanitygen.

There are plenty of quality tools to do this right now already.  So why 
use vanitygen?  The main reason is that it is fast, more than an order 
of magnitude faster than the official bitcoin client with the vanity 
address patch applied.  This is despite the fact that it runs on the 
CPU and does not use OpenCL or CUDA.  Vanitygen is also a bit more 
user-friendly in that it provides feedback on its rate of progress and 
how many keys it has checked.

Vanitygen is written in C, and is provided in source code form and 
pre-built Win32 binaries.  At present, vanitygen can be built on Linux, 
and requires the openssl and pcre libraries.

Vanitygen can generate regular bitcoin addresses, namecoin addresses, 
and testnet addresses.

Vanitygen can search for exact prefixes or regular expression matches.  
When searching for exact prefixes, vanitygen will ensure that the 
prefix is possible, will provide a difficulty estimate, and will run 
about 30% faster.  Exact prefixes are case-sensitive by default, but 
may be searched case-insensitively using the "-i" option.  Regular 
expression patterns follow the Perl-compatible regular expression 
language.

Vanitygen can accept a list of patterns to search for, either on the 
command line, or from a file or stdin using the "-f" option.  File 
sources should have one pattern per line.  When searching for N exact 
prefixes, performance of O(logN) can be expected, and extremely long 
lists of prefixes will have little effect on search rate.  Searching 
for N regular expressions will have varied performance depending on the 
complexity of the expressions, but O(N) performance can be expected.

By default, vanitygen will spawn one worker thread for each CPU in your 
system.  If you wish to limit the number of worker threads created by 
vanitygen, use the "-t" option.

The example below completed quicker than average, and took about 45 sec 
to finish, using both cores of my aging Core 2 Duo E6600:

$ ./vanitygen 1Love
Difficulty: 4476342
[48165 K/s][total 2080000][Prob 37.2%][50% in 21.2s]                           
Pattern: 1Love
Address: 1LoveRg5t2NCDLUZh6Q8ixv74M5YGVxXaN
Privkey: 5JLUmjZiirgziDmWmNprPsNx8DYwfecUNk1FQXmDPaoKB36fX1o

Currently, it is difficult to import the private key into bitcoin.  
Sipa's showwallet branch has a new command called "importprivkey" that 
accepts the base-58 encoded private key.  Vanitygen has been tested to 
work with that version of bitcoin.

