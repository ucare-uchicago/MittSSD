```
 __   __  ___   _______  _______  _______  _______  ______  
|  |_|  ||   | |       ||       ||       ||       ||      | 
|       ||   | |_     _||_     _||  _____||  _____||  _    |
|       ||   |   |   |    |   |  | |_____ | |_____ | | |   |
|       ||   |   |   |    |   |  |_____  ||_____  || |_|   |
| ||_|| ||   |   |   |    |   |   _____| | _____| ||       |
|_|   |_||___|   |___|    |___|  |_______||_______||______| 
```
                              
Contact Information
--------------------

**Maintainer**: [Huaicheng Li](https://people.cs.uchicago.edu/~huaicheng/) (huaicheng@cs.uchicago.edu)


This repo hosts the (SSD-part) source code for our MittOS paper at SOSP'17. And
the bib entry is:


```
@InProceedings{Hao+17-MittOS, 
       Author = {Mingzhe Hao and Huaicheng Li and Michael Hao Tong and Chrisma Pakha 
                 and Riza O. Suminto and Cesar A. Stuardo and Andrew A. Chien and Haryadi S. Gunawi},
        Title = "{MittOS: Supporting Millisecond Tail Tolerance with Fast Rejecting SLO-Aware OS Interface}",
    BookTitle = {The 26th ACM Symposium on Operating Systems Principles (SOSP)},
      Address = {Shanghai, China},
        Month = {October},
         Year = {2017}
}

```

### Requirement

You need an OCSSD to run the code.


### Compilation

```
make defconfig
# then ``make menuconfig`` to manually enable pblk and other drivers you need
make -j8
sudo make modules_install
sudo make install
```

This will install a new kernel to your system. Reboot your host system to run it.

### MittSSD /sys interface

MittSSD provides some ``/sys`` interface for interactions with LightNVM from
user space. Checkout the code ``drivers/lightnvm/pblk-sys.c`` for MittSSD
related ones.

### MittSSD code structure:

- syscall and file system layers: added logics to pass the SLO and
  fast-rejection information through the entire storage stack

- LightNVM: serving as the host-managed ``device`` layer. MittSSD extends it
  with a fine-grnular latency monitoring module for accurate SLO prediction,
  based on pre-profiled NAND level latencies.

- The ``read()`` syscall is extended with a ``SLO``  parameter, upon receiving
  MittSSD returned ``failure``, the application could retry a ``read()`` from
  the replicas.
