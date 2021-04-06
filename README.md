# logstor: A Log-structured user level FreeBSD GEOM layer
Wuyang Chung, wuyang.chung1@gmail.com
## Abstract
Most file systems today are write-in-place file system. This kind of file system will generate random writes to the underlying storage device and random writes are bad for both hard disk and flash disk. On the other hand, log-structured file system is a copy-on-write file system. The new written data are appended to the end of the log so it writes data sequentially. Logstor is a user level FreeBSD GEOM layer that can be inserted between the file system and the storage device. It uses the same principle of log-structured file system, that is the data are always appended to the end of the log, so it can also transform random writes from file system above to sequential writes to the underlying storage device. Logstor can make any file system a log-structured file system when that file system is created on top of it. If the logstor commands snapshot and commit are implemented, it can make the file system run faster by not having to sync file system's metadata frequently.
## Introduction
FreeBSD's GEOM framework makes the organization of storage devices flexible and easy. You can organize your storage devices in any RAID configurations as you like. In fact the various disk partitioning schemes are provided by GEOM in FreeBSD. What the GEOM do is to transform the IO requests from upper layer and then send the transformed requests down to the lower layer. The transformation may be the data contents or the offset where the data is to be stored. Logstor is using GEOM framework to transform the write request to log append request, i.e. to sequential write. It uses the same ideas from log-structured file system. The disk is divided into segments. At the end of each segment there is a segment summary block. Also logstor needs to do garbage collection when the log is full. Currently the cleaning algorithm used is hot-cold separation with aging.

Since file system and disk storage use different terms for their unit of operation, i.e. block vs sector, in this paper I will use block to refer to the logical unit and use sector to refer to the physical unit. Like FTL (flash translation layer), logstor provides a logical view of the disk to the above file system so it needs to store the forward mapping (i.e. block to sector mapping) in its metadata. This forward mapping is not stored in a specific area on the disk. It is also appended to the log. This mapping metadata are load-on-demand. Only the currently active mappings are loaded into DRAM. In order to do garbage collection, it also needs to store the reverse mapping (i.e. sector to block mapping). The reverse mapping is stored in the segment summary block.

The next section will give a detailed information about the implementation of logstor. It is followed by the performance of logstor compared to ggatel. Ggatel is also a user level GEOM but without any transformation. Then I will talk about the future work for logstor and finally the conclusion.
## Implementation
Figure 1 shows the disk layout of logstor. It has only two areas, superblock area and data area. Superblock area is used to store logstor's data structure. The data area is divided into segments. Each segment is divided into sectors. The last sector of each segment stores another logstor's data structure called segment summary block which is used to store reverse map for all the sectors in that segment.

![image](/docs/Figure_1.png)

Figure 1. The disk layout of logstor

The forward map information is not stored on a specific area of the disk. It is stored in the data area. I create a simple file system to store the forward map information. This simple file system does not support sub-directory. It can only have at most 4 files in the root directory. It does not support string file name. Eeach file is named by an integer number. It does not use inode instead it uses page table like data structure to track all the data blocks of a file. Figure 2a shows the page table like data structure when it is stored on disk and figure 2b shows the data structure when it is in DRAM. The currently active PDE, PTEs and data blocks are loaded in the simple file system's buffer cache. All the data blocks of a file in buffer cache are put in a circular queue. All the PDEs and PTEs in buffer cache are put in their indirect queue. When a cache miss happened, the simple file system will choose a victim buffer from the circular queue. The replacement policy used is the second chance policy. The victim buffer is written back to disk if dirty and the new data is loaded to this buffer. Logstor supports TRIM command. When a TRIM command is received, it simply puts delete marks for the mappings of the blocks that are trimmed.

![image](/docs/Figure_2a.png)

Figure 2a. Simple file system in disk

![image](/docs/Figure_2b.png)

Figure 2b. Simple file system in DRAM

Like log-structured file system, logstor needs to do garbage collection when the log is near full. Currently the cleaning algorithm used is hot-cold separation with aging. There are two logs in logstor, hot log and cold log. When the file system writes data blocks to logstor, it is appended to hot log because file system does not provide a hint about the hotness of the data so I can only assume that the data might be changed very soon. And the data blocks recycled during segment cleaning is appended to cold log. Logstor's metadata are always appended to hot log because by nature it changes frequently. The cleaning algorithm uses round-robin method to choose the segment to clean. For a segment with a very high utilization, the cleaner will first check its age. If the segment is still young, it will bypass this high-utilized segment and increase its age. If the segment reaches certain age, it will be recycled for wear leveling. The algorithm below shows how to determine if a sector in a segment is live or dead during segment cleaning.

![image](/docs/Figure_3.png)

## Performance
The benchmark used for performance test is FreeBSD kernel build. I compare the performance of logstor with ggatel. Ggatel is FreeBSD's example user level GEOM program that does not do any transformation on the IO request. Below is the test procedure.
1. Create logstor device
2. Create a new file system on logstor device and enable TRIM
3. Mount the new file system to /mnt
4. Copy FreeBSD's src to /mnt and set the build target to /mnt/obj
5. Build kernel
6. Remove the src and obj directory in /mnt<br>
Goto step 4

The table below shows the test result.

![image](/docs/Table_1.png)

As can be seen the only time that the performance is better is when the src is first copied to /mnt. It is expected because logstor transforms random write to sequential write. All the other test results are worse because garbage collection is triggered. In this test the disk size is 7GB and the size of the FreeBSD source code is 3GB (including the hidden directory .git).
## Future Work and Conclusion
Logstor is currently implemented as a user level GEOM program because it is easier to debug and test the program in user level. The next step would be moving logstor to kernel level. Also since logstor treats the underlying disk as a log, it is easy to implement the operations snapshot, rollback and commit in logstor. The snapshot operation can create a snapshot of the logical disk. Rollback can roll the logical disk back to its previous snapshot. The commit operation can merge the changes after its previous snapshot to logical disk. With these operations, it can make the command 'cp -R' and 'rm -R' run a lot more faster. Of course the file system, cp and rm command must be adapted to use these new operations.
