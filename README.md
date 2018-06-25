About
=====

Most of the Linux file systems have a 255-byte limit on their file name
lengths. It's not VFS that imposes a limit. In fact, FUSE-based file systems can
have up to 1024-byte file names. So it's possible to create a translation layer
in a form of a FUSE-based file system, mapping longer names presented to a user
(front end), to shorter names that are suitable for storing on a real file
system (back end).

longnamefs handles name convertion. Actual files and directories are stored in
files and directories. However their names are changed to fixed-length strings
by a hash function. Original name is stored in another file, next to the file
with data.
