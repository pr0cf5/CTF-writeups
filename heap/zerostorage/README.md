# 0CTF 2016: Zerostorage

## Vulnerabilities:
There is a Use-After-Free bug if we merge two identical storages. However the binary has PIE enabled so there are no addresses known. We need an infoleak bug.

## Exploit
Change global_max_fast --> use fastbin poisoning to change vtable of `_IO_2_1_stdin`
However to trigger `fp->vtable->__overflow` there must be a condition satisfied (I figured this out by analyzing libc)

The condition is:

(1) `fp->file.mode > 0`
(2) `fp->file.wide_data->_IO_write_ptr > fp->file.wide_data->_IO_write_base`
