# ida2json - An IDA Python library for outputting an IDA Pro dissassembled 
# function as JSON.
# Copyright (C) 2013 Alex J Chapman (dev at noxr.net)
#
# This file is licensed under the MIT License, see LICENSE for more details.

import idaapi
import json

def bblock_boundaries(func_addr):
    start_f = GetFunctionAttr(func_addr, FUNCATTR_START)
    end_f = GetFunctionAttr(func_addr, FUNCATTR_END)

    #Locate the basic block boundaries
    block_starts = [start_f]
    block_ends = [end_f]
    addrs = [x for x in FuncItems(start_f)]
    for addr in addrs:
        #Record jmp and next locations of internal jumps
        refsFrom = [x for x in CodeRefsFrom(addr, 1) if x in addrs]
        if len(refsFrom) >= 2:
            for x in refsFrom:
                if not x in block_starts:
                    block_starts.append(x)
            if not addr in block_ends:
                block_ends.append(addr)
        
        #Record address which are the target of internal jumps
        refsTo = [x for x in CodeRefsTo(addr, 1) if x in addrs]
        if len(refsTo) >= 2:
            for x in refsTo:
                if not x in block_ends:
                    block_ends.append(x)
            if not addr in block_starts:
                block_starts.append(addr)

    block_starts.sort()

    #Record the start and end addresses
    blocks = []
    for start in block_starts:
        end = start
        
        #Find the end of the block which occurs at the following conditions:
        #   address is in the block_ends array
        #   next address is in the block_start array
        #   next address is not in the function
        while not end in block_ends:
            _end = NextHead(end)
            if not _end in addrs or _end in block_starts:
                break
            end = _end
        
        blocks.append((start, end))

    return blocks
    
def ida2json(func_addr):
    def _block_to_id(addr):
        for x in range(len(blocks)):
            if blocks[x][0] == addr:
                return x + 1
        return None
    
    addrs = [x for x in FuncItems(func_addr)]
    blocks = bblock_boundaries(func_addr)
    for x in blocks:
        print "%x, %x" % x
    
    output = []
    for x in range(len(blocks)):
        block = {}
        block["id"] = x + 1
        start_addr = blocks[x][0]
        end_addr = blocks[x][1]
        
        #Record the block contents
        contents = ""
        addr = start_addr
        while addr != end_addr:
            contents += GetDisasm(addr) + "\n"
            addr = NextHead(addr)
        contents += GetDisasm(addr)
        block["contents"] = contents
        
        #Find the local jmps from the end address and covert them to ids
        jmps = [_block_to_id(x) for x in CodeRefsFrom(end_addr, 1) if x in addrs]
        
        #If we have a decision jmp, mark the id reference for the true and false jmps
        if len(jmps) == 2:
            block["true_jmp"] = [_block_to_id(x) for x in CodeRefsFrom(end_addr, 0)][0]
            block["false_jmp"] = [x for x in jmps if x != block["true_jmp"]][0]
        
        block["jmps"] = jmps
        output.append(block)
    return json.dumps(output)
    
if __name__ == "__main__":
    print "Loading ida2json.py..."