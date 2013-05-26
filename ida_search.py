# ida2json - An IDA Python library for recursively searching for data in 
# functions.
# Copyright (C) 2013 Alex J Chapman (dev at noxr.net)
#
# This file is licensed under the MIT License, see LICENSE for more details.

import idaapi
import re

def find_rec(ea, func, maxdepth, all=True, depth=0, path=[], processed=[]):
    if depth > maxdepth:
        return

    processed.append(ea)
        
    #Call func for each address in the function
    for addr in [x for x in FuncItems(ea)]:
        func(addr, path)
    
    #For each call instruction in the function descend into that call
    for addr in [x for x in FuncItems(ea) if idaapi.is_call_insn(x)]:
        xrefs = [x for x in CodeRefsFrom(addr, 0)]
        
        #If the call references a function known by IDA
        if len(xrefs) > 0:
            xref = xrefs[0]
            
            #If the function has not alread been processed
            if all == True or not xref in processed:
                #Find further calls in the below function
                path.append(addr)
                find_rec(xref, func, maxdepth, all, depth + 1, path, processed)
                path.pop()


                
def find_function(find_addr, from_addr=None, maxdepth=5):
    def _find_function(addr, path):
        if addr == find_addr:
            print " -> ".join(["0x%08x" % x for x in path]) + " - " + hex(addr)
    
    if from_addr is None:
        from_addr = ScreenEA()
    
    print "Finding 0x%08x starting from 0x%08x..." % (find_addr, from_addr)
    find_rec(from_addr, _find_function, maxdepth)
    print "Finished..."
    

def find_text(research, from_addr=None, maxdepth=5):
    def _find_text(addr, path):
        text = GetDisasm(addr)
        
        if re.search(research, text) is not None:
            print " -> ".join(["0x%08x" % x for x in path]) + " -> " + hex(addr) + " - " + text
    
    if from_addr is None:
        from_addr = ScreenEA()
    
    print "Finding \"%s\" starting from 0x%08x..." % (research, from_addr)
    find_rec(from_addr, _find_text, maxdepth)
    print "Finished..."

if __name__ == "__main__":
    print "Loading ida_search.py..."