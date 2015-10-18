#!/usr/bin/python
# Copyright (C) 2010 Michael Ligh
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# [NOTES] -----------------------------------------------------------
# 1) Tested on Linux (Ubuntu), Windows XP/7, and Mac OS X
# --------------------------------------------------------------------

#
# Modifications to file for Yahoo! by Sean Gillespie
#

import string
import binascii
import sys
import hashlib
import time
import re
import SMRT.pefile.pefile as pefile
import SMRT.pefile.peutils as peutils
import SMRT.magic as magic

# suspicious APIs to alert on
alerts = ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory',
          'CreateRemoteThread', 'ReadProcessMemory', 'CreateProcess',
          'WinExec', 'ShellExecute', 'HttpSendRequest', 'InternetReadFile',
          'InternetConnect', 'CreateService', 'StartService']
# legit entry point sections
good_ep_sections = ['.text', '.code', 'INIT', 'PAGE', 'CODE']


def convert_char(char):
    if char in string.ascii_letters or \
       char in string.digits or \
       char in string.punctuation or \
       char in string.whitespace:
        return char
    else:
        return r'\x%02x' % ord(char)


def convert_to_printable(s):
    return ''.join([convert_char(c) for c in s])


class PEScanner:
    def __init__(self, data, yara_rules=None, peid_sigs=None):
        self.data = data

        # initialize PEiD signatures if provided
        if peid_sigs:
            self.sigs = peutils.SignatureDatabase(peid_sigs)
        else:
            self.sigs = None

        # initialize python magic (file identification)
        # magic interface on python <= 2.6 is different than python >= 2.6
        if 'magic' in sys.modules:
            if sys.version_info <= (2, 6):
                self.ms = magic.open(magic.MAGIC_NONE)
                self.ms.load()

    def check_ep_section(self, pe):
        """ Determine if a PE's entry point is suspicious """
        name = ''
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for sec in pe.sections:
            if (ep >= sec.VirtualAddress) and \
               (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
                name = sec.Name.decode('utf-8').replace('\x00', '')
        return (ep, name)

    def check_verinfo(self, pe):
        """ Determine the version info in a PE file """
        ret = []

        if hasattr(pe, 'VS_VERSIONINFO'):
            if hasattr(pe, 'FileInfo'):
                for entry in pe.FileInfo:
                    if hasattr(entry, 'StringTable'):
                        for st_entry in entry.StringTable:
                            for str_entry in st_entry.entries.items():
                                ret.append(
                                    convert_to_printable(str_entry[0]) + ': ' +
                                    convert_to_printable(str_entry[1]) )
                    elif hasattr(entry, 'Var'):
                        for var_entry in entry.Var:
                            if hasattr(var_entry, 'entry'):
                                ret.append(
                                    convert_to_printable(var_entry.entry.keys()[0]) +
                                    ': ' + var_entry.entry.values()[0])
        return '\n'.join(ret)

    def check_tls(self, pe):
        callbacks = []
        if (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and \
                    pe.DIRECTORY_ENTRY_TLS and \
                    pe.DIRECTORY_ENTRY_TLS.struct and \
                    pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
            callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks \
                    - pe.OPTIONAL_HEADER.ImageBase 
            idx = 0
            while True:
                func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
                if func == 0: 
                    break
                callbacks.append(func)
                idx += 1
        return callbacks

    def check_rsrc(self, pe):
        ret = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            i = 0
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name is not None:
                    name = "%s" % resource_type.name
                else:
                    name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
                if name == None:
                    name = "%d" % resource_type.struct.Id
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(
                                    resource_lang.data.struct.OffsetToData, 
                                    resource_lang.data.struct.Size)
                                if 'magic' in sys.modules:
                                    if sys.version_info <= (2, 6):
                                        filetype = self.ms.buffer(data)
                                    else:
                                        filetype = magic.from_buffer(data)
                                else:
                                    filetype = None
                                if filetype == None:
                                    filetype = ''
                                ret[i] = (name, resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size, filetype)
                                i += 1
        return ret           
        
    def check_libs(self, pe):
        ret = []
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return ret
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            if (lib.dll != None) and (lib.dll != ""):
                ret.append(lib.dll)
        return ret

    def check_imports(self, pe):
        ret = []
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return ret
        for lib in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in lib.imports:
                if (imp.name != ""):
                    if (imp.name == None):
                        importname = lib.dll +":"+ "%04x" % imp.ordinal
                    else:
                        importname = imp.name
                    for alert in alerts:
                        if importname.startswith(alert):
                            importname += ('%-30s%s') % (importname, "[SUSPICIOUS]")
                    ret.append(importname)
        return ret
    
    def check_exportdll(self, pe):
        ret = ""
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            if pe.DIRECTORY_ENTRY_EXPORT.struct.Name:
                return pe.get_string_at_rva(pe.DIRECTORY_ENTRY_EXPORT.struct.Name)
        return ret

    def check_exports(self, pe):
        ret = []
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return ret
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.address is not None:
                exportinfo = ('%04x       %-30s' % (exp.ordinal, exp.name))
                if exp.forwarder:
                    exportinfo += ('%s' % exp.forwarder)
                ret.append(exportinfo)
        return ret
        
    def get_timestamp(self, pe):
        val = pe.FILE_HEADER.TimeDateStamp
        ts = '0x%-8X' % (val)
        try:
            ts = '%s\t[%s]' % (time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(val)),ts)
            that_year = time.gmtime(val)[0]
            this_year = time.gmtime(time.time())[0]
            if that_year < 2000 or that_year > this_year:
                ts += " [SUSPICIOUS]"
        except:
            ts += ' [SUSPICIOUS]'
        return ts

    def check_packers(self, pe):
        packers = []
        if self.sigs:
            matches = self.sigs.match(pe, ep_only = True)
            if matches != None:
                for match in matches:
                    packers.append(match)
        return packers

    def header(self, msg):
        return "\n" + msg + "\n" + ("=" * 60)

    def collect(self):
        data = self.data
        out = []
        if data is None or len(data) == 0:
            out.append("Cannot read %s (maybe empty?)" % file)
            out.append("")
            return out

        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
        except:
            out.append("Cannot parse %s (maybe not PE?)" % file)
            out.append("")
            return out

        # Meta Data
        out.append(self.header("Meta-data"))
        out.append("Size:      %d bytes" % len(data))
        out.append("Date:      %s" % self.get_timestamp(pe))

        exportdll = self.check_exportdll(pe)
        if len(exportdll):
            out.append("ExportDll: %s" % exportdll)
        (ep, name) = self.check_ep_section(pe)

        s = "EP:        %s (%s)" % (hex(ep+pe.OPTIONAL_HEADER.ImageBase), name)
        if name not in good_ep_sections:
            s += " [SUSPICIOUS]"
        out.append(s)

        if 'magic' in sys.modules:
            if sys.version_info <= (2, 6):
                out.append("Type:      %s" % self.ms.buffer(data))
            else:
                out.append("Type:      %s" % magic.from_buffer(data))
            
        out.append("MD5:       %s"  % hashlib.md5(data).hexdigest())
        out.append("SHA1:      %s" % hashlib.sha1(data).hexdigest())
        out.append("SHA256:      %s" % hashlib.sha256(data).hexdigest())

        packers = self.check_packers(pe)
        if len(packers):
            out.append("Packers:   %s" % ','.join(packers))
        
        #Version Info
        verinfo = self.check_verinfo(pe)
        if len(verinfo):
            out.append(self.header("Version info"))
            out.append(verinfo)
        
        #Sections
        out.append(self.header("Sections"))
        out.append("%-10s %-12s %-12s %-12s %-12s" % ("Name", "VirtAddr", "VirtSize", "RawSize", "Entropy"))
        out.append("-" * 60)
        
        for sec in pe.sections:
            s = "%-10s %-12s %-12s %-12s %-12f" % (
                sec.Name.decode('utf-8').replace('\x00', ''),
                hex(sec.VirtualAddress),
                hex(sec.Misc_VirtualSize),
                hex(sec.SizeOfRawData),
                sec.get_entropy())
            if sec.SizeOfRawData == 0 or \
               (sec.get_entropy() > 0 and sec.get_entropy() < 1) or \
               sec.get_entropy() > 7:
                s += "[SUSPICIOUS]"
            out.append(s)
        
        #Resources  
        resources = self.check_rsrc(pe)
        if len(resources):
            out.append(self.header("Resource entries"))
            out.append("%-18s %-12s %-12s Type" % ("Name", "RVA", "Size"))
            out.append("-" * 60)
            for rsrc in resources.keys():
                (name,rva,size,type) = resources[rsrc]
                out.append("%-18s %-12s %-12s %s" % (name,hex(rva),hex(size),type))
        
        #TLS Callbacks        
        callbacks = self.check_tls(pe)
        if len(callbacks):
            out.append(self.header("TLS callbacks"))
            for cb in callbacks:
                out.append("    0x%x" % cb)

        #Exports
        exports = self.check_exports(pe)
        if len(exports):
            out.append(self.header("Exported Functions"))
            out.append("%-10s %-30s%s" % ("Ordinal", "Name", "Forwarder"))
            out.append("-" * 60)
            for exp in exports:
                out.append(exp)

        #Libraries
        libs = self.check_libs(pe)
        if len(libs):
            out.append(self.header("Import Libs"))
            for lib in libs:
                out.append(lib)
        
        #Imports
        imports = self.check_imports(pe)
        if len(imports):
            out.append(self.header("Imported Functions"))
            for imp in imports:
                out.append(imp)

        #Strings
        # results = []
        # patterns = ["[ -~]{2,}[\\\/][ -~]{2,}", "[ -~]{2,}\.[ -~]{2,}","\\\[ -~]{5,}","^[ -~]{5,}[\\\/]$","[ -~]+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[ -~]+"]
                
        # for pattern in patterns:
        #     regex = re.compile(pattern)
        #     results += regex.findall(data)
        # if len(results):
        #     out.append(self.header("Interesting Strings"))
        #     out += list(set(results))
              
        out.append("")
        return out