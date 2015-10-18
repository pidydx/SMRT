# Copyright 2015 Yahoo! Inc.
# Licensed under the GPL 3.0 license.  Developed for Yahoo! by Sean Gillespie.
#
# Yahoo! licenses this file to you under the GPL License, Version
# 3 (the "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#        http://www.gnu.org/licenses/gpl-3.0.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.  See the License for the specific language governing
# permissions and limitations under the License.

import sublime
import sublime_plugin
import base64
import hashlib
import time
import re
import binascii
import zlib
import urllib
import socket
import struct
from SMRT.pescanner import pescanner

# from string import maketrans


def ParseHex(hextext):
    if re.search(r'^([xX][0-9A-F]{2})+$', hextext):
        hextext = re.sub(r'x', '', hextext)
    else:
        hextext = re.sub(r'(0[xX]|\\[xX]|\\[uU]|%[uU]|%|\s)',
                         '', hextext).upper()

    if re.search('^[0-9A-F]+$', hextext):
        if len(hextext) % 2 != 0:
            hextext = "0" + hextext
        return hextext
    else:
        return None


def FormatHex(hextext, bytes=1):
    step = bytes * 2
    formathex = ""

    if not re.search('^[0-9A-F]+$', hextext):
        hextext = ParseHex(hextext)

    if hextext is not None:
        for i in range(0, len(hextext), step):
            formathex += hextext[i:i+step]
            if len(hextext[:i+step]) % 32 == 0:
                formathex += "\n"
            else:
                formathex += " "

        return formathex.upper().rstrip()
    else:
        return None


class SwitchEndiannessCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        for sel in self.view.sel():
            if not sel.empty():
                hextext = ParseHex(self.view.substr(sel))
                if hextext is not None:
                    bytearray = [hextext[i:i+2] for i in range(0, len(hextext), 2)]
                    bytearray.reverse()
                    hextext = "".join(bytearray)
                    self.view.replace(edit, sel, hextext)
                else:
                    self.view.replace(edit, sel, "*Non-hex Input: \\xFF\\xFF xFFxFF %FF%FF \\uFFFF %uFFFF FFFF 0xFFFF expected*")

class IntToIpCommand(sublime_plugin.TextCommand):
    def run(self, edit, order):
        for sel in self.view.sel():
            if not sel.empty():
                inttext = self.view.substr(sel)
                if re.search('^[0-9]+$', inttext):
                    if order == "N":
                        ip = socket.inet_ntoa(struct.pack('>L', int(inttext)))
                    if order == "H":
                        ip = socket.inet_ntoa(struct.pack('<L', int(inttext)))
                    self.view.replace(edit, sel, ip)
                else:
                    self.view.replace(edit, sel, "*Non-integer Input*")

class IpToIntCommand(sublime_plugin.TextCommand):
    def run(self, edit, order):
        for sel in self.view.sel():
            if not sel.empty():
                iptext = self.view.substr(sel)
                if re.search('^((([01]{0,1}[0-9]{1,2})|(2[0-5]{2}))\.){3}(([01]{0,1}[0-9]{1,2})|(2[0-5]{2}))$',iptext):
                    if order == "N":
                        ipint =  struct.unpack(">L", socket.inet_aton(iptext))[0]
                    if order == "H":
                        ipint =  struct.unpack("<L", socket.inet_aton(iptext))[0]
                    inttext = str(ipint)
                    self.view.replace(edit, sel, inttext)
                else:
                    self.view.replace(edit, sel, "*Non-IPv4 Input*")

class UrlUnquoteCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        for sel in self.view.sel():
            if not sel.empty():
                urltext = self.view.substr(sel)
                urltext = urllib.unquote(urltext)
                self.view.replace(edit, sel, urltext)

class UrlQuoteCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        for sel in self.view.sel():
            if not sel.empty():
                urltext = self.view.substr(sel)
                urltext = urllib.quote(urltext)
                self.view.replace(edit, sel, urltext)

class ZlibCompressCommand(sublime_plugin.TextCommand):
    def run (self, edit):
        for sel in self.view.sel():
            if not sel.empty():
                hextext = ParseHex(self.view.substr(sel))
                if hextext != None:
                    ddata = binascii.unhexlify(hextext)
                    cdata = zlib.compress(ddata)[2:-4]
                    hextext = binascii.hexlify(cdata)
                    formathex = FormatHex(hextext)
                    self.view.replace(edit, sel, formathex)
                else:
                    self.view.replace(edit, sel, "*Non-hex Input: \\xFF\\xFF xFFxFF %FF%FF \\uFFFF %uFFFF FFFF 0xFFFF expected*")

class ZlibDecompressCommand(sublime_plugin.TextCommand):
    def run (self, edit):
        for sel in self.view.sel():
            if not sel.empty():
                hextext = ParseHex(self.view.substr(sel))
                if hextext != None:
                    cdata = binascii.unhexlify(hextext)
                    ddata = zlib.decompress(cdata,-15)
                    hextext = binascii.hexlify(ddata)
                    formathex = FormatHex(hextext)
                    self.view.replace(edit, sel, formathex)
                else:
                    self.view.replace(edit, sel, "*Non-hex Input: \\xFF\\xFF xFFxFF %FF%FF \\uFFFF %uFFFF FFFF 0xFFFF expected*")

class HexEncodeCommand(sublime_plugin.TextCommand):
    def run(self, edit, encoding="ascii"):
        for sel in self.view.sel():
            if not sel.empty():
                text = self.view.substr(sel).encode(encoding)
                hextext = binascii.hexlify(text)
                formathex = FormatHex(hextext)
                self.view.replace(edit, sel, formathex)

class HexDecodeCommand(sublime_plugin.TextCommand):
    def run(self, edit, encoding="ascii"):
        for sel in self.view.sel():
            if not sel.empty():
                hextext = ParseHex(self.view.substr(sel))
                if hextext != None:
                    text = binascii.unhexlify(hextext).decode(encoding)
                    cleantext = re.sub(r'[\t\n\r]', '.', text)
                    self.view.replace(edit, sel, cleantext)
                else:
                    self.view.replace(edit, sel, "*Non-hex Input: \\xFF\\xFF xFFxFF %FF%FF \\uFFFF %uFFFF FFFF 0xFFFF expected*")

class FormatHexCommand(sublime_plugin.TextCommand):
    def run (self, edit, bytes):
        for sel in self.view.sel():
            if not sel.empty():
                hextext = ParseHex(self.view.substr(sel))
                if hextext != None:
                    formathex = FormatHex(hextext, bytes)
                    self.view.replace(edit, sel, formathex)
                else:
                    self.view.replace(edit, sel, "*Non-hex Input: \\xFF\\xFF xFFxFF %FF%FF \\uFFFF %uFFFF FFFF 0xFFFF expected*")

class BaseXxEncodeCommand(sublime_plugin.TextCommand):
    def run(self, edit, xx=64, table=None):
        for sel in self.view.sel():
            if not sel.empty():
                text = self.view.substr(sel)
                bxxtext = "*No Encoding Selected*"
                if xx == 64:
                    bxxtext = base64.b64encode(text)
                if xx == 32:
                    bxxtext = base64.b32encode(text)
                self.view.replace(edit, sel, bxxtext)

class BaseXxDecodeCommand(sublime_plugin.TextCommand):
    def run(self, edit, xx=64, table=None):
        for sel in self.view.sel():
            if not sel.empty():
                bxxtext = self.view.substr(sel)
                text = "*Improper or No Decoding Selected*"    
                if xx == 64 and re.search('^[A-Za-z0-9+/=]+$',bxxtext):
                    if len(bxxtext) % 4 != 0:
                        bxxtext += "=" * (4 - (len(bxxtext) % 4))
                    text = base64.b64decode(bxxtext)
                if xx == 32 and re.search('^[A-Z2-7=]+$',bxxtext):
                    if len(bxxtext) % 8 != 0:
                        bxxtext += "=" * (8 - (len(bxxtext) % 8))
                    text = base64.b32decode(bxxtext)
                self.view.replace(edit, sel, text)

class BaseXxEncodeBinaryCommand(sublime_plugin.TextCommand):
    def run(self, edit, xx=64, table=None):
        for sel in self.view.sel():
            if not sel.empty():
                hextext = ParseHex(self.view.substr(sel))
                data = binascii.unhexlify(hextext)
                bxxtext = "*No Encoding Selected*"
                if xx == 64:
                    bxxtext = binascii.b2a_base64(data)
                self.view.replace(edit, sel, bxxtext)

class BaseXxDecodeBinaryCommand(sublime_plugin.TextCommand):
    def run(self, edit, xx=64, table=None):
        for sel in self.view.sel():
            if not sel.empty():
            #TODO Regex for charset and check/correct padding if necessary
                bxxtext = self.view.substr(sel)
                text = "*No Decoding Selected*"    
                if xx == 64:
                    data = binascii.a2b_base64(bxxtext)
                    hextext = binascii.hexlify(data)
                    formathex = FormatHex(hextext)
                self.view.replace(edit, sel, formathex)

class TextTranslateCommand(sublime_plugin.TextCommand):
    def run(self, edit, rot, transin="AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz"):
        transout = transin[rot:] + transin[:rot]
        rottrans = maketrans(transin,transout)
        for sel in self.view.sel():
            if not sel.empty():
                text = self.view.substr(sel)
                rottext = str(text).translate(rottrans)
                self.view.replace(edit, sel, rottext)

class HashCommand(sublime_plugin.TextCommand):
    def run(self, edit, alg=None):
        for sel in self.view.sel():
            if not sel.empty():
                hashtext = self.view.substr(sel)
                if alg == "md5":
                    hashed = hashlib.md5(hashtext).hexdigest()
                elif alg == "sha1":
                    hashed = hashlib.sha1(hashtext).hexdigest()
                elif alg == "sha256":
                    hashed = hashlib.sha256(hashtext).hexdigest()
                else:
                    hashed = "*No algorithm selected*"
                self.view.replace(edit, sel, hashed)

class TimestampFromIntCommand(sublime_plugin.TextCommand):
    def run(self, edit, format="Unix"):
        for sel in self.view.sel():
            if not sel.empty():
                timeint = self.view.substr(sel)
                timetext = "*No Timestamp Format Selected*"
                if format == "Unix":
                    timetext = time.strftime("%d-%b-%Y %H:%M:%S", time.gmtime(int(timeint)))
                self.view.replace(edit, sel, timetext)

class DisplayInputErrorCommand(sublime_plugin.TextCommand):
    def run(self, edit, errortext="*Unknown Error*"):
        for sel in self.view.sel():
            if not sel.empty():
                self.view.replace(edit, sel, errortext)

class IntToHexCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        for sel in self.view.sel():
            if not sel.empty():
                inttext = self.view.substr(sel)
                if re.search('^[0-9]+$', inttext):
                    hextext = FormatHex( "%x" % (int(inttext)))
                    self.view.replace(edit, sel, hextext)
                else:
                    self.view.replace(edit, sel, "*Non-integer Input*")

class HexToIntCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        for sel in self.view.sel():
            if not sel.empty():
                hextext = ParseHex(self.view.substr(sel))
                if hextext != None:
                    text = str(int(hextext, 16))
                    self.view.replace(edit, sel, text)
                else:
                    self.view.replace(edit, sel, "*Non-hex Input: \\xFF\\xFF xFFxFF %FF%FF \\uFFFF %uFFFF FFFF 0xFFFF expected*")

class PeScannerCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        peid_sigs = sublime.packages_path() + '/SMRT/peid.db'
        for sel in self.view.sel():
            hextext = ParseHex(self.view.substr(sel))
            if hextext != None:
                pehex = pescanner.PEScanner(binascii.unhexlify(hextext), peid_sigs=peid_sigs)
                report_file = self.view.window().new_file()
                report_file.set_name("PE Scanner Report")
                report_file.insert(edit, 0, '\n'.join(pehex.collect()))

class GetTextRotValue(sublime_plugin.WindowCommand):
    def run(self):
        self.window.show_input_panel('Rotation', '', self.on_done, None, None)

    def on_done(self, rot):
        if re.search('^[0-9]+$', rot):
            rot = int(rot)
            if self.window.active_view():
                self.window.active_view().run_command("text_translate", {"rot": rot*2})
        else:
            if self.window.active_view():
                self.window.active_view().run_command("display_input_error", {"errortext": "*Non-integer Input*"})

class GetSwapMap(sublime_plugin.WindowCommand):
    def run(self):
        self.window.show_input_panel('Swap Map', '', self.on_done, None, None)

    def on_done(self, swapmap):
        if re.search('[^:]+:[^:]+', swapmap):
            seta, setb = swapmap.split(":")
            if len(seta) == len(setb):
                rot = len(seta)
                transin = seta + setb
                if self.window.active_view():
                    self.window.active_view().run_command("text_translate", {"rot": rot, "transin": transin})
            else:
                if self.window.active_view():
                    self.window.active_view().run_command("display_input_error", {"errortext": "*Invalid Swap Map: Use Xx:Yy format*"})
        else:
            if self.window.active_view():
                self.window.active_view().run_command("display_input_error", {"errortext": "*Invalid Swap Map: Use Xx:Yy format*"})

