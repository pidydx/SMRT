import sublime, sublime_plugin
import base64
import hashlib
import time
import re

from string import maketrans

def ParseHex(hextext):
    if re.search(r'^(x[0-9A-F]{2})+$', hextext):
        hextext = re.sub(r'x','',hextext)
    else:
        hextext = re.sub(r'(0x|\\x|\s|%)','',hextext).upper()
    if re.search('^[0-9A-F]+$', hextext):
        return hextext
    else:
        return None

def FormatHex(hextext, bytes = 2):
    step = bytes * 2
    formathex = ""

    if not re.search('^[0-9A-F]+$', hextext):
        hextext = ParseHex(hextext)
    
    if hextext != None:
        if len(hextext) % step != 0:
            hextext = "0" * (step - (len(hextext) % step)) + hextext

        for i in range(0, len(hextext), step):
            formathex += hextext[i:i+step]
            if len(hextext[:i+step]) % 32 == 0:
                formathex += "\n"
            else:
                formathex += " "

        return formathex.upper().rstrip()
    else:
        return None

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
                if xx == 16:
                    bxxtext = base64.b16encode(text)
                self.view.replace(edit, sel, bxxtext)

class BaseXxDecodeCommand(sublime_plugin.TextCommand):
    def run(self, edit, xx=64, table=None):
        for sel in self.view.sel():
            if not sel.empty():
            #TODO Regex for charset and check/correct padding if necessary
                bxxtext = self.view.substr(sel)
                text = "*No Decoding Selected*"
                if xx == 64:
                    text = base64.b64decode(bxxtext)
                if xx == 32:
                    text = base64.b32decode(bxxtext)
                if xx == 16:
                    text = base64.b16decode(bxxtext)
                self.view.replace(edit, sel, text)

class TextTranslateCommand(sublime_plugin.TextCommand):
    def run(self, edit, rot, transin="AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz"):
        transout = transin[rot:] + transin[:rot]
        rottrans = maketrans(transin,transout)
        for sel in self.view.sel():
            if not sel.empty():
                text = self.view.substr(sel)
                rottext = str(text).translate(rottrans)
                self.view.replace(edit, sel, rottext)

class Rot13Command(sublime_plugin.TextCommand):
    def run(self, edit):
        for sel in self.view.sel():
            if not sel.empty():
                text = self.view.substr(sel)
                rot13text = text.encode('rot13')
                self.view.replace(edit, sel, rot13text)

class Md5Command(sublime_plugin.TextCommand):
    def run(self, edit):
        for sel in self.view.sel():
            if not sel.empty():
                hashtext = self.view.substr(sel)
                hashed = hashlib.md5(hashtext).hexdigest()
                self.view.replace(edit, sel, hashed)

class Sha1Command(sublime_plugin.TextCommand):
    def run(self, edit):
        for sel in self.view.sel():
            if not sel.empty():
                hashtext = self.view.substr(sel)
                hashed = hashlib.sha1(hashtext).hexdigest()
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
                    self.view.replace(edit, sel, "*Non-hex Input: \\xFF\\xFF xFFxFF %FF%FF FFFF 0xFFFF expected*")

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

