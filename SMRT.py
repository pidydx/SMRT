import sublime, sublime_plugin
import base64
import hashlib
import time

class BaseXxEncodeCommand(sublime_plugin.TextCommand):
    def run(self, edit, xx=64, table=None):
        for sel in self.view.sel():
            if not sel.empty():
                text = self.view.substr(sel)
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
                if xx == 64:
                    text = base64.b64decode(bxxtext)
                if xx == 32:
                    text = base64.b32decode(bxxtext)
                if xx == 16:
                    text = base64.b16decode(bxxtext)
                self.view.replace(edit, sel, text)

class Rot13Command(sublime_plugin.TextCommand):
    def run(self, edit):
        for sel in self.view.sel():
            if not sel.empty():
                text = self.view.substr(sel)
                rot13text = text.encode('rot13')
                self.view.replace(edit, sel, rot13text)

class md5Command(sublime_plugin.TextCommand):
    def run(self, edit):
        for sel in self.view.sel():
            if not sel.empty():
                hashtext = self.view.substr(sel)
                hashed = hashlib.md5(hashtext).hexdigest()
                self.view.replace(edit, sel, hashed)

class sha1Command(sublime_plugin.TextCommand):
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
                if format == "Unix":
                    timetext = time.strftime("%d-%b-%Y %H:%M:%S", time.gmtime(int(timeint)))
                self.view.replace(edit, sel, timetext)


