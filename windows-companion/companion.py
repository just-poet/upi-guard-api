"""UPI Guard: user-invoked, always-on-top Windows helper. Standard library only."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import queue
import re
import threading
import tkinter as tk
from tkinter import ttk
import urllib.error
import urllib.request
import webbrowser

API='https://upi-guard-api.onrender.com'
WEBSITE='https://upi-guard-payment-safety.copperlemur.chatgpt.site/?companion=connect'
STORE=Path(os.environ.get('LOCALAPPDATA',str(Path.home()))) / 'UPIGuard' / 'connection.bin'


class Blob(ctypes.Structure):
    _fields_=[('size',wintypes.DWORD),('data',ctypes.POINTER(ctypes.c_ubyte))]


def protect(data,decrypt=False):
    if os.name!='nt': raise RuntimeError('This companion requires Windows.')
    buffer=ctypes.create_string_buffer(data);source=Blob(len(data),ctypes.cast(buffer,ctypes.POINTER(ctypes.c_ubyte)));target=Blob()
    ctypes.windll.crypt32.CryptProtectData.argtypes=[ctypes.POINTER(Blob),wintypes.LPCWSTR,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)]
    ctypes.windll.crypt32.CryptUnprotectData.argtypes=[ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)]
    ctypes.windll.kernel32.LocalFree.argtypes=[ctypes.c_void_p]
    ctypes.windll.kernel32.LocalFree.restype=ctypes.c_void_p
    if decrypt: ok=ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(source),None,None,None,None,1,ctypes.byref(target))
    else: ok=ctypes.windll.crypt32.CryptProtectData(ctypes.byref(source),'UPI Guard companion',None,None,None,1,ctypes.byref(target))
    if not ok: raise ctypes.WinError()
    try: return ctypes.string_at(target.data,target.size)
    finally: ctypes.windll.kernel32.LocalFree(target.data)


def load_connection():
    try: return json.loads(protect(STORE.read_bytes(),True))
    except (OSError,ValueError,RuntimeError): return {}


def save_connection(value):
    STORE.parent.mkdir(parents=True,exist_ok=True)
    temporary=STORE.with_suffix('.tmp');temporary.write_bytes(protect(json.dumps(value).encode()));temporary.replace(STORE)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None


def api(path,body,token=None):
    headers={'Content-Type':'application/json','User-Agent':'UPI-Guard-Windows/1.0'}
    if token: headers['Authorization']='Bearer '+token
    request=urllib.request.Request(API+path,data=json.dumps(body).encode(),headers=headers,method='POST')
    opener=urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request,timeout=30) as response: return json.load(response)
    except urllib.error.HTTPError as error:
        try: detail=json.load(error).get('detail','The check failed.')
        except (ValueError,OSError): detail='The service returned an unexpected response.'
        raise RuntimeError(detail if isinstance(detail,str) else 'The request could not be completed.') from None
    except (urllib.error.URLError,TimeoutError,OSError):
        raise RuntimeError('The free service may be waking up or offline. Please retry shortly.') from None


def request_payload(message,link=''):
    message=message.strip()[:5000];link=link.strip()[:2048]
    if not link:
        match=re.search(r'https?://[^\s<>"\x27]+|upi://[^\s<>"\x27]+',message,re.I)
        if match: link=match.group(0).rstrip('.,);]')[:2048]
    if not message and not link: raise ValueError('Select or paste a message or link first.')
    return {'message':message or 'Please assess this link and its public page.','link':link,'inspect_link':True,'language':'en','context':'User-requested check from the Windows floating companion.'}


class Companion:
    def __init__(self):
        self.root=tk.Tk();self.root.title('UPI Guard');self.root.overrideredirect(True);self.root.attributes('-topmost',True);self.root.configure(bg='#f5f8f7')
        self.root.geometry(f'58x58+{self.root.winfo_screenwidth()-90}+{self.root.winfo_screenheight()-150}')
        self.button=tk.Canvas(self.root,width=56,height=56,bg='#f5f8f7',highlightthickness=0,cursor='hand2');self.button.pack()
        self.button.create_oval(2,2,54,54,fill='#087f7a',outline='#c7e9df',width=2);self.button.create_text(28,27,text='◈',fill='white',font=('Segoe UI',25,'bold'))
        self.panel=tk.Toplevel(self.root);self.panel.title('UPI Guard — Understand before you act');self.panel.geometry('460x720');self.panel.minsize(390,560);self.panel.attributes('-topmost',True);self.panel.withdraw();self.panel.protocol('WM_DELETE_WINDOW',self.panel.withdraw)
        
        try:
            self.app_icon=tk.PhotoImage(file=str(Path(__file__).with_name('icon.png')));self.panel.iconphoto(True,self.app_icon)
        except tk.TclError:pass
        self.connection=load_connection();self.events=queue.Queue();self.busy=False;self.drag=None
        self.build_panel();self.button.bind('<ButtonPress-1>',self.press);self.button.bind('<B1-Motion>',self.move);self.button.bind('<ButtonRelease-1>',self.release)
        menu=tk.Menu(self.root,tearoff=False);menu.add_command(label='Open checker',command=self.show);menu.add_command(label='Open website',command=lambda:webbrowser.open(WEBSITE));menu.add_separator();menu.add_command(label='Quit UPI Guard',command=self.root.destroy);self.button.bind('<Button-3>',lambda e:menu.tk_popup(e.x_root,e.y_root))
        self.root.update_idletasks()
        if os.name=='nt':
            # Keep the source app focused when the floating shield is clicked.
            ctypes.windll.user32.GetParent.argtypes=[wintypes.HWND];ctypes.windll.user32.GetParent.restype=wintypes.HWND
            ctypes.windll.user32.GetForegroundWindow.restype=wintypes.HWND
            ctypes.windll.user32.GetClassNameW.argtypes=[wintypes.HWND,wintypes.LPWSTR,ctypes.c_int]
            hwnd=ctypes.windll.user32.GetParent(self.root.winfo_id());get_style=ctypes.windll.user32.GetWindowLongW;set_style=ctypes.windll.user32.SetWindowLongW
            set_style(hwnd,-20,get_style(hwnd,-20)|0x08000000|0x00000080)
        self.root.after(80,self.pump)
        if not self.connection.get('token'):self.root.after(250,self.show)

    def build_panel(self):
        style=ttk.Style();style.theme_use('clam');style.configure('TFrame',background='#f5f8f7');style.configure('TLabel',background='#f5f8f7',foreground='#18343f',font=('Segoe UI',10));style.configure('TButton',padding=8,font=('Segoe UI',10),background='#e6f1ec',foreground='#17655d',borderwidth=0);style.map('TButton',background=[('active','#d0e8de')]);style.configure('Accent.TButton',background='#087f7a',foreground='white')
        frame=ttk.Frame(self.panel,padding=18);frame.pack(fill='both',expand=True)
        ttk.Label(frame,text='UPI Guard · beside you',font=('Segoe UI',18,'bold')).pack(anchor='w')
        ttk.Label(frame,text='Select a message, then click the floating shield.\nIf copying is unavailable, paste below.',wraplength=410).pack(anchor='w',pady=(8,12))
        self.status=tk.StringVar(value='Connected to your private workspace.' if self.connection.get('token') else 'Connect using website Settings → Create connection code.')
        ttk.Label(frame,textvariable=self.status,wraplength=410).pack(anchor='w',pady=(0,10))
        pair=ttk.Frame(frame);pair.pack(fill='x');self.code=ttk.Entry(pair,width=18);self.code.pack(side='left',fill='x',expand=True);self.connect_button=ttk.Button(pair,text='Connect code',command=self.connect,style='Accent.TButton');self.connect_button.pack(side='left',padx=(8,0))
        links=ttk.Frame(frame);links.pack(fill='x',pady=8);ttk.Button(links,text='Website / Settings',command=lambda:webbrowser.open(WEBSITE)).pack(side='left');ttk.Button(links,text='Disconnect',command=self.disconnect).pack(side='left',padx=6)
        ttk.Label(frame,text='Message').pack(anchor='w');self.message=tk.Text(frame,height=4,wrap='word',font=('Segoe UI',10),bd=1,relief='solid');self.message.pack(fill='x',pady=(4,8))
        ttk.Label(frame,text='Link (optional)').pack(anchor='w');self.link=ttk.Entry(frame);self.link.pack(fill='x',pady=(4,8))
        buttons=ttk.Frame(frame);buttons.pack(fill='x');self.check_button=ttk.Button(buttons,text='Check message + link',command=self.check,style='Accent.TButton');self.check_button.pack(side='left');ttk.Button(buttons,text='Paste clipboard',command=self.paste).pack(side='left',padx=6);ttk.Button(buttons,text='Clear',command=self.clear).pack(side='left')
        result=ttk.Frame(frame);result.pack(fill='both',expand=True,pady=(14,8));self.result=tk.Text(result,height=1,wrap='word',state='disabled',font=('Segoe UI',10),bg='white',bd=1,relief='solid');self.result.pack(side='left',fill='both',expand=True);scroll=ttk.Scrollbar(result,command=self.result.yview);scroll.pack(side='right',fill='y');self.result.configure(yscrollcommand=scroll.set)
        ttk.Label(frame,text='Only requested text and public-link content go to your backend and OpenAI. No passive screen recording. No payment is made.',wraplength=410,font=('Segoe UI',8)).pack(anchor='w')
        footer=ttk.Frame(frame);footer.pack(fill='x',pady=(10,0));ttk.Button(footer,text='Hide panel',command=self.panel.withdraw).pack(side='left');ttk.Button(footer,text='Quit',command=self.root.destroy).pack(side='right')

    def show(self):
        self.panel.deiconify();self.panel.lift();self.panel.focus_force()
    def press(self,event):
        self.drag=(event.x_root,event.y_root,self.root.winfo_x(),self.root.winfo_y(),False)
    def move(self,event):
        if not self.drag: return
        x,y,wx,wy,_=self.drag;dx=event.x_root-x;dy=event.y_root-y
        if abs(dx)+abs(dy)>6:
            self.drag=(x,y,wx,wy,True);self.root.geometry(f'+{max(0,wx+dx)}+{max(0,wy+dy)}')
    def release(self,_event):
        moved=bool(self.drag and self.drag[4]);self.drag=None
        if not moved:self.copy_selection()
    def copy_selection(self):
        if self.busy:return
        if os.name!='nt':self.show();return
        user=ctypes.windll.user32
        before=user.GetClipboardSequenceNumber()
        foreground=user.GetForegroundWindow();own={user.GetParent(self.root.winfo_id()),user.GetParent(self.panel.winfo_id())}
        if foreground in own:self.show();return
        class_name=ctypes.create_unicode_buffer(256);user.GetClassNameW(foreground,class_name,256)
        if class_name.value.lower() in ('consolewindowclass','cascadia_hosting_window_class','mintty','virtualconsoleclass'):
            self.show();self.status.set('For terminal windows, copy the selected text yourself and choose Paste clipboard.');return
        # A click asks for the selection. Never submit stale clipboard data if copy fails.
        user.keybd_event(0x11,0,0,0);user.keybd_event(0x43,0,0,0);user.keybd_event(0x43,0,2,0);user.keybd_event(0x11,0,2,0)
        def copied():
            changed=user.GetClipboardSequenceNumber()!=before
            self.show()
            if changed:
                try: text=self.root.clipboard_get()
                except tk.TclError:text=''
                if text.strip():self.set_message(text[:5000]);self.check();return
            self.status.set('No fresh selection was copied. Paste the message or link below.')
        self.root.after(220,copied)
    def set_message(self,value):
        self.message.delete('1.0','end');self.message.insert('1.0',value);self.link.delete(0,'end')
    def paste(self):
        try:self.set_message(self.root.clipboard_get()[:5000]);self.status.set('Clipboard text pasted. Choose Check to submit it.')
        except tk.TclError:self.status.set('The clipboard does not contain text.')
    def clear(self):
        if self.busy:return
        self.set_message('');self.write_result('')
    def write_result(self,text):
        self.result.configure(state='normal');self.result.delete('1.0','end');self.result.insert('1.0',text);self.result.configure(state='disabled')
    def background(self,work,done):
        if self.busy:return
        self.busy=True;self.check_button.configure(state='disabled');self.connect_button.configure(state='disabled')
        def runner():
            try:self.events.put((done,work(),None))
            except Exception as error:self.events.put((done,None,str(error)))
        threading.Thread(target=runner,daemon=True).start()
    def pump(self):
        try:
            while True:
                done,value,error=self.events.get_nowait();self.busy=False;self.check_button.configure(state='normal');self.connect_button.configure(state='normal')
                if error:self.status.set(error)
                else:done(value)
        except queue.Empty:pass
        self.root.after(80,self.pump)
    def connect(self):
        code=self.code.get().strip()
        if not code:self.status.set('Create a one-time connection code in website Settings first.');return
        def save(value):
            try:save_connection(value);self.connection=value;self.code.delete(0,'end');self.status.set('Connected. Your device credential is encrypted for this Windows account.')
            except OSError:self.status.set('Could not save the encrypted connection. Check your Windows user folder permissions.')
        self.background(lambda:api('/companion/redeem',{'code':code,'name':'Windows floating companion'}),save)
    def disconnect(self):
        if self.busy:return
        token=self.connection.get('token')
        def remove(_):
            self.connection={}
            try:STORE.unlink(missing_ok=True)
            except OSError:pass
            self.status.set('Disconnected. Create a new code to reconnect.')
        if token:self.background(lambda:api('/companion/disconnect',{},token),remove)
        else:remove(None)
    def check(self):
        if not self.connection.get('token'):self.status.set('Connect a one-time code from website Settings before checking.');return
        try:payload=request_payload(self.message.get('1.0','end'),self.link.get())
        except ValueError as error:self.status.set(str(error));return
        self.status.set('Reading message and public link…');self.write_result('')
        def show_result(r):
            labels={'likely_scam':'LIKELY SCAM','suspicious':'SUSPICIOUS — VERIFY FIRST','no_clear_scam_signals':'NO CLEAR SCAM SIGNALS','insufficient_context':'MORE CONTEXT NEEDED'}
            lines=[labels.get(r['verdict'],'REVIEW NEEDED'),'',r['summary'],'','WARNING SIGNS']
            lines += [f"• {f['signal']}: {f['evidence']}" for f in r.get('red_flags',[])] or ['No specific warning signs returned.']
            if r.get('link_inspection'):
                info=r['link_inspection'];lines+=['','PUBLIC LINK: '+info['status'].upper(),info['reason'],info.get('final_url','')]
            lines+=['','NEXT STEPS']+[f'{i}. {line}' for i,line in enumerate(r['next_steps'],1)]+['','LIMITS OF THIS CHECK']+['• '+line for line in r['limitations']]
            self.write_result('\n'.join(lines));self.status.set('Check saved to your private website history.')
        self.background(lambda:api('/companion/analyze',payload,self.connection['token']),show_result)
    def run(self):self.root.mainloop()


if __name__=='__main__':Companion().run()
