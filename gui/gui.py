""" MQTT payload crypt analyzing tool """
# pylint: disable=W0703
import sys
import traceback
import hashlib
from paho.mqtt import publish
import hexdump

if sys.version_info[0] >= 3:
    import tkinter as tk
else:
    import Tkinter as tk

# pylint: disable=C0413
# Allow module import from upper level
sys.path.append('../')
from mcont import mcont
import mfile

#pylint: disable=R0901
class PwApp(tk.Frame):
    """ Password application class """
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        master.resizable(False, False)
        self.pw_fail_cnt = 0
        top = self.top = master
        pw_label = tk.Label(top, text="Password")
        self.raw_pw = tk.Entry(top, show=u"\u2620")
        ok_button = tk.Button(top, text='Ok', command=self.ok_click)
        new_button = tk.Button(top, text='New', command=self.new_click)
        exit_button = tk.Button(top, text='Exit', command=self.exit_click)

        pw_label.pack(fill=tk.X, padx=10)
        self.raw_pw.pack()

        ok_button.pack(fill=tk.X, padx=10, side=tk.LEFT)
        new_button.pack(fill=tk.X, padx=10, side=tk.LEFT)
        exit_button.pack(fill=tk.X, padx=10, side=tk.LEFT)

        self.status = tk.Label(self.top, text="Waiting...")
        self.status.pack()

    def ok_click(self):
        """ Handle ok button """
        password = self.raw_pw.get()
        password = hashlib.sha512(password.encode()).hexdigest()
        lc_fp = mfile.mfile.LocalSecrets(password)
        sc_tuple = lc_fp.read("GENERAL", "PWHash")
        if sc_tuple and sc_tuple[0] == password:
            mfile.pw = password
            mcont.selftest(password)
            self.top.destroy()
        else:
            self.pw_fail_cnt = self.pw_fail_cnt + 1
            self.status['text'] = 'Failed, 5/' + str(self.pw_fail_cnt)
            if self.pw_fail_cnt > 5:
                self.top.destroy()
                sys.exit(1)

    def new_click(self):
        """ Handle new button """
        password = self.raw_pw.get()
        password = hashlib.sha512(password.encode()).hexdigest()
        lc_fp = mfile.mfile.LocalSecrets(password, force_new=True)
        mfile.pw = password
        lc_fp.write(password, None, "GENERAL", "PWHash")
        self.status['text'] = 'Generating keys...'
        self.status.pack()
        mcont.selftest(password)
        self.status['text'] = 'OK'
        self.status.pack()
        self.top.destroy()

    def exit_click(self):
        """ Handle exit button """
        self.top.destroy()
        sys.exit(0)

#pylint: disable=R0902
#pylint: disable=R0915
class App(tk.Frame):
    """ GUI application class """
    def __init__(self, master):
        tk.Frame.__init__(self, master)

        master.resizable(False, False)

        self.algs = mcont.get_available_algorithms()
        self.macs = mcont.get_available_macs()
        self.rands = mcont.get_available_rands()
        self.tstamps = mcont.get_available_tstamp()
        self.seqs = mcont.get_available_seqs()
        self.mqtt_path = None

        self.variable_alg = tk.StringVar(self)
        self.variable_key = tk.StringVar(self)
        self.variable_mode = tk.StringVar(self)
        self.variable_mac = tk.StringVar(self)
        self.variable_rands = tk.StringVar(self)
        self.variable_tstamps = tk.StringVar(self)
        self.variable_seqs = tk.StringVar(self)
        self.mqtt_path_str = tk.StringVar(self, value=' ')
        self.mqtt_host = tk.StringVar(self)
        self.mqtt_port = tk.StringVar(self)
        self.mqtt_id = tk.StringVar(self)

        self.variable_alg.trace('w', self.update_alg_options)
        self.variable_key.trace('w', self.update_options)
        self.variable_mode.trace('w', self.update_options)

        self.optionmenu_alg = tk.OptionMenu(self, self.variable_alg, *self.algs)
        self.optionmenu_key = tk.OptionMenu(self, self.variable_key, '')
        self.optionmenu_mode = tk.OptionMenu(self, self.variable_mode, '')
        self.optionmenu_hmacs = tk.OptionMenu(self, self.variable_mac, *self.macs)
        self.optionmenu_rands = tk.OptionMenu(self, self.variable_rands, *self.rands)
        self.optionmenu_tstamps = tk.OptionMenu(self, self.variable_tstamps, *self.tstamps)
        self.optionmenu_seqs = tk.OptionMenu(self, self.variable_seqs, *self.seqs)


        self.variable_alg.set('NONE')
        self.variable_key.set('0')
        self.variable_mode.set('NONE')
        self.variable_mac.set('NONE')
        self.variable_rands.set('0')
        self.variable_tstamps.set('NONE')
        self.variable_seqs.set('NONE')
        self.alg = mcont.MCONT('NONE')

        self.mqtt_path = tk.Entry(self, width=30, textvariable=self.mqtt_path_str)
        self.mqtt_host = tk.Entry(self, width=30)
        self.mqtt_port = tk.Entry(self, width=10)
        self.mqtt_id = tk.Entry(self, width=20)

        tk.Label(self, text="Select algorithm").grid(row=1, column=0)

        tk.Label(self, text="Algorithm:", anchor="w").grid(row=2, column=0)
        self.optionmenu_alg.grid(row=2, column=1)

        tk.Label(self, text="Key lenght:", anchor="w").grid(row=3, column=0)
        self.optionmenu_key.grid(row=3, column=1)

        tk.Label(self, text="Mode", anchor="w").grid(row=4, column=0)
        self.optionmenu_mode.grid(row=4, column=1)

        tk.Label(self, text="Additional parameters").grid(row=1, column=2)

        tk.Label(self, text="Hash", anchor="w").grid(row=2, column=2)
        self.optionmenu_hmacs.grid(row=2, column=3)

        tk.Label(self, text="Random bytes", anchor="w").grid(row=3, column=2)
        self.optionmenu_rands.grid(row=3, column=3)

        tk.Label(self, text="TStamp", anchor="w").grid(row=4, column=2)
        self.optionmenu_tstamps.grid(row=4, column=3)

        tk.Label(self, text="Sequence#", anchor="w").grid(row=5, column=2)
        self.optionmenu_seqs.grid(row=5, column=3)

        tk.Label(self, text="Path:").grid(row=6, column=0)
        self.mqtt_path.grid(row=6, column=1)

        tk.Label(self, text="Broker addr:").grid(row=9, column=0)
        self.mqtt_host.grid(row=9, column=1)

        tk.Label(self, text="Broker Port:").grid(row=9, column=2)
        self.mqtt_port.grid(row=9, column=3)

        tk.Label(self, text="Client ID").grid(row=10, column=0)
        self.mqtt_id.grid(row=10, column=1)

        self.randomize_var = tk.IntVar()
        self.randomize_chk = tk.Checkbutton(self,
                                            text="Randomize payload dict",
                                            variable=self.randomize_var,
                                            onvalue=1,
                                            offvalue=None)
        self.randomize_chk.grid(row=2, column=4)

        self.splitrand_var = tk.IntVar()
        self.splitrand_chk = tk.Checkbutton(self,
                                            text="Split random bytes around",
                                            variable=self.splitrand_var,
                                            onvalue=1,
                                            offvalue=None)

        self.splitrand_chk.grid(row=3, column=4)


        self.send_button = tk.Button(text="Send", command=self.sendmqtt)
        self.send_button.pack(fill=tk.X, padx=10)

        self.clear_button = tk.Button(text="Clear", command=self.clear)
        self.clear_button.pack(fill=tk.X, padx=10)

        self.dump = tk.Text(master, width=100, height=15)
        self.dump.pack(fill=tk.X, padx=10, anchor=tk.N)

        self.pack()

    def clear(self):
        """ Clear dump section - text part on UI """
        if self.dump:
            self.dump.delete('1.0', tk.END)

    def open_conf(self):
        """ Open configuration file """
        ls_fp = mfile.mfile.LocalSecrets(mfile.pw)
        sc_tuple = ls_fp.read("MQTT", "Settings")
        if sc_tuple is None:
            ls_fp.write("", "", "MQTT", "Settings")
            sc_tuple = ls_fp.read("MQTT", "Settings")

        self.mqtt_host.delete(0, 'end')
        self.mqtt_host.insert(tk.END, sc_tuple[0])
        self.mqtt_port.delete(0, 'end')
        self.mqtt_port.insert(tk.END, sc_tuple[1])

    def update_alg_options(self, *args):
        """ Get supported algorithms to drop down list """
        args = args
        alg = self.variable_alg.get()
        self.alg = mcont.MCONT(alg, mfile.pw)
        keys = self.alg.get_key_len()
        self.variable_key.set(keys[0])

        menu = self.optionmenu_key['menu']
        menu.delete(0, 'end')

        for key in keys:
            menu.add_command(label=key,
                             command=lambda key_len=key: self.variable_key.set(key_len))

        modes = self.alg.get_modes()
        self.variable_mode.set(modes[0])

        menu = self.optionmenu_mode['menu']
        menu.delete(0, 'end')

        for mode in modes:
            menu.add_command(label=mode,
                             command=lambda alg_mode=mode: self.variable_mode.set(alg_mode))

        self.update_path()

    def update_options(self, *args):
        """ Update path  """
        args = args
        self.update_path()

    def update_path(self):
        """ Update path  """
        if self.alg:
            mode = self.variable_mode.get()
            if mode != "NONE":
                self.alg.set_mode(self.variable_mode.get())
            self.alg.set_key_len(self.variable_key.get())
            if self.mqtt_path:
                path = self.alg.get_path()
                self.mqtt_path.delete(0, 'end')
                self.mqtt_path.insert(tk.END, path)

    #pylint: disable=R0914
    def sendmqtt(self):
        """ Send MQTT message to broker using selected parameters """
        if self.alg:
            value = self.dump.get("1.0", tk.END).rstrip()
            mac = self.variable_mac.get()
            rnd = self.variable_rands.get()
            mode = self.variable_mode.get()
            tstamp = self.variable_tstamps.get()
            seq = self.variable_seqs.get()
            rnddict = self.randomize_var.get()
            randsplit = self.splitrand_var.get()
            package = None
            try:
                package = self.alg.construct(value,
                                             mac,
                                             int(rnd),
                                             mode,
                                             tstamp,
                                             seq,
                                             rnddict,
                                             randsplit)
            except ValueError:
                if self.dump:
                    self.dump.delete('1.0', tk.END)
                    self.dump.insert(tk.INSERT,
                                     "Message did not fit into the block")
                return
            except Exception as failure:
                if self.dump:
                    self.dump.delete('1.0', tk.END)
                    self.dump.insert(tk.INSERT, str(failure))
                    trace = traceback.format_exc()
                    self.dump.insert(tk.INSERT, "\nDump:\n")
                    self.dump.insert(tk.INSERT, str(trace))

                return

            if self.dump:
                #self.dump.delete('start', 'end')
                if isinstance(package["Ciphertext"], str):
                    hx_value = package["Ciphertext"].encode()
                else:
                    hx_value = package["Ciphertext"]
                hx_value = hexdump.dump(hx_value, size=4, sep=' ')
                self.dump.delete('1.0', tk.END)
                self.dump.insert(tk.INSERT, "Ciphertext\n")
                self.dump.insert(tk.INSERT, hx_value)
                self.dump.insert(tk.INSERT, "\n\nPlaintext\n")
                self.dump.insert(tk.INSERT, package["Plaintext"])
                self.dump.insert(tk.INSERT, "\n\nPath\n")
                self.dump.insert(tk.INSERT, package["Path"])
                self.dump.insert(tk.INSERT, "\n\nPlaintext vs. ciphertext\n")
                plaintxt = len(package["Plaintext"])
                ciphertext = len(package["Ciphertext"])
                dump_txt = "Plaintext " + str(plaintxt) + " bytes - Ciphertext " + \
                    str(ciphertext) + " bytes ratio P/C " + str(round(plaintxt/ciphertext, 5))
                self.dump.insert(tk.INSERT, dump_txt)
                self.dump.insert(tk.INSERT, "\n\nUsed path vs. set path\n")
                self.dump.insert(tk.INSERT, package["Path"] + " " + str(self.alg.get_path()))
                self.dump.insert(tk.INSERT, "\n\nEncrypt duration\n")
                self.dump.insert(tk.END, str(round(package["Duration"], 8)) + "\n")

            if self.mqtt_host and self.mqtt_port:
                lc_fp = mfile.mfile.LocalSecrets(mfile.pw)
                sc_tuple = lc_fp.read("MQTT", "Settings")
                if sc_tuple is None:
                    lc_fp.write(self.mqtt_host.get(),
                                self.mqtt_port.get(),
                                "MQTT", "Settings")
                    sc_tuple = lc_fp.read("MQTT", "Settings")
                else:
                    if sc_tuple[0] != self.mqtt_host.get() or sc_tuple[1] != self.mqtt_port.get():
                        lc_fp.write(self.mqtt_host.get(),
                                    self.mqtt_port.get(),
                                    "MQTT", "Settings")
                        sc_tuple = lc_fp.read("MQTT", "Settings")

                try:
                    publish.single(self.mqtt_path.get(),
                                   package["Ciphertext"],
                                   qos=0,
                                   retain=False,
                                   hostname=sc_tuple[0],
                                   port=int(sc_tuple[1]),
                                   client_id=self.mqtt_id.get(),
                                   keepalive=0)
                except Exception as failure:
                    #self.dump.delete('1.0', tk.END)
                    self.dump.insert(tk.INSERT, "MQTT failure\n")
                    self.dump.insert(tk.INSERT, str(failure))

if __name__ == "__main__":
    TK_ROOT = tk.Tk()
    PW_APP = PwApp(TK_ROOT)
    PW_APP.mainloop()

    LS_FP = mfile.mfile.LocalSecrets(mfile.pw)
    SC_TUPLE = LS_FP.read("MQTT", "Settings")
    if SC_TUPLE is None:
        LS_FP.write("", "", "MQTT", "Settings")
        SC_TUPLE = LS_FP.read("MQTT", "Settings")

    TK_ROOT = tk.Tk()
    GUI_APP = App(TK_ROOT)
    GUI_APP.open_conf()
    GUI_APP.update_path()
    GUI_APP.mainloop()
