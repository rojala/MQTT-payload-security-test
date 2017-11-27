""" MQTT payload crypt analyzing tool """
# pylint: disable=W0703
import os
import sys
import shutil
import traceback
import hashlib
import time
import json
import pickle
import threading
from paho.mqtt import publish
import hexdump
import subprocess
import logging

logging.basicConfig(level=logging.DEBUG,
                    format='[%(levelname)s] (%(threadName)-10s) %(message)s',
                    )

if sys.version_info[0] >= 3:
    import tkinter as tk
else:
    import Tkinter as tk

# pylint: disable=C0413
# Allow module import from upper level
sys.path.append('../')
from mcont import mcont
import mfile
from analyze.analyze import analyze_randomness

DUMP = None

# #################################################################
# PW UI
# #################################################################
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

# #################################################################
# TEST PROCESSES
# #################################################################

def test_a_algo_process(params):
    arand = analyze_randomness(10, 2)
    res = None
    try:
        #params.print("S")
        res = params.run()
    except Exception as failure:
        #pass
        trace = traceback.format_exc()
        logging.debug("Exception: " + str(failure))
        logging.debug("Exception: " + trace)
    #params.print("X", 1)
    return res

def test_process_algos(params):
    logging.debug("Starting")
    from multiprocessing import Pool
    import multiprocessing

    try:
        shutil.rmtree("analyse_temp", ignore_errors=True)
        if not os.path.exists("analyse_temp"):
            os.makedirs("analyse_temp")
        threads = multiprocessing.cpu_count()
        if 1 < threads:
            threads -= 1
        pool = Pool(threads)
        results = pool.map(test_a_algo_process, params)
        #DUMP.delete('1.0', tk.END)
        #DUMP.insert(tk.INSERT, "Processing completed\n")
        with open("results.bin", mode='wb') as write_fb:
            content = pickle.dumps(results)
            write_fb.write(content)
        #DUMP.insert(tk.INSERT, "results.bin written.\n")
    except Exception as failure:
        #pass
        trace = traceback.format_exc()
        logging.debug("Exception: " + str(failure))
        logging.debug("Exception: " + trace)
    logging.debug("Completed")

class test_data(object):
    def __init__(self, myalg,
                       alg,
                       rounds,
                       send_value,
                       key_len,
                       mac,
                       rnd,
                       mode,
                       tstmp,
                       seq,
                       suffle,
                       split):

        self.myalg = myalg
        self.alg = alg
        self.rounds = rounds
        self.send_value = send_value
        self.mac = mac
        self.key_len = key_len
        self.rnd = rnd
        self.mode = mode
        self.tstmp = tstmp
        self.seq = seq
        self.suffle = suffle
        self.split = split
        self.score = -1
        self.res = {"Alg":    alg,    "Keyl" : key_len,
                    "Mode":   mode,   "Hash" : mac,
                    "Tst":    tstmp,  "Seq"  : seq,
                    "Rnd":    rnd,    "Split": self.split,
                    "Suffle": suffle, "Score": self.score}
        self.datatofile = []

    def run(self):
        try:
            self.print(r"->", 0)
            arand = analyze_randomness(10, 2)
            for tstrnd in range(0, self.rounds):
                ctxt = self.myalg.construct(self.send_value, self.mac,
                                            int(self.rnd), self.mode,
                                            self.tstmp, self.seq,
                                            self.suffle, self.split)
                arand.add(ctxt["Ciphertext"])
                self.datatofile.append(ctxt["Ciphertext"])
                #logging.debug("cipher: " + str(ctxt))
            self.score = arand.analyze()
            self.res["Score"] = self.score
            self.writefile()
            self.print(r"<-", 1)
        except Exception as failure:
            #pass
            trace = traceback.format_exc()
            logging.debug("Exception: " + str(failure))
            logging.debug("Exception: " + trace)
        return self.res

    def writefile(self):
        dbg = self.gettag()
        try:
            dbg = dbg.replace(" ", "_").replace(":", "-").replace(r"%", "mod")
            outfp = open("analyse_temp/" + dbg + ".csv", "w")
            if outfp:
                cnt = 0
                for row in self.datatofile:
                    outfp.write("%d,%s\n" % (cnt,row))
                    cnt += 1
                outfp.close()
        except Exception as failure:
            print(failure)
            sys.exit(2)
 
    def gettag(self):
        dbg = "Alg:" + self.alg + " Keyl:" + self.key_len + \
              " Mode:" + self.mode + " Hash:" + self.mac +  \
              " Tst:" + self.tstmp + " Seq:" + self.seq + \
              " Rnd:" + str(self.rnd) + " Split:" + str(self.split) + \
              " Suffle:" + str(self.suffle)
        return dbg
 
    def print(self, prefix, print_score=0):
        dbg = self.gettag()
        if print_score:
            dbg += " Score:" + str(self.score)

        logging.debug(prefix + " " + dbg)


# #################################################################
# UI
# #################################################################
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


        tk.Label(self, text="#test rounds:").grid(row=9, column=4)
        self.numtestrnds.grid(row=10, column=4)
        self.numtestrnds.insert(tk.END, "5")

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

        self.test_button = tk.Button(text="Test", command=self.test)
        self.test_button.pack(fill=tk.X, padx=10)

        self.dump = tk.Text(master, width=100, height=15)
        self.dump.pack(fill=tk.X, padx=10, anchor=tk.N)

        self.pack()

        global DUMP
        DUMP = self.dump

    def clear(self):
        """ Clear dump section - text part on UI """
        if self.dump:
            self.dump.delete('1.0', tk.END)

            res = None

    def test_a_algo_run(self, params):
        logging.debug("--->")
        threading.Thread(target=test_process_algos, args=(params,)).start()
        logging.debug("<---")

    def test(self):
        """ Test all possible compinations with given data.
            Single test is executed as many times as desired,
            but minimum is 2 times """

        send_value = self.dump.get("1.0", tk.END).rstrip()
        self.dump.delete('1.0', tk.END)
        rounds = int(self.numtestrnds.get()) # error not tested text, negative
        if 4 > rounds:
            self.dump.insert(tk.INSERT, "5 test rounds is minimum - test cancelled")
            return
        elif 200 < rounds:
            self.dump.insert(tk.INSERT, "200 test rounds is maximum - test cancelled")
            return
        mac = self.variable_mac.get()
        rnd = self.variable_rands.get()
        seq = self.variable_seqs.get()

        runme = []
        try:
            cnt = 1
            for alg in mcont.get_available_algorithms():                # algorithms ["NONE"]: #
                test_ciphertext = []
                self.dump.see(tk.END)
                myalg = mcont.MCONT(alg.upper(), mfile.pw)              # select algorithm
                for key in  myalg.get_key_len():                        # key lens
                    myalg.set_key_len(key)                              # set keylen
                    for mode in myalg.get_modes():                      # modes
                        for mac in self.macs:                           # hash functions
                            for tstmp in self.tstamps:                  # timestamps
                                for seq in self.seqs:                   # sequence numbers
                                    for rnd in self.rands:              # random functions
                                        for split in range(0, 2):       # split random numbers
                                            for suffle in range(0, 2):  # suffle payload dict
                                                cnt += rounds
                                                tsd = test_data(myalg,
                                                                alg,
                                                                rounds,
                                                                send_value,
                                                                key,
                                                                mac,
                                                                rnd,
                                                                mode,
                                                                tstmp,
                                                                seq,
                                                                suffle,
                                                                split)
                                                runme.append(tsd)

            self.dump.delete('1.0', tk.END)
            self.dump.insert(tk.INSERT, "Please wait - processing " + str(cnt))
            self.dump.insert(tk.INSERT, " test runs\n")
            self.dump.insert(tk.INSERT, "will take quite some time!\n")
            self.test_a_algo_run(runme)
        except Exception as e:
            self.dump.insert(tk.INSERT,str(e))

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
                self.dump.insert(tk.INSERT, "\n\nPlaintext/Payload vs. ciphertext\n")
                plaintxt = len(package["Plaintext"])
                payload = len(json.dumps(package["Payload"]))
                ciphertext = len(package["Ciphertext"])
                dump_txt = "Plaintext " + str(plaintxt) + " bytes - Ciphertext " + \
                    str(ciphertext) + " bytes ratio P/C " + str(round(plaintxt/ciphertext, 5)) + "\n"
                self.dump.insert(tk.INSERT, dump_txt)
                dump_txt = "Payload " + str(payload) + " bytes - Ciphertext " + \
                    str(ciphertext) + " bytes ratio P/C " + str(round(payload/ciphertext, 5)) + "\n"
                self.dump.insert(tk.INSERT, dump_txt)
                self.dump.insert(tk.INSERT, "\nUsed path vs. set path\n")
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
