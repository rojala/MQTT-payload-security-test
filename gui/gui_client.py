""" MQTT crypto test client application """

import sys
import signal
import traceback
import hashlib
import hexdump
import paho.mqtt.client as mqtt

if sys.version_info[0] >= 3:
    import tkinter as tk
else:
    import Tkinter as tk

# pylint: disable=C0413
sys.path.append('../')
from mcont import mcont
import mfile

DUMP = None
MQTTC = None

# pylint: disable=W0603
# pylint: disable=W0703

def on_message(client, userdata, message):
    """ MQTT - receive messages """
    client = client
    userdata = userdata
    global DUMP
    try:
        DUMP.delete('1.0', tk.END)
        cont = mcont.MCONT(None, mfile.pw)
        package = cont.destruct(message.payload, message.topic)
        print(package)

        if isinstance(package["Ciphertext"], str):
            hx_value = package["Ciphertext"].encode()
        else:
            hx_value = package["Ciphertext"]

        hx_value = hexdump.dump(hx_value, size=4, sep=' ')
        DUMP.insert(tk.INSERT, "MQTT msg received\n")
        DUMP.insert(tk.INSERT, "Ciphertext\n")
        DUMP.insert(tk.INSERT, hx_value)
        DUMP.insert(tk.INSERT, "\n\nPlaintext\n")
        DUMP.insert(tk.INSERT, package["Plaintext"])
        DUMP.insert(tk.INSERT, "\n\nPath\n")
        DUMP.insert(tk.INSERT, package["Path"])
        DUMP.insert(tk.INSERT, "\n\nDecrypt duration\n")
        DUMP.insert(tk.END, str(round(package["Duration"], 8)) + "\n")

    except ValueError:
        DUMP.delete('1.0', tk.END)
        DUMP.insert(tk.INSERT, "Hash failure\n")
        #DUMP.insert(tk.INSERT, "\nBacktrace\n")
        #DUMP.insert(tk.INSERT, str(traceback.format_exc()))

    except Exception as failure:
        DUMP.delete('1.0', tk.END)
        DUMP.insert(tk.INSERT, str(failure))
        DUMP.insert(tk.INSERT, "\nBacktrace\n")
        DUMP.insert(tk.INSERT, str(traceback.format_exc()))

def mqtt_init():
    """ initialize MQTT """
    try:
        lc_fp = mfile.mfile.LocalSecrets(mfile.pw)
        sc_tuple = lc_fp.read("MQTT", "Settings")
        if sc_tuple is None:
            lc_fp.write("", "", "MQTT", "Settings")
            sc_tuple = lc_fp.read("MQTT", "Settings")

        broker_address = sc_tuple[0]
        client = mqtt.Client() #create new instance
        client.on_message = on_message #attach function to callback
        client.connect(broker_address, port=int(sc_tuple[1])) #connect to broker
        client.loop_start() #start the loop
        client.subscribe("TTKS0600/#")

        global MQTTC
        MQTTC = client
        DUMP.insert(tk.INSERT, "MQTT Ready\n")

    except Exception as failure:
        DUMP.insert(tk.INSERT, failure)

# pylint: disable=R0901
class PwApp(tk.Frame):
    """ Password UI"""
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        master.resizable(False, False)
        self.pw_fail_cnt = 0
        top = self.top = master
        lable_pw = tk.Label(top, text="Password")
        self.raw_pw = tk.Entry(top, show=u"\u2620")
        button_ok = tk.Button(top, text='Ok', command=self.ok_click)
        button_exit = tk.Button(top, text='Exit', command=self.exit_click)

        lable_pw.pack(fill=tk.X, padx=10)
        self.raw_pw.pack()

        button_ok.pack(fill=tk.X, padx=10, side=tk.LEFT)
        button_exit.pack(fill=tk.X, padx=10, side=tk.LEFT)

        self.status = tk.Label(self.top, text="Waiting...")
        self.status.pack()

    def ok_click(self):
        """ OK Button """
        password = self.raw_pw.get()
        password = hashlib.sha512(password.encode()).hexdigest()
        mfile.pw = password
        lc_fp = mfile.mfile.LocalSecrets(password)
        sc_tuple = lc_fp.read("GENERAL", "PWHash")
        if sc_tuple and sc_tuple[0] == password:
            mfile.pw = password
            self.top.destroy()
        else:
            self.pw_fail_cnt = self.pw_fail_cnt + 1
            self.status['text'] = 'Failed, 5/' + str(self.pw_fail_cnt)
            if self.pw_fail_cnt > 5:
                self.top.destroy()
                sys.exit(1)

    def exit_click(self):
        """ Exit button """
        self.top.destroy()
        sys.exit(0)

# pylint: disable=C0413
class App(tk.Frame):
    """ Client APPGUI """
    def __init__(self, master):
        tk.Frame.__init__(self, master)
        master.resizable(False, False)
        self.maser = master
        self.connect_button = tk.Button(text="Connect",
                                        command=self.connect)
        self.exit_button = tk.Button(text="Exit",
                                     command=self.exit)
        tk.Label(self, text="").grid(row=1, column=0)
        self.connect_button.pack()
        self.exit_button.pack()
        self.dump = tk.Text(master)
        self.dump.pack()
        self.pack()

        global DUMP
        DUMP = self.dump

    def connect(self):
        """ MQTT Connect """
        self = self
        mqtt_init()

    def exit(self):
        """ Exit app - stop MQTT """
        if MQTTC:
            MQTTC.loop_stop() #stop the mqtt loop
        self.master.destroy()

# pylint: disable=W0621
# pylint: disable=W0613
def signal_handler(signal=None, frame=None):
    """ Catch ctrl+c """
    print('Ctrl+C')
    global MQTTC
    if MQTTC:
        MQTTC.loop_stop()
    sys.exit(0)

# pylint: enable=W0621
# pylint: enable=W0613

def main():
    """ App main """
    #Napataan ctrl-c
    signal.signal(signal.SIGINT, signal_handler)
    tk_root = tk.Tk()
    pw_app = PwApp(tk_root)
    pw_app.mainloop()

    lc_fp = mfile.mfile.LocalSecrets(mfile.pw)
    sc_tuble = lc_fp.read("MQTT", "Settings")
    if sc_tuble is None:
        sys.exit()

    tk_root = tk.Tk()
    main_app = App(tk_root)
    main_app.mainloop()

if __name__ == "__main__":
    main()
