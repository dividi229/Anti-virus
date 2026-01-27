import requests
import os
import time
import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter import filedialog

print("Program started.")

# API_KEY
API_KEY = "Your api"
# The file/path
file_path = ""
# headers
headers = {
    "x-apikey": API_KEY
 }



# Send the file/path
def check_file():
    global file_path
    if not file_path:
        print("Select file!")
        return

    response = upload_file_to_virustotal(file_path, headers)
    data = response.json()

    analysis_id = data["data"]["id"]


    while True:
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_response = requests.get(analysis_url, headers=headers)
        analysis_data = analysis_response.json()

        status = analysis_data["data"]["attributes"]["status"]
        if status == "completed":
            stats = analysis_data["data"]["attributes"]["stats"]
            print("results is :")
            print(f"harmless: {stats['harmless']}")
            print(f"malicious: {stats['malicious']}")
            print(f"suspicious: {stats['suspicious']}")
            print(f"undetected: {stats['undetected']}")

            if stats['malicious'] > 0 or stats['suspicious'] > 0:
                negative_window()
            else:
                positive_window()
            break
        else:
            print("BRO JUST WAIT.................")
            time.sleep(5)






#All def

def openFile():
    global file_path
    file_path = filedialog.askopenfilename()
    result1.delete(0, tk.END)
    result1.insert(tk.END, file_path)
    print("Selected file path:", file_path) 

def positive_window():
    window = Tk()
    window.grab_set()
    window.title("Result")
    window.geometry("700x500")
    window.maxsize(1676, 800)
    my_label1 = Label(window,
                      text='your PC got 0 virus you smart like albert einstein 💀',
                      font=50
    )
    my_label1.pack(pady=20)
    print("you are albert einstein💀")
    r.destroy()

def negative_window():
    print("Checking file:", file_path)
    window = Tk()
    window.grab_set()
    window.title("Result")
    window.geometry("700x500")
    window.maxsize(1676, 800)
    my_label1 = Label(window,
                      text=f'OMG! Hitler virus detected on your PC!',
                      font=50)
    my_label1.pack(pady=20)
    print("your PC got virus L")
    r.destroy()  


def upload_file_to_virustotal(file_path, headers):
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
    return response




#menu
r = tk.Tk()
r.title('Virus Detector Ver.67')
r.geometry("500x220")
r.minsize(500, 220)
r.maxsize(1676, 300)
Grid.rowconfigure(r,0,weight=1)
Grid.columnconfigure(r,0,weight=1)
Grid.rowconfigure(r,1,weight=1)
Grid.rowconfigure(r,2,weight=1)

button1 = tk.Button(r, text='Enter Path', command=openFile)
button2 = tk.Button(r, text='Check for Virus', command=check_file)
button1.grid(row = 0, column = 0, sticky = N+S+E+W)
button2.grid(row = 2, column = 0, sticky = N+S+E+W)
result1 = tk.Entry(r)
result1.grid(row = 1, column = 0, sticky = N+S+E+W)

r.mainloop()


print("Program ended.")









