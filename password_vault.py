import hashlib
import sqlite3
from functools import partial
from tkinter import *
from tkinter import messagebox, simpledialog, ttk
import smtplib
import random

from password_generator import passGenerator

# Database Code (you can rename your database file to something less obvious)
with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
platform TEXT NOT NULL,
account TEXT NOT NULL,
password TEXT NOT NULL);
""")

# Create PopUp


def popUp(text):
    answer = simpledialog.askstring("input string", text)

    return answer

# Initiate Window


window = Tk()
window.update()

window.title("Password Vault")


def hashPassword(input):
    hash1 = hashlib.md5(input)
    hash1 = hash1.hexdigest()

    return hash1

#   Set up master password screen #######################################


def firstTimeScreen():
    window.geometry("250x150")

    lbl = Label(window, text="Create Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Re-enter Password")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*")
    txt1.pack()

    def savePassword():
        if txt.get() == txt1.get():
            hashedPassword = hashPassword(txt.get().encode('utf-8'))

            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?) """
            cursor.execute(insert_password, [hashedPassword])
            db.commit()
            vaultScreen()

        else:
            lbl.config(text="Passwords don't match")

    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=5)

#   Login screen #######################################


def loginScreen():
    window.geometry("250x100")

    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.pack()

    def getMasterPassword():
        checkhashedpassword = hashPassword(txt.get().encode("utf-8"))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [checkhashedpassword])

        return cursor.fetchall()

    def checkPassword():
        password = getMasterPassword()

        if password:
            otp_ver()

        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password")

    btn = Button(window, text="Submit", command=checkPassword)
    btn.pack(pady=5)

# OTP VERIFICATION.
    def otp_ver():
        otp = random.randint(1000, 9999)
        otp = str(otp)

        def send():
            try:
                s = smtplib.SMTP("smtp.gmail.com", 587)  # 587 is a port number
                s.starttls()
                s.login("krishnadembla708@gmail.com", "vaultaccount24")
                s.sendmail("krishnadembla708@gmail.com", "krishnadembla2001@gmail.com", otp)
                messagebox.showinfo("Send OTP via Email", f"OTP sent to your mail.")
                s.quit()

            except:
                messagebox.showinfo("Send OTP via Email",
                                    "Please enter the valid email address OR check an internet connection")

        send()
        root = Tk()
        root.title("OTP Verification")
        root.geometry("565x250")
        email_label = Label(root, text="Enter OTP: ")
        email_label.grid(row=0, column=0, padx=15, pady=60)
        email_entry = Entry(root, width=25,)
        email_entry.grid(row=0, column=1, padx=12, pady=60)
        email_entry.focus()

        def verify():
            if email_entry.get() == otp:
                root.destroy()
                vaultScreen()
            else:
                messagebox.showinfo("Incorrect OTP", "Please check and rewrite.")

        send_button = Button(root, text="Check OTP",command=verify)
        send_button.place(x=210, y=150)
        root.mainloop()


#   Vault functionalities #######################################


def vaultScreen():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"

        website = popUp(text1)
        username = popUp(text2)
        password = popUp(text3)

        insert_fields = """INSERT INTO vault(platform, account, password)
        VALUES(?, ?, ?)"""

        cursor.execute(insert_fields, (website, username, password))
        db.commit()
        vaultScreen()

    def updateEntry(input):
        update = "Type new password"
        password = popUp(update)

        cursor.execute("UPDATE vault SET password = ? WHERE id = ?", (password, input,))
        db.commit()
        vaultScreen()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        vaultScreen()

    def copyAcc(input):
        window.clipboard_clear()
        window.clipboard_append(input)

    def copyPass(input):
        window.clipboard_clear()
        window.clipboard_append(input)

#   Window layout #######################################

    window.geometry("650x350")
    main_frame = Frame(window)
    main_frame.pack(fill=BOTH, expand=1)

    my_canvas = Canvas(main_frame)
    my_canvas.pack(side=LEFT, fill=BOTH, expand=1)

    my_scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=my_canvas.yview)
    my_scrollbar.pack(side=RIGHT, fill=Y)

    my_canvas.configure(yscrollcommand=my_scrollbar.set)
    my_canvas.bind('<Configure>', lambda e: my_canvas.configure(scrollregion=my_canvas.bbox("all")))

    second_frame = Frame(my_canvas)

    my_canvas.create_window((0, 0), window=second_frame, anchor="nw")

    lbl = Label(second_frame, text="Password Vault by KryTax")
    lbl.grid(column=2)

    btn2 = Button(second_frame, text="Generate Password", command=passGenerator)
    btn2.grid(column=0, pady=10)

    btn = Button(second_frame, text="Add Credentials", command=addEntry)
    btn.grid(row = 1,column=1, pady=10)

    lbl = Label(second_frame, text="Website")
    lbl.grid(row=2, column=0, padx=40)
    lbl = Label(second_frame, text="Username")
    lbl.grid(row=2, column=1, padx=40)
    lbl = Label(second_frame, text="Password")
    lbl.grid(row=2, column=2, padx=40)

    cursor.execute("SELECT * FROM vault")

#   Buttons Layout #######################################

    if cursor.fetchall() is not None:
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            lbl1 = Label(second_frame, text=(array[i][1]))
            lbl1.grid(column=0, row=i + 3)
            lbl2 = Label(second_frame, text=(array[i][2]))
            lbl2.grid(column=1, row=i + 3)
            lbl3 = Label(second_frame, text=(array[i][3]))
            lbl3.grid(column=2, row=i + 3)
            btn2 = Button(second_frame, text="Copy User", command=partial(copyAcc, array[i][2]))
            btn2.grid(column=3, row=i + 3, pady=10)
            btn3 = Button(second_frame, text="Copy Pass", command=partial(copyPass, array[i][3]))
            btn3.grid(column=4, row=i + 3, pady=10)
            btn1 = Button(second_frame, text="Update", command=partial(updateEntry, array[i][0]))
            btn1.grid(column=5, row=i + 3, pady=10)
            btn = Button(second_frame, text="Delete", command=partial(removeEntry, array[i][0]))
            btn.grid(column=6, row=i + 3, pady=10)

            i = i + 1

            cursor.execute("SELECT * FROM vault")
            if len(cursor.fetchall()) <= i:
                break


cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    loginScreen()
else:
    firstTimeScreen()
window.mainloop()
