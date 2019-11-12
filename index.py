#Starting page of the application
from tkinter import *
#Libraries required to import
import codecs
import sqlite3
import datetime
import time

#Libraries to support AES
from simplecrypt import encrypt,decrypt
from base64 import b64encode,b64decode
from getpass import getpass

#----------------------------------------------Main ROT13Encryption FUNCTION-----------------------------------------#
def ROT13E_conn():
    conn=sqlite3.connect('database.db')
    c=conn.cursor()

    plain=E1.get()
    cipher=codecs.encode(plain, 'rot_13')
    E2.insert(0,str(cipher))
    
    def create_table():
        c.execute("CREATE TABLE IF NOT EXISTS rot13_encrypt(Date_and_Time text,Plain_text text, Cipher_text text)")

    def data_entry():
        unix=time.time()
        date=str(datetime.datetime.fromtimestamp(unix).strftime('%Y-%m-%d %H:%M:%S'))
        p=plain
        ciph=cipher
        c.execute("INSERT INTO rot13_encrypt(Date_and_Time,Plain_text,Cipher_text) VALUES(?,?,?)",
            (date,p,ciph))
        conn.commit()
        c.close()
        conn.close()

    create_table()
    data_entry()

#----------------------------------------------Main ROT13Decryption FUNCTION-----------------------------------------#
def ROT13D_conn():
    conn=sqlite3.connect('database.db')
    c=conn.cursor()

    cipher=E9.get()
    plain=codecs.encode(cipher, 'rot_13')
    E10.insert(0,str(plain))
    
    def create_table():
        c.execute("CREATE TABLE IF NOT EXISTS rot13_decrypt(Date_and_Time text,Cipher_text text, Plain_text text)")

    def data_entry():
        unix=time.time()
        date=str(datetime.datetime.fromtimestamp(unix).strftime('%Y-%m-%d %H:%M:%S'))
        ciph=cipher
        p=plain
        c.execute("INSERT INTO rot13_decrypt(Date_and_Time,Cipher_text,Plain_text) VALUES(?,?,?)",
            (date,ciph,p))
        conn.commit()
        c.close()
        conn.close()

    create_table()
    data_entry()

#------------------------------------------Main AES Function-----------------------------------------------#
def AESE_conn():
    conn=sqlite3.connect('database.db')
    c=conn.cursor()
    
    global password1
    password1=E5.get()
    plaintext=E6.get()
    ciphertext=encrypt(password1,plaintext)
    encoded_cipher=b64encode(ciphertext)
    E6_1.insert(0,encoded_cipher)

    def create_table():
        c.execute("CREATE TABLE IF NOT EXISTS AES_encrypt(Date_and_Time text,Plain_text text, Cipher_text text, Password text)")

    def data_entry():
        unix=time.time()
        date=str(datetime.datetime.fromtimestamp(unix).strftime('%Y-%m-%d %H:%M:%S'))
        p=plaintext
        ciph=encoded_cipher
        pswd=password1
        c.execute("INSERT INTO AES_encrypt(Date_and_Time,Plain_text,Cipher_text,Password) VALUES(?,?,?,?)",
            (date,p,ciph,pswd))
        conn.commit()
        c.close()
        conn.close()

    create_table()
    data_entry()

def AESD_conn():
    conn=sqlite3.connect('database.db')
    c=conn.cursor()
    global password2
    password2=E13.get()
    if password2==password1:
        encoded_cipher=E14.get()
        ciphertext=b64decode(encoded_cipher)
        plaintext=decrypt(password2,ciphertext)
        E14_1.insert(0,plaintext)
    else:
        print("The password is incorrect")
        
    

    def create_table():
        c.execute("CREATE TABLE IF NOT EXISTS AES_decrypt(Date_and_Time text, Cipher_text text,Plain_text text, Password text)")
    
    def data_entry():
        unix=time.time()
        date=str(datetime.datetime.fromtimestamp(unix).strftime('%Y-%m-%d %H:%M:%S'))
        ciph=encoded_cipher
        p=plaintext
        pswd=password2
        c.execute("INSERT INTO AES_decrypt(Date_and_Time,Cipher_text,Plain_text,Password) VALUES(?,?,?,?)",
            (date,ciph,p,pswd))
        conn.commit()
        c.close()
        conn.close()
    
    create_table()
    data_entry()


   
#-------------------------------------------Encryption-----------------------------------------------------#
#Function Encryption window displays
def encrypt_win():
    window=Tk()
    window.title("Encryption")
    window.geometry('2001x8000')
    window.configure(background="#2C3E50")
    label1=Label(window,text="Select the encryption method",font=("Arial",27),bg="#2C3E50",fg="white")
    label1.place(x=510,y=100)
    button1=Button(window,text="ROT13 ",font="Arial",padx=(100),pady=(15),command=rot13E_win,bg="#f89406",fg="lavender")
    button1.place(x=600,y=200)
    button3=Button(window,text=" AES     ",font="Arial",padx=(100),pady=(10),command=AESE_win,bg="#f89406",fg="lavender")
    button3.place(x=600,y=400)
    button5=Button(window,text="Exit",padx=("100"),pady=("10"),font="Arial",command=exit_win,bg="#d64541",fg="white")
    button5.place(x=1200,y=700)
    button6=Button(window,text="Back",padx=("100"),pady=("10"),font="Arial",command=back_win,bg="#00b5cc",fg="white")
    button6.place(x=900,y=700)

#Function Decryption window displays
def decrypt_win():
    window1=Tk()
    window1.title("Decryption")
    window1.geometry('2001x8000')
    window1.configure(background="#2C3E50")
    label1=Label(window1,text="Select the decryption method",font=("Arial",27),bg="#2C3E50",fg="white")
    label1.place(x=510,y=100)
    button1=Button(window1,text="ROT13 ",font="Arial",padx=(100),pady=(15),command=rot13D_win,bg="#f89406",fg="lavender")
    button1.place(x=600,y=200)
    button3=Button(window1,text="AES     ",font="Arial",padx=(100),pady=(10),command=AESD_win,bg="#f89406",fg="lavender")
    button3.place(x=600,y=400)
    button5=Button(window1,text="Exit",padx=("100"),pady=("10"),font="Arial",command=exit_win,bg="#d64541",fg="white")
    button5.place(x=1200,y=700)
    button6=Button(window1,text="Back",padx=("100"),pady=("10"),font="Arial",command=back_win,bg="#00b5cc",fg="white")
    button6.place(x=900,y=700)
    
#Function ROT13 Encryption Window displays
def rot13E_win():
    global E1,E2
    window2=Tk()
    window2.title("ROT13 Encryption")
    window2.geometry('2001x8000')
    window2.configure(background="#2C3E50")
    label1=Label(window2,text="ROT13 Encryption",font="Arial",bg="#2C3E50",fg="white")
    label1.place(x=700,y=100)
    label2=Label(window2,text="Plain Text",font="Arial",bg="#2C3E50",fg="white")
    label2.place(x=450,y=200)
    E1=Entry(window2,bd=5,width=40,font = ('arial', 16, 'bold'),bg="#6c7a89",fg="white")
    E1.place(x=600,y=200)
    button5=Button(window2,text="Encrypt",padx=("100"),pady=("10"),font="Arial",command=ROT13E_conn,bg="#f89406",fg="lavender")
    button5.place(x=650,y=280)
    label3=Label(window2,text="Cipher Text",font="Arial",bg="#2C3E50",fg="white")
    label3.place(x=450,y=400)
    E2=Entry(window2,bd=5,width=40,font = ('arial', 16, 'bold'),bg="#6c7a89",fg="white")
    E2.place(x=600,y=400)
    button6=Button(window2,text="Exit",padx=("100"),pady=("10"),font="Arial",command=exit_win,bg="#d64541",fg="white")
    button6.place(x=1200,y=700)
    button7=Button(window2,text="Back",padx=("100"),pady=("10"),font="Arial",command=back_e,bg="#00b5cc",fg="white")
    button7.place(x=900,y=700)

#Function to display MD5 Encryption window
def AESE_win():
    global E5,E6,E6_1
    window4=Tk()
    window4.title("AES Encryption")
    window4.geometry('2001x8000')
    window4.configure(background="#2C3E50")
    label7=Label(window4,text="AES Encryption",font="Arial",bg="#2C3E50",fg="white")
    label7.place(x=700,y=100)
    label8=Label(window4,text="Password",font="Arial",bg="#2C3E50",fg="white")
    label8.place(x=450,y=200)
    E5=Entry(window4,show="*",bd=5,width=40,font = ('arial', 16, 'bold'),bg="#6c7a89",fg="white")
    E5.place(x=600,y=200)
    label9=Label(window4,text="Plain Text",font="Arial",bg="#2C3E50",fg="white")
    label9.place(x=450,y=300)
    E6=Entry(window4,bd=5,width=40,font = ('arial', 16, 'bold'),bg="#6c7a89",fg="white")
    E6.place(x=600,y=300)
    button11=Button(window4,text="Encrypt",padx=("100"),pady=("10"),font="Arial",command=AESE_conn,bg="#f89406",fg="lavender")
    button11.place(x=700,y=380)
    label9_1=Label(window4,text="Cipher Text",font="Arial",bg="#2C3E50",fg="white")
    label9_1.place(x=450,y=500)
    E6_1=Entry(window4,bd=5,width=40,font = ('arial', 16, 'bold'),bg="#6c7a89",fg="white")
    E6_1.place(x=600,y=500)
    button12=Button(window4,text="Exit",padx=("100"),pady=("10"),font="Arial",command=exit_win,bg="#d64541",fg="white")
    button12.place(x=1200,y=700)
    button13=Button(window4,text="Back",padx=("100"),pady=("10"),font="Arial",command=back_e,bg="#00b5cc",fg="white")
    button13.place(x=900,y=700)
    
#------------------------------------------------Decryption-------------------------------------------------#
#Function ROT13 Decryption Window displays
def rot13D_win():
    global E9,E10
    window6=Tk()
    window6.title("ROT13 Decryption")
    window6.geometry('2001x8000')
    window6.configure(background="#2C3E50")
    label13=Label(window6,text="ROT13 Decryption",font="Arial",bg="#2C3E50",fg="white")
    label13.place(x=700,y=100)
    label14=Label(window6,text="Cipher Text",font="Arial",bg="#2C3E50",fg="white")
    label14.place(x=450,y=200)
    E9=Entry(window6,bd=5,width=40,font = ('arial', 16, 'bold'),bg="#6c7a89",fg="white")
    E9.place(x=600,y=200)
    button17=Button(window6,text="Decrypt",padx=("100"),pady=("10"),font="Arial",command=ROT13D_conn,bg="#f89406",fg="lavender")
    button17.place(x=650,y=280)
    label15=Label(window6,text="Plain Text",font="Arial",bg="#2C3E50",fg="white")
    label15.place(x=450,y=400)
    E10=Entry(window6,bd=5,width=40,font = ('arial', 16, 'bold'),bg="#6c7a89",fg="white")
    E10.place(x=600,y=400)
    button18=Button(window6,text="Exit",padx=("100"),pady=("10"),font="Arial",command=exit_win,bg="#d64541",fg="white")
    button18.place(x=1200,y=700)
    button19=Button(window6,text="Back",padx=("100"),pady=("10"),font="Arial",command=back_d,bg="#00b5cc",fg="white")
    button19.place(x=900,y=700)
   
#Function to display AES Decryption window
def AESD_win():
    global E13,E14,E14_1
    window8=Tk()
    window8.title("AES Decryption")
    window8.geometry('2001x8000')
    window8.configure(background="#2C3E50")
    label19=Label(window8,text="AES Decryption",font="Arial",bg="#2C3E50",fg="white")
    label19.place(x=700,y=100)
    label20=Label(window8,text="Password",font="Arial",bg="#2C3E50",fg="white")
    label20.place(x=450,y=200)
    E13=Entry(window8,show="*",bd=5,width=40,font = ('arial', 16, 'bold'),bg="#6c7a89",fg="white")
    E13.place(x=600,y=200)
    label21=Label(window8,text="Cipher Text",font="Arial",bg="#2C3E50",fg="white")
    label21.place(x=450,y=300)
    E14=Entry(window8,bd=5,width=40,font = ('arial', 16, 'bold'),bg="#6c7a89",fg="white")
    E14.place(x=600,y=300)
    button24=Button(window8,text="Decrypt",padx=("100"),pady=("10"),font="Arial",command=AESD_conn,bg="#f89406",fg="lavender")
    button24.place(x=700,y=380)
    label21_1=Label(window8,text="Plain Text",font="Arial",bg="#2C3E50",fg="white")
    label21_1.place(x=450,y=500)
    E14_1=Entry(window8,bd=5,width=40,font = ('arial', 16, 'bold'),bg="#6c7a89",fg="white")
    E14_1.place(x=600,y=500)
    button25=Button(window8,text="Exit",padx=("100"),pady=("10"),font="Arial",command=exit_win,bg="#d64541",fg="white")
    button25.place(x=1200,y=700)
    button25_1=Button(window8,text="Back",padx=("100"),pady=("10"),font="Arial",command=back_e,bg="#00b5cc",fg="white")
    button25_1.place(x=900,y=700)
    
#--------------------------------------Back Button---------------------------------------------------------#
#Function for back button to display main encryption/ decryption window
def back_win():
    root1=Tk()
    root1.title("Welcome")
    root1.geometry('2001x8000')
    root1.configure(background="#2C3E50")
    label2=Label(root1,text="Select one of these",font=("Arial",27),bg="#2C3E50",fg="white")
    label2.place(x=600,y=100)
    btn1=Button(root1,text="Encryption",padx=("100"),pady=("10"),font="Arial",command=encrypt_win,bg="#f89406",fg="lavender")
    btn1.place(x=600,y=200)
    btn2=Button(root1,text="Decryption",padx=("100"),pady=("10"),font="Arial",command=decrypt_win,bg="#f89406",fg="lavender")
    btn2.place(x=600,y=300)
    btn3=Button(root1,text="Exit",padx=("100"),pady=("10"),font="Arial",command=quit,bg="#d64541",fg="white")
    btn3.place(x=1200,y=700)

#function for back button in encryption window
def back_e():    
    window=Tk()
    window.title("Encryption")
    window.geometry('2001x8000')
    window.configure(background="#2C3E50")
    label1=Label(window,text="Select the encryption method",font=("Arial",27),bg="#2C3E50",fg="white")
    label1.place(x=510,y=100)
    button1=Button(window,text="ROT13 ",font="Arial",padx=(100),pady=(15),command=rot13E_win,bg="#f89406",fg="lavender")
    button1.place(x=600,y=200)
    button3=Button(window,text="AES     ",font="Arial",padx=(100),pady=(10),command=AESE_win,bg="#f89406",fg="lavender")
    button3.place(x=600,y=400)
    button5=Button(window,text="Exit",padx=("100"),pady=("10"),font="Arial",command=exit_win,bg="#d64541",fg="white")
    button5.place(x=1200,y=700)
    button6=Button(window,text="Back",padx=("100"),pady=("10"),font="Arial",command=back_win,bg="#00b5cc",fg="white")
    button6.place(x=900,y=700)

#Function for back button in decryption window
def back_d():
    window1=Tk()
    window1.title("Decryption")
    window1.geometry('2001x8000')
    window1.configure(background="#2C3E50")
    label1=Label(window1,text="Select the decryption method",font=("Arial",27),bg="#2C3E50",fg="white")
    label1.place(x=510,y=100)
    button1=Button(window1,text="ROT13 ",font="Arial",padx=(100),pady=(15),command=rot13D_win,bg="#f89406",fg="lavender")
    button1.place(x=600,y=200)
    button3=Button(window1,text="AES     ",font="Arial",padx=(100),pady=(10),command=AESD_win,bg="#f89406",fg="lavender")
    button3.place(x=600,y=400)
    button5=Button(window1,text="Exit",padx=("100"),pady=("10"),font="Arial",command=exit_win,bg="#d64541",fg="white")
    button5.place(x=1200,y=700)
    button6=Button(window1,text="Back",padx=("100"),pady=("10"),font="Arial",command=back_win,bg="#00b5cc",fg="white")
    button6.place(x=900,y=700)


#----------------------------------------Function for exit-------------------------------------------------#

def exit_win():
    root1=Tk()
    root1.title("Welcome")
    root1.geometry('2001x8000')
    root1.configure(background="#2C3E50")
    label2=Label(root1,text="Select one of these",font=("Arial",27),bg="#2C3E50",fg="white")
    label2.place(x=600,y=100)
    btn1=Button(root1,text="Encryption",padx=("100"),pady=("10"),font="Arial",command=encrypt_win,bg="#f89406",fg="lavender")
    btn1.place(x=600,y=200)
    btn2=Button(root1,text="Decryption",padx=("100"),pady=("10"),font="Arial",command=decrypt_win,bg="#f89406",fg="lavender")
    btn2.place(x=600,y=300)
    btn3=Button(root1,text="Exit",padx=("100"),pady=("10"),font="Arial",command=quit,bg="#d64541",fg="white")
    btn3.place(x=1200,y=700)
    root1.mainloop()

#----------------------------------------main_index_window-------------------------------------------------#
root1=Tk()
root1.title("Welcome")
root1.geometry('2001x8000') 
root1.configure(background="#2C3E50")
label2=Label(root1,text="Select one of these",font=("Arial",27),bg="#2C3E50",fg="lavender")
label2.place(x=600,y=100)
btn1=Button(root1,text="Encryption",padx=("100"),pady=("10"),font="Arial",command=encrypt_win,bg="#f89406",fg="lavender")
btn1.place(x=600,y=200)
btn2=Button(root1,text="Decryption",padx=("100"),pady=("10"),font="Arial",command=decrypt_win,bg="#f89406",fg="lavender")
btn2.place(x=600,y=300)
btn3=Button(root1,text="Exit",padx=("100"),pady=("10"),font="Arial",command=quit,bg="#d64541",fg="white")
btn3.place(x=1200,y=700)
root1.mainloop()
