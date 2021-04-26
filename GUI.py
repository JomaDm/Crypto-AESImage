from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from tkinter import filedialog
from AES import *


class GUI():

    HEIGHT = 300
    WIDTH = 600
    background_color = "#23262E"
    white = "#fff"
    select_color = "#7A5FEE"
    show_inputs = False
    last_option = 0
    window = None
    frame = None
    cipher = None
    selected = False
    option_action = 0
    option_mode = 0

    path_message = ""
    plaintext = ""

    choose_file = False

    dynamic_widgets = []

    def __init__(self):
        self.window = Tk()
        self.window.title("Practice 2.AES")
        self.window.geometry(str(self.HEIGHT)+'x'+str(self.WIDTH))
        self.window.resizable(0, 0)

        self.frame = Frame(self.window,
                           background=self.background_color
                           )
        self.frame.pack(fill="both",
                        expand=True
                        )

        self.label_opt = Label(self.frame,
                               text="Choose your action:",
                               fg=self.white,
                               bg=self.background_color,
                               font=("Arial", 14)
                               )
        self.label_opt.pack()

        option_action = IntVar()

        self.radioButton4 = Radiobutton(self.frame,
                                        text="Encrypt",
                                        variable=option_action,
                                        value=1,
                                        bg=self.background_color,
                                        selectcolor=self.select_color,
                                        fg=self.white,
                                        font=("Arial", 12)
                                        )
        self.radioButton4.pack()

        self.radioButton5 = Radiobutton(self.frame,
                                        text="Decrypt",
                                        variable=option_action,
                                        value=2,
                                        bg=self.background_color,
                                        selectcolor=self.select_color,
                                        fg=self.white,
                                        font=("Arial", 12)
                                        )
        self.radioButton5.pack()

        self.selectButtonCipher = Button(self.frame,
                                         text="select",
                                         bd=0,
                                         fg=self.white,
                                         bg=self.select_color,
                                         font=("Arial", 12),
                                         command=lambda: self.selectButton_Action(
                                             option_action.get())
                                         )
        self.selectButtonCipher.pack()

        self.generateModeFunction()

    def run(self):
        self.window.mainloop()

    def selectButton_Action(self, option):
        self.destroyDynamicWidgets()
        # print(option)
        # print("Option:", option, "Selected:", self.selected)
        self.option_action = option

    def destroyDynamicWidgets(self):
        self.path_message = ""
        self.plaintext = ""
        for i in self.dynamic_widgets:
            i.destroy()

    def generateModeFunction(self):
        label_Mode = Label(self.frame,
                           text="Choose your mode:",
                           fg=self.white,
                           bg=self.background_color,
                           font=("Arial", 14)
                           )
        label_Mode.pack()

        # self.dynamic_widgets.append(label_Mode)

        option_mode = IntVar()
        radioButton0 = Radiobutton(self.frame,
                                   text="ECB",
                                   variable=option_mode,
                                   value=1,
                                   bg=self.background_color,
                                   selectcolor=self.select_color,
                                   fg=self.white,
                                   font=("Arial", 12)
                                   )
        radioButton0.pack()
        # self.dynamic_widgets.append(radioButton0)

        radioButton1 = Radiobutton(self.frame,
                                   text="CBC",
                                   variable=option_mode,
                                   value=2,
                                   bg=self.background_color,
                                   selectcolor=self.select_color,
                                   fg=self.white,
                                   font=("Arial", 12)
                                   )
        radioButton1.pack()
        # self.dynamic_widgets.append(radioButton1)

        radioButton2 = Radiobutton(self.frame,
                                   text="CFB",
                                   variable=option_mode,
                                   value=3,
                                   bg=self.background_color,
                                   selectcolor=self.select_color,
                                   fg=self.white,
                                   font=("Arial", 12)
                                   )
        radioButton2.pack()

        # self.dynamic_widgets.append(radioButton2)

        radioButton3 = Radiobutton(self.frame,
                                   text="OFB",
                                   variable=option_mode,
                                   value=4,
                                   bg=self.background_color,
                                   selectcolor=self.select_color,
                                   fg=self.white,
                                   font=("Arial", 12)
                                   )
        radioButton3.pack()

        # self.dynamic_widgets.append(radioButton3)

        selectButtonMode = Button(self.frame,
                                  text="select",
                                  bd=0,
                                  fg=self.white,
                                  bg=self.select_color,
                                  font=("Arial", 12),
                                  command=lambda: self.selectButton_function(
                                      option_mode.get())
                                  )
        selectButtonMode.pack()
        # self.dynamic_widgets.append(selectButtonMode)

    def selectButton_function(self, option):
        self.option_mode = option
        self.destroyDynamicWidgets()
        self.addSpaceWidget()
        if(self.option_action == 1):
            self.generateEncryptWidgets()
        elif(self.option_action == 2):
            self.generateDecryptWidgets()

    def generateFunctionWidgets(self):
        self.destroyDynamicWidgets()
        label_space = Label(self.frame,
                            text="",
                            bg=self.background_color
                            )
        label_space.pack()
        # self.dynamic_widgets.append(label_space)

        option_action = IntVar()

        radioButtonEncrypt = Radiobutton(self.frame,
                                         text="Encrypt",
                                         variable=option_action,
                                         value=1,
                                         bg=self.background_color,
                                         selectcolor=self.select_color,
                                         fg=self.white,
                                         font=("Arial", 12)
                                         )
        radioButtonEncrypt.pack()
        # self.dynamic_widgets.append(radioButtonEncrypt)

        radioButtonDecrypt = Radiobutton(self.frame,
                                         text="Decrypt",
                                         variable=option_action,
                                         value=2,
                                         bg=self.background_color,
                                         selectcolor=self.select_color,
                                         fg=self.white,
                                         font=("Arial", 12)
                                         )
        radioButtonDecrypt.pack()
        # self.dynamic_widgets.append(radioButtonDecrypt)

        selectButtonFunction = Button(self.frame,
                                      text="select",
                                      bd=0,
                                      fg=self.white,
                                      bg=self.select_color,
                                      font=("Arial", 12),
                                      command=lambda: self.selectButton_function(
                                          option_action.get())
                                      )
        selectButtonFunction.pack()

        # self.dynamic_widgets.append(selectButtonFunction)

    def addSpaceWidget(self):
        label_space = Label(self.frame,
                            text="",
                            bg=self.background_color
                            )
        label_space.pack()
        self.dynamic_widgets.append(label_space)

    def generateEncryptWidgets(self):
        self.addSpaceWidget()
        if(self.option_mode != 1):
            label_key = Label(self.frame,
                              text="KEY : ",
                              fg=self.white,
                              bg=self.background_color,
                              font=("Arial", 14)
                              )
            label_key.pack()
            self.dynamic_widgets.append(label_key)
            input_key = Entry(self.frame)
            input_key.pack()
            self.dynamic_widgets.append(input_key)
            self.addSpaceWidget()

            label_iv = Label(self.frame,
                             text="Initial Vector : ",
                             fg=self.white,
                             bg=self.background_color,
                             font=("Arial", 14)
                             )
            label_iv.pack()
            self.dynamic_widgets.append(label_iv)
            input_iv = Entry(self.frame)
            input_iv.pack()
            self.dynamic_widgets.append(input_iv)

            self.addSpaceWidget()
            FileBtn = Button(self.frame,
                             text="Image File",
                             bd=0,
                             fg=self.white,
                             bg=self.select_color,
                             font=("Arial", 12),
                             command=lambda: self.pathFile()
                             )
            FileBtn.pack()
            self.dynamic_widgets.append(FileBtn)

            self.addSpaceWidget()
            EncryptBtn = Button(self.frame,
                                text="Encrypt",
                                bd=0,
                                fg=self.white,
                                bg=self.select_color,
                                font=("Arial", 12),
                                command=lambda: self.encrypt(input_key.get(), iv=input_iv.get())
                                )
            EncryptBtn.pack()
            self.dynamic_widgets.append(EncryptBtn)
        else:
            label_key = Label(self.frame,
                              text="KEY : ",
                              fg=self.white,
                              bg=self.background_color,
                              font=("Arial", 14)
                              )
            label_key.pack()
            self.dynamic_widgets.append(label_key)
            input_key = Entry(self.frame)
            input_key.pack()
            self.dynamic_widgets.append(input_key)

            self.addSpaceWidget()
            FileBtn = Button(self.frame,
                             text="Image File",
                             bd=0,
                             fg=self.white,
                             bg=self.select_color,
                             font=("Arial", 12),
                             command=lambda: self.pathFile()
                             )
            FileBtn.pack()
            self.dynamic_widgets.append(FileBtn)

            self.addSpaceWidget()
            EncryptBtn = Button(self.frame,
                                text="Encrypt",
                                bd=0,
                                fg=self.white,
                                bg=self.select_color,
                                font=("Arial", 12),
                                command=lambda: self.encrypt(input_key.get())
                                )
            EncryptBtn.pack()
            self.dynamic_widgets.append(EncryptBtn)
        self.addSpaceWidget()

    def generateDecryptWidgets(self):
        self.addSpaceWidget()
        if(self.option_mode != 1):
            label_key = Label(self.frame,
                              text="KEY : ",
                              fg=self.white,
                              bg=self.background_color,
                              font=("Arial", 14)
                              )
            label_key.pack()
            self.dynamic_widgets.append(label_key)
            input_key = Entry(self.frame)
            input_key.pack()
            self.dynamic_widgets.append(input_key)
            self.addSpaceWidget()

            label_iv = Label(self.frame,
                             text="Initial Vector : ",
                             fg=self.white,
                             bg=self.background_color,
                             font=("Arial", 14)
                             )
            label_iv.pack()
            self.dynamic_widgets.append(label_iv)
            input_iv = Entry(self.frame)
            input_iv.pack()
            self.dynamic_widgets.append(input_iv)

            self.addSpaceWidget()
            FileBtn = Button(self.frame,
                             text="Image File",
                             bd=0,
                             fg=self.white,
                             bg=self.select_color,
                             font=("Arial", 12),
                             command=lambda: self.pathFile()
                             )
            FileBtn.pack()
            self.dynamic_widgets.append(FileBtn)

            self.addSpaceWidget()
            EncryptBtn = Button(self.frame,
                                text="Decrypt",
                                bd=0,
                                fg=self.white,
                                bg=self.select_color,
                                font=("Arial", 12),
                                command=lambda: self.decrypt(input_key.get(), iv=input_iv.get())
                                )
            EncryptBtn.pack()
            self.dynamic_widgets.append(EncryptBtn)
        else:
            label_key = Label(self.frame,
                              text="KEY : ",
                              fg=self.white,
                              bg=self.background_color,
                              font=("Arial", 14)
                              )
            label_key.pack()
            self.dynamic_widgets.append(label_key)
            input_key = Entry(self.frame)
            input_key.pack()
            self.dynamic_widgets.append(input_key)

            self.addSpaceWidget()
            FileBtn = Button(self.frame,
                             text="Image File",
                             bd=0,
                             fg=self.white,
                             bg=self.select_color,
                             font=("Arial", 12),
                             command=lambda: self.pathFile()
                             )
            FileBtn.pack()
            self.dynamic_widgets.append(FileBtn)

            self.addSpaceWidget()
            EncryptBtn = Button(self.frame,
                                text="Decrypt",
                                bd=0,
                                fg=self.white,
                                bg=self.select_color,
                                font=("Arial", 12),
                                command=lambda: self.decrypt(input_key.get())
                                )
            EncryptBtn.pack()
            self.dynamic_widgets.append(EncryptBtn)
        self.addSpaceWidget()

    def pathFile(self):
        self.path_message = filedialog.askopenfilename()
        self.choose_file = True
        # print(self.path_message)
        # print("Archivo seleccionado")

    def encrypt(self, keys, iv=''):
        self.cipher = AESImageCipher()
        if(iv != ''):
            self.cipher.setImagePath(self.path_message)
            self.cipher.setKey(bytes(keys, 'utf-8'))
            self.cipher.setIv(bytes(iv, 'utf-8'))

            modo = None
            if(self.option_mode == 1):
                modo = 'ECB'
            elif(self.option_mode == 2):
                modo = 'CBC'
            elif(self.option_mode == 3):
                modo = 'CFB'
            elif(self.option_mode == 4):
                modo = 'OFB'
            self.cipher.setMode(modo)
            self.cipher.encrypt()
        elif(iv == ''):
            self.cipher.setImagePath(self.path_message)
            self.cipher.setKey(bytes(keys, 'utf-8'))

            modo = None
            if(self.option_mode == 1):
                modo = 'ECB'
            elif(self.option_mode == 2):
                modo = 'CBC'
            elif(self.option_mode == 3):
                modo = 'CFB'
            elif(self.option_mode == 4):
                modo = 'OFB'
            self.cipher.setMode(modo)
            self.cipher.encrypt()
        else:
            messagebox.showinfo(
                message="Error", title="Error"
            )

    def decrypt(self, key, iv=''):
        self.cipher = AESImageCipher()
        if(iv != ''):
            if(len(key) > 16):
                messagebox.showinfo(
                    message="Error with the key length", title="Error"
                )
            if(len(iv) > 16):

                messagebox.showinfo(
                    message="Error with the key length", title="Error"
                )
            if(len(iv) <= 16 and len(key) <= 16):
                self.cipher.setImagePath(self.path_message)
                self.cipher.setKey(bytes(key, 'utf-8'))
                self.cipher.setIv(bytes(iv, 'utf-8'))

                modo = None
                if(self.option_mode == 1):
                    modo = 'ECB'
                elif(self.option_mode == 2):
                    modo = 'CBC'
                elif(self.option_mode == 3):
                    modo = 'CFB'
                elif(self.option_mode == 4):
                    modo = 'OFB'
                self.cipher.setMode(modo)
                self.cipher.decrypt()
        elif(iv == ''):
            self.cipher.setImagePath(self.path_message)
            self.cipher.setKey(bytes(key, 'utf-8'))
            if(len(key) > 16):
                messagebox.showinfo(
                    message="Error with the key length", title="Error"
                )
            else:
                modo = None
                if(self.option_mode == 1):
                    modo = 'ECB'
                elif(self.option_mode == 2):
                    modo = 'CBC'
                elif(self.option_mode == 3):
                    modo = 'CFB'
                elif(self.option_mode == 4):
                    modo = 'OFB'
                self.cipher.setMode(modo)
                self.cipher.decrypt()
        else:
            messagebox.showinfo(
                message="Error", title="Error"
            )


if __name__ == "__main__":
    gui = GUI()
    gui.run()
