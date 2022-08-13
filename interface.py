
import diction
from analyse import *
import tkinter
from tkinter import *
from tkinter import filedialog
from tkinter import ttk
import os

def openfile():
    filepath = filedialog.askopenfilename(initialdir= os.getcwd(),
                                        title = "choisissez une trame",
                                        filetypes=(("text files", "*.txt"),
                                            ("all files", "*.*")))
    
    file = open(filepath, "r")
    for Widgets in fram1.winfo_children():
        Widgets.destroy()
    for Widgets in fram2.winfo_children():
        Widgets.destroy()
    print(filepath)
    filename = os.path.basename(filepath)
    print(filename)
    liste = clean_trames(filename)
    
    
    creat_button(liste)
    #obj.pack(clean_trames(filename))
    file.close()

def creat_button(liste):
    i=1
    for l in liste:
        t = str(i)+"trame"
        button = Button(fram1,
                        text=t,
                        command=lambda k=l,j=t
                        :click(k,j),
                        bg="green")
        button.pack()
        i+=1

def creat_small_button(t,name):
    button = Button(fram1,
                        text=t,
                        command=lambda k=name:click_small_button(name),
                        bg="yellow")
    button.pack()

def click_small_button(t):
    
    os.startfile(t)

def show_label(t):
    label=Label(fram2,
                text=t)
    label.pack()

def write_res(text,name):
    with open(name+'.txt','w') as f:
        f.write(text)

def click(liste,t):
    
    res = ""
    res_ethernet, debut=Ethernet(liste, 0)
    
    res+=res_ethernet
    res_ip, fin_ip= IP(liste, debut)
    
    res+=res_ip
    res_udp,s_p,d=Couche_UDP(liste, fin_ip)
    
    res+=res_udp
    if s_p == 53:
        res_dns = DNS(liste,d)
        res+=res_dns
    res_dhcp = DHCP(liste,d)
    
    res+=res_dhcp
    t = t+"_res"
    write_res(res,t)
    creat_small_button("open "+t,t+".txt")

def splitTrame(ficher):
    with open(ficher, "r") as f:
        bigTrame = f.read()
        splited = bigTrame.split('0000')
        splited.remove("")
        for x in range(0,len(splited)):
            splited[x] = "0000" + splited[x]
        return splited

def checkOffset(a_trame, n):
    
    
            
    line1 = ""
    line2 = ""
    offset1 = 0
    offset2 = 0
    nbLine = 1
    trame_to_clean = []
    read_trame = a_trame.split("\n")  
      
    while '' in read_trame:
        read_trame.remove('')
    while ' ' in read_trame:
        read_trame.remove(' ')
    

    nb_of_lines = len(read_trame)
            
    for x in range(0,nb_of_lines-1):
        line1 = read_trame[x]
        line2 = read_trame[x + 1]

                        
        offset1 = line1.split()[0]
        if len(offset1) != 4:
            show_label("Problem found in trame" + str(n) + " line "+ str(nbLine)+ ", the offset is incorret")
            return ""
        offset2 = line2.split()[0]
        if len(offset2) != 4:
            show_label("Problem found in trame" + str(n) + " line "+ str(nbLine+1)+ ", the offset is incorret")
            
            return ""
        if isHex(offset1)==False :
            show_label("Problem found in trame" + str(n) + " line "+ str(nbLine)+ ", "+ "the offset is in wrong format")
            

            return ""
        if isHex(offset2)==False:
            show_label("Problem found in trame" + str(n) + " line "+ str(nbLine+1)+ ", "+ "the offset is in wrong format")
            

            return ""
        diff = int(offset2,16) - int(offset1,16)
        
                
        if diff <= 0:
            show_label("Problem found in trame" + str(n) + "line "+ str(nbLine)+ ", "+ "the offset is incorret")
            
            return ""
        
                
               
        trame_to_clean.append(line1)

        line1 = line2
        nbLine = nbLine + 1 

                
    last_line = read_trame[nb_of_lines-1]
    trame_to_clean.append(last_line)
    

    

    nb_of_lines = len(trame_to_clean)
    nbLine = 1
    for x in range(0,nb_of_lines-1):
            line1 = trame_to_clean[x]
            line2 = trame_to_clean[x + 1]
                
            offset1 = line1.split()[0]
            offset2 = line2.split()[0]
            diff = int(offset2,16) - int(offset1,16)
            
            word_list_line1 = line1.split()
            for t in range (1,len(word_list_line1)):
                if isHex(str(t)) == False:
                    show_label("this trame is in wrong format")
                    return ""
            number_of_words_in_line1 = len(word_list_line1)
                
            if (diff > 0):
                if number_of_words_in_line1 < diff + 1:
                    show_label("Problem found in trame" + str(n) + " line "+ str(nbLine)+ ", "+ str(diff - number_of_words_in_line1 + 1)+ "byte are missing")
                    
                    return  ""
                elif number_of_words_in_line1 > diff + 1:
                    show_label("Problem found in trame" + str(n) + " line "+ str(nbLine)+ ", "+ str(number_of_words_in_line1 + 1 - diff)+ " byte more")
                    
                    return ""
                else:
                    words=line1.split()
                    words = words[0:diff+1]
                    line1 = " ".join(words)
                    trame_to_clean[x] = line1
                        

            line1 = line2
            nbLine = nbLine + 1        
    


    
    return trame_to_clean

def cut_into_bytes(trame):
    for x in range(0, len(trame)):
        trame[x].split(' ', 1)
        trame[x] = trame[x].split(' ', 1)[1]
    
    trame = " ".join(trame)
    
    trame = trame.split(" ")
    while '' in trame:
        trame.remove('')
    while ' ' in trame:
        trame.remove(' ')
    
    return trame

def rebuild_trame(trames):
    while '' in trames:
        trames.remove('')
    while ' ' in trames:
        trames.remove(' ')
    
    return trames

def clean_trames(ficher):
    splited = splitTrame(ficher)
    
    for x in range (0,len(splited)):
        
        splited[x] = checkOffset(splited[x], x+1)
        
        if splited[x] != "":
            splited[x] = cut_into_bytes(splited[x])
    
    splited = rebuild_trame(splited)
    
    return splited


def isHex(s):
    hexNumber = set("0123456789abcdefABCDEF")
    for char in s:
        if not (char in hexNumber):
            return False
    return True 


window = Tk()
window.geometry("700x600")
window.title("Analyseur des trames")



menubar = Menu(window)
window.config(menu=menubar)
file_menu = Menu(menubar, tearoff=0)
menubar.add_cascade(label="file", menu = file_menu)
file_menu.add_command(label="Open", command=openfile)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=quit)

panedwindow=ttk.Panedwindow(window, orient=HORIZONTAL)  
panedwindow.pack(fill=BOTH, expand=True)  
   
fram1=ttk.Frame(panedwindow,width=100,height=300, relief=SUNKEN)  
fram2=ttk.Frame(panedwindow,width=390,height=390,relief=SUNKEN) 
    
panedwindow.add(fram1, weight=1)  
panedwindow.add(fram2, weight=1) 
    

window.mainloop()

