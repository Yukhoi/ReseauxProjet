import diction, outils

def Ethernet(liste, position):
    res=""
    #Affichage de Ethernet
    res+=("Ethernet:\n")

    #Adresse destination
    #Position des octets de l'adresse destination
    debut=position
    fin=debut+6
    #Verification de index
    outils.index(liste, debut, fin, "Ethernet")
    #Lecture de l'adresse destination
    dest=""
    for i in range(debut, fin-1):
        dest+=liste[i]+":"
    dest+=liste[fin-1]
    res+=outils.affichage(1,"Destination: ", dest, "")

    #Adresse source
    #Position des octets de l'adresse source
    debut=fin
    fin=debut+6
    #Verification de index
    outils.index(liste, debut, fin, "Ethernet")
    #Lecture de l'adresse source
    source=""
    for i in range(debut, fin-1):
        source+=liste[i]+":"
    source+=liste[fin-1]
    res+=outils.affichage(1,"Source: ", source, "")

    #Type
    #Position des octets du type
    debut=fin
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "Ethernet")
    #Lecture du type
    typet="".join(liste[debut:fin])
    #Verifier si le type est IPv4
    if outils.if_IPv4(typet):
        res+=outils.affichage(1, "Type: 0x", typet, "(IPv4)")
    else:
        res+=outils.affichage(1, "Type Unknown:", " 0x"+typet, "")

    return (res, fin)

def IP(liste, position):
    res=""
    #Affichage de IP
    res+=("IP:\n")

    #Version et IHL
    #Position des octets de version et IHL
    debut=position
    fin=debut+1
    #Verification de index
    outils.index(liste, debut, fin, "IP")
    #Lecture de version et IHL
    octet="".join(liste[debut:fin])
    #Version
    #Lecture du version
    if octet[0]=="4":
        version="IPv4"
        res+=outils.affichage(1,"Version: 0x",octet[0],"("+version+")")
    else:
        res+=outils.affichage(1, "Version Unknown: ", "0x"+octet[0], "")
    #Header Length(IHL)
    #Lecture de IHL et transformation en decimal
    IHL_d=int(octet[1],16)*4
    res+=outils.affichage(1,"Header length: 0x",octet[1],"("+str(IHL_d)+" bytes)")

    #Type of Service
    #Position des octets de type of service
    debut=fin
    fin=debut+1
    #Verification de index
    outils.index(liste, debut, fin, "IP")
    #Lecture de Type of Service
    tos="".join(liste[debut:fin])
    res+=outils.affichage(1,"Type of service: 0x",tos,"")

    #Total Length
    #Position des octets de total length
    debut=fin
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "IP")
    #Lecture de Total length et transformation en decimal
    TL="".join(liste[debut:fin])
    TL_d=int(TL,16)
    res+=outils.affichage(1,"Total length: 0x",TL,"("+str(TL_d)+")")

    #Identifier
    #Position des octets de identifier
    debut=fin
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "IP")
    #Lecture de l'identifier et transformation en decimal
    Id="".join(liste[debut:fin])
    Id_d=int(Id,16)
    res+=outils.affichage(1,"Identifier: 0x", Id, "("+str(Id_d)+")")

    #Flags et Offset
    #Position des octets de fragmentation
    debut=fin
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "IP")
    #Flags
    res+=outils.affichage(1, "Flags: ", "", "")
    #Lecture de flags et transformation en binaire
    flags="".join(liste[debut:fin])
    flags=outils.to_bin(int(flags,16), 2)
    #Lecture de R
    if flags[0]!="0":
        print("IP: Error\n"+"\tFlags Error")
        exit()
    res+=outils.affichage(2, "R: ", str(int(flags[0],2)), "")
    #Lecture de DF
    res+=outils.affichage(2, "DF: ", str(int(flags[1],2)), "")
    #Lecture de MF
    res+=outils.affichage(2, "MF: ", str(int(flags[2],2)), "")

    #Offset
    #Lecture de Offset et transformation en hex
    offset=int(flags[3:],2)
    offset_h="".join(hex(offset))
    res+=outils.affichage(2, "Offset: ",offset_h, "("+str(offset)+")")

    #TTL
    #Position des octets de time to live
    debut=fin
    fin=debut+1
    #Verification de index
    outils.index(liste, debut, fin, "IP")
    #Lecture de TTL et transformation en decimal
    TTL="".join(liste[debut:fin])
    TTL_d=int(TTL,16)
    res+=outils.affichage(1,"Time To Live: 0x", TTL, "("+str(TTL_d)+")")

    #Protocol
    #Position des octets de protocol
    debut=fin
    fin=debut+1
    #Verification de index
    outils.index(liste, debut, fin, "IP")
    #Lecture de Protocol, transformation en decimal
    proto="".join(liste[debut:fin])
    proto_d=int(proto, 16)
    #Si protol Inconnu
    if str(proto_d) not in diction.dict_protocol:
        res+=outils.affichage(1, "Protocol Unknown: ", str(proto_d), "(0x"+proto+")")
    #Recherche dans la dictionnaire
    else:
        t_proto=diction.dict_protocol[str(proto_d)]
        res+=outils.affichage(1, "Protocol: ", t_proto, "("+str(proto_d)+")")

    #Checksum
    #Position des octets de checksum
    debut=fin
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "IP")
    #Lecture de Checksum
    check="".join(liste[debut:fin])
    res+=outils.affichage(1, "Checksum: 0x", check, "")

    #Adresse source
    #Position des octets de l'adresse source
    debut=fin
    fin=debut+4
    #Verification de index
    outils.index(liste, debut, fin, "IP")
    #Lecture de Adresse source
    Ad_Source="".join(liste[debut:fin])
    res+=outils.affichage(1, "Address Source: 0x", Ad_Source, "")

    #Adresse destination
    #Position des octets de l'adresse destination
    debut=fin
    fin=debut+4
    #Verification de index
    outils.index(liste, debut, fin, "IP")
    #Lecture de Adresse destination
    Ad_Dest="".join(liste[debut:fin])
    res+=outils.affichage(1, "Adresse Destination: 0x", Ad_Dest, "")

    #Option
    #Verifier si options existe dans cette trame
    if IHL_d!=20:
        #Type
        #Position des octets de type
        debut=fin
        fin=debut+1
        #Verification de index
        outils.index(liste, debut, fin, "IP")
        #Lecture de type, transformation en decimal
        option="".join(liste[debut:fin])
        option_d=int(option, 16)
        #Si option inconnu
        if str(option_d) not in diction.dict_option_IP:
            t_option="Unknown"
        #Recherche dans la dictionnaire
        else: t_option=diction.dict_option_IP[str(option_d)]

        #Length
        #Position des octets de length
        debut=fin
        fin=debut+1
        #Verification de index
        outils.index(liste, debut, fin, "IP")
        #Lecture de length, transformation en decimal
        length="".join(liste[debut:fin])
        length_d=int(length, 16)

        #Pointer
        #Position des octets de pointer
        debut=fin
        fin=debut+1
        #Verification de index
        outils.index(liste, debut, fin, "IP")
        #Lecture de pointer, transformation en decimal
        pointer="".join(liste[debut:fin])
        pointer_d=int(pointer, 16)

        #Affichage Options
        res+=outils.affichage(1, "Options: (", str(length_d)+" bytes), ", t_option)
        res+=outils.affichage(2, "IP Option: ", t_option, "("+str(option_d)+")")
        res+=outils.affichage(3, "Type: ", str(option_d), "")
        #Transformation en binaire
        type=outils.to_bin(option_d, 1)
        #Copy
        res+=outils.affichage(4, type[0], "... .... = Copy on fragmentation: ", diction.dict_YN[type[0]])
        #Class
        key=int("".join(type[1:3]), 2)
        if key not in diction.dict_CN:
            res+=outils.affichage(4, "."+type[1:3], ". .... = Class: Unknown", "("+str(key)+")")
        else:
            res+=outils.affichage(4, "."+type[1:3], ". .... = Class: "+diction.dict_CN[key], "("+str(key)+")")
        #Number
        key=int("".join(type[3:]), 2)
        res+=outils.affichage(4, "..."+type[3]+" "+type[4:], " = Number: "+t_option, "("+str(key)+")")
        res+=outils.affichage(3, "Length: ", str(length_d), "(0x"+length+")")
        res+=outils.affichage(3, "Pointer: ", str(pointer_d), "(0x"+pointer+")")

        #Padding
        #Verifie si padding existe
        if (length_d+20)<IHL_d:
            #Calcul de longueur de padding
            l_padding=IHL_d-20-length_d
            #Position des octets de padding
            debut=fin+length_d-3
            fin=debut+l_padding
            #Verification de index
            outils.index(liste, debut, fin, "IP")
            #Lecture de padding
            padding="".join(liste[debut:fin])
            res+=outils.affichage(2, "Padding: ", "0x",padding)

    #Position du premier octet de la prochaine partie
    fin=14+IHL_d #14 est le nombre d'octets fixe de la couche 2 Ethernet

    return (res, fin)

def Couche_UDP(liste, position):
    res=""

    res+="UDP:\n"
    debut_udp = position

    #Source Port
    source_port = "".join(liste[debut_udp: debut_udp+2])
    res += outils.affichage(1,"Source Port: 0x", source_port, "("+str(int(source_port, 16))+")")

    #Destination Port
    des_port = "".join(liste[debut_udp+2: debut_udp+4] )
    res += outils.affichage(1,"Destination Port: 0x", des_port, "("+str(int(des_port, 16))+")")

    #Length
    length = "".join(liste[debut_udp+4: debut_udp+6])
    res += outils.affichage(1,"Length: 0x", length, "("+str(int(length,16))+")")

    #Checksum
    checksum = "".join(liste[debut_udp+6: debut_udp+8])
    res += outils.affichage(1,"Checksum: 0x", checksum, "")

    return (res, int(source_port, 16), debut_udp+8)


def name(liste, debut, fin, name_tab):
    #Declaration des variables
    label=0
    n=""
    position=debut
    #Verification de index
    outils.index(liste, debut, 0, "DNS")
    #Si l'octet tout au debut est 00
    if int(liste[debut],16)==0:
        n="<Root>"
        return ((position, n), label, debut, fin)
    #Tant que l'octet n'est pas 00
    while str(liste[debut])!="00":
        #Si l'octet commence par c0
        if (str(liste[debut])=="c0"):
            first=name_tab[0][0]
            #Verification de index
            outils.index(liste, debut+1, 0, "DNS")
            #Chercher l'octet concernant
            jump_to=(int(liste[debut+1], 16)-12)+first
            #Transformation en dictionnaire pour faciliter la recherche
            dict_name_tab=dict(name_tab)
            #Si existe pas, lancer la fonction name
            if jump_to not in dict_name_tab:
                n+=name(liste, jump_to, jump_to+1, name_tab)[0][1]
            #Si existe, utilise directement
            else:
                n+=dict_name_tab[jump_to]
            #Changement de position
            debut=fin
            fin=debut+1
            label+=1

            return ((position, n), label, debut, fin)

        taille=0
        #Le premier octet signifie la taille de ce mot
        while taille<int(liste[debut],16):
            #Verification de index
            outils.index(liste, debut, fin+1, "DNS")
            #Transformation le l'octet en decimal puis en caractere et l'ajout dans n
            n+=chr(int(liste[fin],16))
            #Incrementation
            fin+=1
            taille+=1
        #Sort de la boucle car taille > int(liste[debut],16)
        #Changement de position
        debut=fin
        fin=debut+1
        #L'ajout de . apres chaque mot
        n+="."
        taille=0
        label+=1

    return ((position, n), label, debut, fin)

def queries(liste, debut, fin, name_tab, nb):
    #Declaration de la variable res
    res=""
    #Name
    #Appel a la fonction name
    (position, name_q), label, d, f=name(liste, debut, fin, name_tab)
    #Rajoute le tuple (position, name) dans le tableau
    name_tab.append((position, name_q))

    #Type
    #Position des octets de type
    debut=f
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "DNS")
    #Lecture des octets de type et transformation en decimal
    type_qr="".join(liste[debut:fin])
    type_qr_d=int(type_qr, 16)
    #Verifier si c'est un type connu
    if (str(type_qr_d)) not in diction.dict_type_queries:
        type_q="Unknown"
    else:
        type_q=diction.dict_type_queries[str(type_qr_d)]

    #Class
    #Position des octets de class
    debut=fin
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "DNS")
    #Lecture des octets de class et transformation en decimal
    class_qr="".join(liste[debut:fin])
    class_qr_d=int(class_qr, 16)
    #Verifier si c'est un class connu
    if (str(class_qr_d)) not in diction.dict_type_class:
        class_q="Unknown"
    else:
        class_q=diction.dict_type_class[str(class_qr_d)]

    #Affichage de tete de queries
    res+=outils.affichage(2, name_q+": ", "type "+type_q, ", class "+class_q)

    #Affichage de Name:
    res+=outils.affichage(3, "name: ", name_q, "")

    #Affichage de Length
    res+=outils.affichage(3, "[Name length: ", str(len(name_q)-1), "]")

    #Affichage de Label Count
    res+=outils.affichage(3, "[Label Length: ", str(label), "]")

    #Affichage de Type
    res+=outils.affichage(3, "Type: ", type_q, "("+str(type_qr_d)+")")

    #Affichage de Classe
    res+=outils.affichage(3, "class: ", class_q, "(0x"+class_qr+")")

    return (res, debut, fin)

def Answer(liste, debut, fin, name_tab, nb, ans):
    #Declaration de la variable res
    res=""

    #Name
    #Verification de index
    outils.index(liste, debut, fin, "DNS")
    #Appel a la fonction name
    (position, name_a), label, d, f=name(liste, debut, fin, name_tab)
    #Rajoute le tuple (position, name) dans le tableau
    name_tab.append((position, name_a))

    #Type
    #Position des octets de type
    debut=f
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "DNS")
    #Lecture de type et transformation en decimal
    type_an="".join(liste[debut:fin])
    type_an_d=int(type_an, 16)
    #Verifier si c'est un type inconnu
    if (str(type_an_d)) not in diction.dict_type_queries:
        type_a="Unknown"
    else:
        type_a=diction.dict_type_queries[str(type_an_d)]

    #Class
    #Position des octets de class
    debut=fin
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "DNS")
    #Lecture de class et transformation en decimal
    class_an="".join(liste[debut:fin])
    class_an_d=int(class_an, 16)
    #Verifier si c'est un class inconnu
    if str(class_an_d) not in diction.dict_type_class:
        class_a="Unknown"
    else:
        class_a=diction.dict_type_class[str(class_an_d)]

    #TTL
    #Position des octets de ttl
    debut=fin
    fin=debut+4
    #Verification de index
    outils.index(liste, debut, fin, "DNS")
    #Lecture de TTL et transformation en decimal
    ttl="".join(liste[debut:fin])
    ttl_d=int(ttl,16)
    ttl_t=outils.time(ttl_d)

    #DL
    #Position des octets de dl
    debut=fin
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "DNS")
    #Lecture de DL et transformation en decimal
    dl="".join(liste[debut:fin])
    dl_d=int(dl,16)

    #Premier octet de la partie suivante
    pos=fin+dl_d

    #Affichage de tete de answer de type cname
    res+=outils.affichage(2, name_a+": ", "type "+type_a, ", class "+class_a)

    #Affichage de Name:
    res+=outils.affichage(3, "name: ", name_a, "")

    #Affichage de Type
    res+=outils.affichage(3, "Type: ", type_a, "("+str(type_an_d)+")")

    #Affichage de Classe
    res+=outils.affichage(3, "class: ", class_a, "(0x"+class_an+")")

    #Affichage de TTL
    res+=outils.affichage(3, "Time to live: ", str(ttl_d), "("+ttl_t+")")

    #Affichage de DL
    res+=outils.affichage(3, "Data length: 0x", dl, "("+str(dl_d)+")")

    #RData: les frmats differents car types differents
    #SSNAME
    if type_a in diction.dict_type_queries_name:
        #Position des octets de name
        debut=fin
        fin=debut+1
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Appel a la fonction name
        (position, ssname), label, d, f=name(liste, debut, fin, name_tab)
        #Rajoute le tuple (position, name) dans le tableau
        name_tab.append((position, ssname))
        #Affichage de name
        res+=outils.affichage(3, diction.dict_type_queries_name[type_a], ": ", ssname)
    #SOA
    elif type_a == "SOA":
        #MNAME
        #Position des octets de mname
        debut=fin
        fin=debut+1
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Appel a la fonction name
        (position, mname), label, d, f=name(liste, debut, fin, name_tab)
        #Rajoute le tuple (position, name) dans le tableau
        name_tab.append((position, mname))
        #Affichage de mname
        res+=outils.affichage(3, "Primary name server: ", mname, "")

        #RNAME
        #Position des octets de rname
        debut=f
        fin=debut+1
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Appel a la fonction name
        (position, rname), label, d, f=name(liste, debut, fin, name_tab)
        #Rajoute le tuple (position, name) dans le tableau
        name_tab.append((position, rname))
        #Affichage de rname
        res+=outils.affichage(3, "Responsible authority's mailbox: ", rname, "")

        #Serial
        #Position des octets de serial
        debut=f
        fin=debut+4
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Lecture de serial et transformation en decimal
        serial="".join(liste[debut:fin])
        serial_d=int(serial, 16)
        #Affichage de serial number
        res+=outils.affichage(3, "Serial Number: ", str(serial_d), "(0x"+serial+")")

        #Refresh
        #Position des octets de refresh
        debut=fin
        fin=debut+4
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Lecture de refresh et transformation en decimal et en unite du temps
        refresh="".join(liste[debut:fin])
        refresh_d=int(refresh, 16)
        refresh_t=outils.time(refresh_d)
        #Affichage de refresh interval
        res+=outils.affichage(3, "Refresh Interval: ", str(refresh_d), "("+refresh_t+")")

        #Retry
        #Position des octets de retry
        debut=fin
        fin=debut+4
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Lecture de retry et transformation en decimal
        retry="".join(liste[debut:fin])
        retry_d=int(retry, 16)
        retry_t=outils.time(retry_d)
        #Affichage de retry interval
        res+=outils.affichage(3, "Retry Interval: ", str(retry_d), "("+retry_t+")")

        #Expire
        #Position des octets de expire
        debut=fin
        fin=debut+4
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Lecture de expire et transformation en decimal
        expire="".join(liste[debut:fin])
        expire_d=int(expire, 16)
        expire_t=outils.time(expire_d)
        #Affichage de expire limit
        res+=outils.affichage(3, "Expire Limit: ", str(expire_d), "("+expire_t+")")

        #Minimim TTL
        #Position des octets de min ttl
        debut=fin
        fin=debut+4
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Lecture de min ttl et transformation en decimal
        mini="".join(liste[debut:fin])
        mini_d=int(mini, 16)
        mini_t=outils.time(mini_d)
        #Affichage de minimum ttl
        res+=outils.affichage(3, "Minimum TTL: ", str(mini_d), "("+mini_t+")")
    #NULL
    elif type_a == "NULL":
        #Position des octets de data
        debut=fin
        fin=debut+dl_d
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Lecture de Adresse
        nll="".join(liste[debut:fin])
        #Affichage du data
        res+=outils.affichage(3, "Null(Data): ", nll, "")
    #HINFO
    elif type_a == "HINFO":
        #CPU Length
        #Position des octets de cpu length
        debut=fin
        fin=debut+1
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Lecture de cpu length
        cpu_l="".join(liste[debut:fin])
        cpu_l_d=int(cpu_l, 16)
        #Affichage de cpu length
        res+=outils.affichage(3, "CPU Length: ", str(cpu_l_d), "(0x"+cpu_l+")")

        #CPU
        #Position des octets de cpu
        debut=fin
        fin=debut+cpu_l_d
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Lecture de cpu
        i=0
        cpu=""
        while debut<fin:
            cpu+=chr(int(liste[debut],16))
            debut+=1
        ##Affichage de cpu
        res+=outils.affichage(3, "CPU: ", cpu, "")

        #OS Length
        #Position des octets de os length
        debut=fin
        fin=debut+1
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Lecture de os length
        os_l="".join(liste[debut:fin])
        os_l_d=int(os_l, 16)
        ##Affichage de os length
        res+=outils.affichage(3, "OS Length: ", str(os_l_d), "(0x"+os_l+")")

        #OS
        #Position des octets de os
        debut=fin
        fin=debut+os_l_d
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Lecture de os
        i=0
        os=""
        while debut<fin:
            os+=chr(int(liste[debut],16))
            debut+=1
        ##Affichage de os
        res+=outils.affichage(3, "OS: ", os, "")
    #MINFO
    elif type_a=="MINFO":
        #RMAILBX
        #Position des octets de rmailbx
        debut=fin
        fin=debut+1
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Appel a la fonction name
        (position, rmailbx), label, d, f=name(liste, debut, fin, name_tab)
        #Rajoute le tuple (position, name) dans le tableau
        name_tab.append((position, rmailbx))
        ##Affichage de rmailbx
        res+=outils.affichage(3, "Responsible MailBox: ", rmailbx, "")

        #EMAILBX
        #Position des octets de emailbx
        debut=f
        fin=debut+1
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Appel a la fonction name
        (position, emailbx), label, d, f=name(liste, debut, fin, name_tab)
        #Rajoute le tuple (position, name) dans le tableau
        name_tab.append((position, emailbx))
        ##Affichage de emailbx
        res+=outils.affichage(3, "Error MailBox: ", emailbx, "")
    #A
    elif type_a=="A":
        #Address
        #Position des octets de Adresse
        debut=fin
        fin=debut+4
        #Verification de index
        outils.index(liste, debut, fin, "DNS")
        #Lecture de Adresse
        addr="".join(liste[debut:fin])
        #Affichage de l'adresse
        res+=outils.affichage(3, "Address: ", addr, "")

    #Changement de position de fin
    fin=pos

    return (res, debut, fin)

def DNS(liste, position):
    #Declaration de la variable res
    res=""

    #Affichage de DNS
    res+="DNS: \n"

    #ID
    #Position des octets de ID
    debut=34+8
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "DNS")
    #Lecture de ID
    ID="".join(liste[debut:fin])
    res+=outils.affichage(1,"Transaction ID: 0x", ID, "")

    #Flags
    #Position des octets de Flags
    debut=fin
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "DNS")
    #Lecture de Flags
    flags="".join(liste[debut:fin])
    res+=outils.affichage(1, "Flags: 0x", flags, "")
    #Transformation en binaire
    binaire=outils.to_bin(int(flags,16), 2)

    #Response
    #Lecture de Response
    response=diction.dict_QR[binaire[0]]
    res+=outils.affichage(2, binaire[0], "... .... .... .... = ", "Response: Message is a "+response)

    #Opcode
    #Lecture de Opcode et transformation en decimal
    Opcode_s=binaire[1:5]
    key=int(Opcode_s,2)
    #Different cas
    if 3<=key<=15:
        Opcode=diction.dict_Opcode['3-15']
        res+=outils.affichage(2, "."+binaire[1:4]+" "+binaire[4]+"... .... .... = ", "Opcode: ", Opcode+"("+str(key)+")")
    else:
        Opcode=diction.dict_Opcode[str(key)]
        res+=outils.affichage(2, "."+binaire[1:4]+" "+binaire[4]+"... .... .... = ", "Opcode: ", Opcode+"("+str(key)+")")

    #AA
    #Lecture de AA
    AA=diction.dict_AA[binaire[5]]
    res+=outils.affichage(2, ".... .",binaire[5]+".. .... .... = ", "Authoritative Answer: "+AA)

    #TC
    #Lecture de TC
    TC=diction.dict_TC[binaire[6]]
    res+=outils.affichage(2, ".... ..",binaire[6]+". .... .... = ", "Truncated: "+TC)

    #RD
    #Lecture de RD
    RD=diction.dict_RD[binaire[7]]
    res+=outils.affichage(2, ".... ...",binaire[7]+" .... .... = ", "Recursion desired: "+RD)

    #RA
    #Lecture de RA
    RA=diction.dict_RA[binaire[8]]
    res+=outils.affichage(2, ".... .... ",binaire[8]+"... .... = ", "Recursion Available: "+RA)

    #Z
    #Verifier si z est 0
    if (binaire[9])!='0':
        print("DNS: Error\n"+"\tFlags Error: Z Error(0b"+binaire[0]+")")
        exit()
    #Lecture et affichage de Z
    res+=outils.affichage(2, ".... .... .",binaire[9:12]+" .... = ", "Z: Reserved(0)")

    #RCode
    #Lecture de RCode et transformation en decimal
    key=int(binaire[12:16], 2)
    #Traitement des differents cas
    if 6<=key<=15:
        Rcode=diction.dict_RCode['6-15']
    else:
        Rcode=diction.dict_RCode[str(key)]
    res+=outils.affichage(2, ".... .... .... ", binaire[12:16], " = Reply Code: "+Rcode+"("+str(key)+")")

    #Question
    #Position des octets de Question
    debut=fin
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "DNS")
    #Lecture de Question
    question="".join(liste[debut:fin])
    res+=outils.affichage(1, "Question: ", str(int(question,16)), "")

    #Answer RRs
    #Position des octets de Answer RRs
    debut=fin
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "DNS")
    #Lecture de Answer RRs
    ans="".join(liste[debut:fin])
    res+=outils.affichage(1, "Answer RRs: ", str(int(ans,16)), "")

    #Authority RRs
    #Position des octets de Authority RRs
    debut=fin
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "DNS")
    #Lecture de Authority RRs
    auth="".join(liste[debut:fin])
    res+=outils.affichage(1, "Authority RRs: ", str(int(auth,16)), "")

    #Additional RRs
    #Position des octets de Additional RRs
    debut=fin
    fin=debut+2
    #Verification de index
    outils.index(liste, debut, fin, "DNS")
    #Lecture de Additional RRs
    addi="".join(liste[debut:fin])
    res+=outils.affichage(1, "Additional RRs: ", str(int(addi,16)), "")

    #Queries
    #Position des octets de Queries
    debut=fin
    fin=debut+1
    #Creation d'un tableau de tuple (position, name)
    name_tab=[]
    #Tant que le nombre de Queries n'est pas 0
    if int(question,16)>0:
        #Compteur le nombre de Queries
        nb=0
        res+=outils.affichage(1, "Queries: ", "", "")
        #Tant que nb est inferieur au nombre de queries
        while nb<int(question,16):
            #Verification de index
            outils.index(liste, debut, fin, "DNS")
            #Appel a la fonction queries
            u, v, w=queries(liste, debut, fin, name_tab, nb)
            #Changement de position
            debut=w
            fin=debut+1
            #Incrementation de nb
            nb+=1
            res+=u

    #Answers
    #Tant que le nombre de Answer n'est pas 0
    if int(ans,16)>0:
        #Compteur le nombre de Answers
        nb=0
        res+=outils.affichage(1, "Answers: ", "", "")
        #Tant que nb est inferieur au nombre de answer
        while nb<int(ans,16):
            #Verification de index
            outils.index(liste, debut, fin, "DNS")
            #Appel a la fonction answer
            u, v, w=Answer(liste, debut, fin, name_tab, nb, ans)
            #Changement de position
            debut=w
            fin=debut+1
            #Incrementation de nb
            nb=nb+1
            res+=u

    #Authority
    #Tant que le nombre de Authority n'est pas 0
    if int(auth,16)>0:
        #Compteur le nombre de Authority
        nb=0
        res+=outils.affichage(1, "Authoritative nameserver: ", "", "")
        #Tant que nb est inferieur au nombre de authority
        while nb<int(auth,16):
            #Verification de index
            outils.index(liste, debut, fin, "DNS")
            #Appel a la fonction authority
            #u, v, w=Authority(liste, debut, fin, name_tab, nb, ans)
            u, v, w=Answer(liste, debut, fin, name_tab, nb, auth)
            #Changement de position
            debut=w
            fin=debut+1
            #Incrementation de nb
            nb=nb+1
            res+=u

    #Additional
    #Tant que le nombre de addi n'est pas 0
    if int(addi,16)>0:
        #Compteur le nombre de Addi
        nb=0
        res+=outils.affichage(1, "Additinal records: ", "", "")
        while nb<int(addi,16):
            #Verification de index
            outils.index(liste, debut, fin, "DNS")
            #Appel a la fonction queries
            #u, v, w=Additional(liste, debut, fin, name_tab, nb, addi)
            u, v, w=Answer(liste, debut, fin, name_tab, nb, addi)
            #Changement de position
            debut=w
            fin=debut+1
            #Incrementation de nb
            nb+=1
            res+=u

    return res

def DHCP(liste, position):
    res = ""

    debut_dhcp = position
    debut_udp = position-8
    options = { 53: 'DHCP Message Type',
               116: 'DHCP Auto-Configuration',
               61: 'Client Identifier',
               50: 'Requested IP Address',
               12: 'Hostname',
               60: 'Vendor Class Identifier',
               55: 'Parameter Request List',
               255: 'End',
               1: 'Subnet Mask Value',
               3: 'Router',
               6: 'Domain Name Server',
               15: 'Domain Name',
               51: 'Adress Lease Time',
               54: 'DHCP Server Identification',
               }

    type_of_dhcp = {1: 'Discover',
                    2: 'Offer',
                    3: 'Request',
                    4: 'Decline',
                    5: 'ACK',
                    6: 'NAK',
                    7: 'Release',
                    8: 'Inform',
                    }

    parameter_request = {   1: 'Subnet Mask',
                            3: 'Router',
                            6: 'Domain Name Server',
                            15: 'Domain Name',
                            31: 'Perform Router Discover',
                            33: 'Static Route',
                            43: 'Vendor-Specific Infomation',
                            44: 'NetBIOS over TCP/IP Name Server',
                            46: 'NetBIOS over TCP/IP Node Type',
                            47: 'NetBIOS over TCP/IP Scope',
                            249: 'Private/Classless Static Route'
                        }

    if (liste[debut_udp+1] == '44' or liste[debut_udp+1] == '43') and (liste[debut_udp+3] == '43' or liste[debut_udp+3] == '44'):

        res+=("DHCP:\n ")

        #OP
        op = liste[debut_dhcp]
        if op == "01":
            res += outils.affichage(1, "Message type: Boot Request (1)", "", "")
        elif op == "02":
            res += outils.affichage(1, "Message type: Boot Reply (2)", "", "")
        else:
            res += outils.affichage(1, "Message type: Unknown (", str(int(op,16)), ")")

        #htype
        htype = liste[debut_dhcp+1]
        if htype == "01":
            res += outils.affichage(1, "Hardware type : Ethernet (0x01)", "", "")
        else:
            res += outils.affichage(1, "Hardware type : Unknown (0x", htype, ")")

        #hlen
        hlen = int(liste[debut_dhcp+2],16)
        if htype == "01":
            res += outils.affichage(1, "Hardware adress length: 6", "", "")
        else:
            res += outils.affichage(1, "Hardware adress length : Unknown", "", "")

        #hops
        hops = liste[debut_dhcp+3]
        res += outils.affichage(1, "Hops: ", str(int(hops,16)) , "")

        #Xid
        xid_list = liste[debut_dhcp+4: debut_dhcp+7]
        xid = ''.join(i for i in xid_list)
        res += outils.affichage(1, "Transaction ID: 0x ", xid , "")

        #sec
        sec_list = liste[debut_dhcp+8: debut_dhcp+9]
        sec = ''.join(i for i in sec_list)
        res += outils.affichage(1, "Seconds elapsed: ", str(int(sec,16)) , "")

        #flag
        sec = liste[debut_dhcp+10: debut_dhcp+11]
        if sec == 0000:
            res += outils.affichage(1, "Bootp flags: 0x0000 (unicast) ", "" , "")
        if sec == 8000:
            res += outils.affichage(1, "Bootp flags: 0x8000 (Broadcast) ", "" , "")

        #ciaddr
        ci1 =str(int(liste[debut_dhcp+12],16))
        ci2 =str(int(liste[debut_dhcp+13],16))
        ci3 =str(int(liste[debut_dhcp+14],16))
        ci4 =str(int(liste[debut_dhcp+15],16))
        res += outils.affichage(1, "Client IP adress :", ci1 + "." + ci2 + "." + ci3 + "." + ci4 , "")

        #yiaddr
        yi1 =str(int(liste[debut_dhcp+16],16))
        yi2 =str(int(liste[debut_dhcp+17],16))
        yi3 =str(int(liste[debut_dhcp+18],16))
        yi4 =str(int(liste[debut_dhcp+19],16))
        res += outils.affichage(1, "Your IP adress :", yi1 + "." + yi2 + "." + yi3 + "." + yi4 , "")

        #siaddr
        si1 =str(int(liste[debut_dhcp+20],16))
        si2 =str(int(liste[debut_dhcp+21],16))
        si3 =str(int(liste[debut_dhcp+22],16))
        si4 =str(int(liste[debut_dhcp+23],16))
        res += outils.affichage(1, "Next server IP adress :", si1 + "." + si2 + "." + si3 + "." + si4 , "")

        #giaddr
        gi1 =str(int(liste[debut_dhcp+24],16))
        gi2 =str(int(liste[debut_dhcp+25],16))
        gi3 =str(int(liste[debut_dhcp+26],16))
        gi4 =str(int(liste[debut_dhcp+27],16))
        res += outils.affichage(1, "Relay agent IP adress :", gi1 + "." + gi2 + "." + gi3 + "." + gi4 , "")

        #chaddr
        mac = ""
        for x in range(0,hlen):

            ch =liste[debut_dhcp+28+x]
            mac += ch
            if x != hlen-1:
                mac += ":"
        res += outils.affichage(1, "Client MAC adress :", mac ,"")
        res += outils.affichage(1, "Client hardward adress padding: " + (16-hlen)* "00" ,"" , "")


        #sname
        sname_list = liste[debut_dhcp+44: debut_dhcp+107]
        sname = ''.join(i for i in sname_list)
        if int(sname,16) == 0:
            res += outils.affichage(1, "Server host name not given ", "", "")

        #file
        file_list = liste[debut_dhcp+108: debut_dhcp+235]
        file = ''.join(i for i in file_list)
        if int(file,16) == 0:
            res += outils.affichage(1, "Boot file name not given ", "", "")



        #magic cokkie
        res += outils.affichage(1, "Magic Cokkie: DHCP", "", "")

        #option
        debut_option = debut_dhcp+240
        total_length_option = 0
        while int(liste[debut_option],16) != 255 :
            key = int(liste[debut_option],16)

            if key == 53:
                print("(" , type_of_dhcp[int(liste[debut_option+2], 16)], ")")
                res += outils.affichage(1, "Option: (" + str(key) +')' , options[key], '(' + type_of_dhcp[int(liste[debut_option+2], 16)] + ')')
                res += outils.affichage(2, "Length: ", str(int(liste[debut_option+1],16)),"")
                res += outils.affichage(2, "DHCP: ", type_of_dhcp[int(liste[debut_option+2], 16)], "(" + str(int(liste[debut_option+2], 16)) +")")



            elif key == 116:
                res += outils.affichage(1, "Option: (" + str(key) +')' , options[key], "")
                res += outils.affichage(2, "Length: ", str(int(liste[debut_option+1])),"")
                if int(liste[debut_option+2], 16) == 1:
                    res += outils.affichage(2, "DHCP ", type_of_dhcp[int(liste[debut_option+2], 16)], "(" + str(int(liste[debut_option+2], 16)) +")")
                else:
                    res += outils.affichage(2, "DHCP: ", type_of_dhcp[int(liste[debut_option+2], 16)], "(unknown)")


            elif key == 61:
                res += outils.affichage(1, "Option: (" + str(key) +')' , options[key], "")
                res += outils.affichage(2, "Length: ", str(int(liste[debut_option+1],16)),"")
                if int(liste[debut_option+2], 16) == 1:
                    res += outils.affichage(2, "Hardware type: Ethernet (0x01) ", "" ,"" )
                else:
                    res += outils.affichage(2, "Hardware type: Unknown ", "" ,"" )


            elif key == 50:
                ip_requested = ""
                for x in range(0,int(liste[debut_option+1],16)):
                    ip_requested += str(int(liste[debut_option+2+x],16))
                    if x != int(liste[debut_option+1])-1:
                        ip_requested += "."

                res += outils.affichage(1, "Option: (" + str(key) +')' , options[key], "(" + ip_requested + ")")
                res += outils.affichage(2, "Length: ", str(int(liste[debut_option+1],16)),"")
                res += outils.affichage(2, "Requested IP Adress: ",ip_requested ,"")


            elif key == 12:
                res += outils.affichage(1, "Option: (" + str(key) +')' , options[key], "")
                res += outils.affichage(2, "Length: ", str(int(liste[debut_option+1],16)),"")
                ascii_list = liste[debut_option+2:debut_option+2+int(liste[debut_option+1],16)]
                for x in range(0, len(ascii_list)):
                    ascii_list[x] = int(ascii_list[x],16)
                name = ''.join(chr(i) for i in ascii_list)
                res += outils.affichage(2, "Host Name: ",name ,"")


            elif key == 60:
                res += outils.affichage(1, "Option: (" + str(key) +')' , options[key], "")
                res += outils.affichage(2, "Length: ", str(int(liste[debut_option+1],16)),"")
                ascii_list = liste[debut_option+2:debut_option+2+int(liste[debut_option+1],16)]
                for x in range(0, len(ascii_list)):
                    ascii_list[x] = int(ascii_list[x],16)
                name = ''.join(chr(i) for i in ascii_list)
                res += outils.affichage(2, "Vendor Class Identifier: ",name ,"")




            elif key == 55:
                res += outils.affichage(1, "Option: (" + str(key) +')' , options[key], "")
                res += outils.affichage(2, "Length: ", str(int(liste[debut_option+1],16)),"")
                for x in range(0, int(liste[debut_option+1],16)):
                    parameter_num = int(liste[debut_option+2+x],16)
                    para = parameter_request[parameter_num]
                    res += outils.affichage(2, "Parameter Request List Item: (", str(parameter_num) + ")", para)

            elif key == 1:

                ip_mask = ""
                for x in range(0,int(liste[debut_option+1],16)):

                    ip_mask += str(int(liste[debut_option+2+x],16))
                    if x != int(liste[debut_option+1])-1:
                        ip_mask += "."
                res += outils.affichage(1, "Option: (" + str(key) +')' , options[key], "(" + ip_mask + ")")
                res += outils.affichage(2, "Length: ", str(int(liste[debut_option+1],16)),"")
                res += outils.affichage(2, "Subnet Mask: ",ip_mask ,"")

            elif key == 3:
                rou = ""
                for x in range(0,int(liste[debut_option+1],16)):
                    rou += str(int(liste[debut_option+2+x],16))
                    if x != int(liste[debut_option+1])-1:
                        rou += "."
                res += outils.affichage(1, "Option: (" + str(key) +')' , options[key], "")
                res += outils.affichage(2, "Length: ", str(int(liste[debut_option+1],16)),"")
                res += outils.affichage(2, "Subnet Mask: ",rou ,"")

            elif key == 6:
                res += outils.affichage(1, "Option: (" + str(key) +')' , options[key], "")
                res += outils.affichage(2, "Length: ", str(int(liste[debut_option+1],16)),"")
                dom_ser = ""
                quanti_ser = int(liste[debut_option+1],16)//4
                for y in range(0,quanti_ser):
                    for x in range(0,4):
                        dom_ser += str(int(liste[debut_option+2+x+y*4],16))
                        if x != 3:
                            dom_ser += "."
                    res += outils.affichage(2, "Domaine Name Server: ",dom_ser ,"")
                    dom_ser = ""

            elif key == 15:
                res += outils.affichage(1, "Option: (" + str(key) +')' , options[key], "")
                res += outils.affichage(2, "Length: ", str(int(liste[debut_option+1],16)),"")
                ascii_list = liste[debut_option+2:debut_option+2+int(liste[debut_option+1],16)]
                for x in range(0, len(ascii_list)):
                    ascii_list[x] = int(ascii_list[x],16)
                name = ''.join(chr(i) for i in ascii_list)
                res += outils.affichage(2, "Domaine Name: ",name ,"")

            elif key == 51:
                res += outils.affichage(1, "Option: (" + str(key) +')' , options[key], "")
                res += outils.affichage(2, "Length: ", str(int(liste[debut_option+1],16)),"")
                time_list = liste[debut_option+2:(debut_option+2+int(liste[debut_option+1],16))]
                time = ''.join(i for i in time_list)

                time = int(time,16)
                res += outils.affichage(2, "IP Adress Lease Time: ( " + str(time) + "s)", str(time//86400),"day")

            elif key == 54:
                server = ""
                for x in range(0,int(liste[debut_option+1],16)):
                    server += str(int(liste[debut_option+2+x],16))
                    if x != int(liste[debut_option+1])-1:
                        server += "."
                res += outils.affichage(1, "Option: (" + str(key) +')' , options[key], "(" + server + ")")
                res += outils.affichage(2, "Length: ", str(int(liste[debut_option+1],16)),"")
                res += outils.affichage(2, "DHCP Server Identification: ",server ,"")





            else:
                res += outils.affichage(1, "Option: (" + str(key) +')' , "Unknown", "")
                res += outils.affichage(2, "Length: ", str(int(liste[debut_option+1],16)),"")



            debut_option += int(liste[debut_option+1],16) + 2
            total_length_option += int(liste[debut_option+1],16) + 2

        res += outils.affichage(1, "Option: (255) END", "", "")
        res += outils.affichage(2, "Options End: 255", "", "")

        #pading
        total_length = int(liste[16] + liste[17] ,16)


        res += outils.affichage(1, "Pading: ", '00'*(total_length+14 - (debut_dhcp + 240 + total_length_option)),"")


    return res
