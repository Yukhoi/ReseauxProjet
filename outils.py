def if_IPv4(s):
    if s=="0800":
        return True
    return False

def affichage(ind, s1, s2, s3):
    aff="\t"*ind
    aff+=s1+s2+s3+"\n"
    return aff

def to_bin(i,octet):
    b=str(bin(int(i)))
    binaire=b[2:]
    res=""
    l=len(binaire)%(8*octet)
    if l!=0:
        res+=((8*octet)-l)*'0'
        return res+binaire
    return binaire

def to_hex(i,octet):
    h=str(hex(int(i)))
    h=h[2:]
    l=len(h)%(2*octet)
    if l!=0:
        return (2*octet-l)*"0"+h
    return h

def index(liste, debut, fin, s):
    res=""
    if debut>=len(liste) or fin>len(liste):
        res=affichage(0, "[MalFormed: IndexError ", s, "]" )
        print(res)
        exit()

def time(i):
    d=str(i/86400)
    h=str((i%86400)/3600)
    m=str(((i%86400)%3600)/60)
    s=str(i%86400%3600%60)
    return(d+" days "+h+" hours "+m+" minutes "+s+" seconds")
