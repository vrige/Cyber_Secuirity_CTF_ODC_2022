## Challange
Read the key when the user login.
## Solution
During registration there is a race condition, for few moments the user is inserted in the database with `isRestricted` set to `false`. If we register and login multiple times is possible to exploit it and see the key.
