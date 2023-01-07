## Challange
Read all the challanges.
## Solution
When a new user is registered is set to admin temporarily probably, since there is a function `$db->fix_user($id);` immediatly after which set the admin status on the database to 0.
In the page `http://meta.training.jinblack.it/index.php` we can see all the challanges if the user is admin otherwise we see only the user's ones.
By registering and login with different threads multiple times is possible to have a race condition for which the user visting the `index.php` can see all challanges because is admin.
