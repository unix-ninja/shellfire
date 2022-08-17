<?php
if (isset($_REQUEST['url'])) {
  $location = $_REQUEST['path']; // Get the URL from the user.
  $curl = curl_init();
  curl_setopt($curl, CURLOPT_URL, $location); // Not validating the input. Trusting the location variable
  curl_exec($curl); 
  curl_close($curl);
} else {
  $location = "https://httpbin.org/anything";
  $curl = curl_init();
  curl_setopt($curl, CURLOPT_URL, $location);
  curl_exec($curl); 
  curl_close($curl);
}
